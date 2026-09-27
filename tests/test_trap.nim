## Tests the trap: which bad path maps to which target, and that hits are saved
## and can be reported on

import std/[unittest, asyncdispatch, os]
from std/asyncnet import newAsyncSocket, connect, send, recv, recvLine, close
from std/net import Port
from std/strutils import split, contains, startsWith, repeat
from std/options import some, none, isNone, get
from db_connector/db_sqlite import DbConn, getValue, getAllRows, sql

from trap import TrapConfig, Tactic, classify, trap, findAgent
from database import TrapHit, getDbConnection, createTables, insertTrapHit, finishTrapHit,
    getTopTrappedIPs, getTopTraps, getTopTrappedURIs, getTrappedCredentials, getTrapTotals


suite "classify":
  test "the paths from the offender list land in the right target":
    check $classify("/.env") == "env"
    check $classify("/api/.env") == "env"
    check $classify("/.env.production") == "env"
    check $classify("/.git/config") == "git"
    check $classify("/wp-login.php") == "wordpress"
    check $classify("//wp-includes/wlwmanifest.xml") == "wordpress"
    check $classify("/.aws/credentials") == "creds"
    check $classify("/.ssh/id_rsa") == "creds"
    check $classify("/backup.sql") == "backup"
    check $classify("/db.sql.gz") == "backup"
    check $classify("/config.json") == "config"
    check $classify("/phpinfo.php") == "php"
    check $classify("/actuator/env") == "api"
    check $classify("/api/v1/users") == "api"
    check $classify("/.well-known/gecko-litespeed.php") == "php"

  test "admin and login pages beat the plain php trap, so we can harvest logins":
    check $classify("/administrator/index.php") == "admin"
    check $classify("/phpmyadmin/") == "admin"
    check $classify("/login") == "admin"

  test "path traversal and shells are their own target":
    check $classify("/../../etc/passwd") == "rce"
    check $classify("/cgi-bin/test.cgi") == "rce"
    check $classify("/getcmd") == "rce"
    check $classify("/deploy.sh") == "rce"
    check $classify("/..%5c..%5cwindows/win.ini") == "rce"
    check $classify("/..\\..\\windows/win.ini") == "rce"
    check $classify("/..;/manager/html") == "rce"
    check $classify("/static/..") == "rce"

  test "the paths that used to fall through are trapped now":
    check $classify("/error.log") == "backup"
    check $classify("/storage/logs/laravel.log") == "backup"
    check $classify("/aws.json") == "creds"
    check $classify("/rclone.conf") == "creds"
    check $classify("/service_account.json") == "creds"
    check $classify("/console") == "admin"
    check $classify("/reset-password") == "admin"
    check $classify("/health") == "api"
    check $classify("/server-info") == "api"
    check $classify("/.DS_Store") == "config"

  test "innocent paths are not trapped":
    check $classify("/") == "none"
    check $classify("/posts/hello") == "none"
    check $classify("/index.xml") == "none"


proc newDb(): DbConn =
  result = getDbConnection(":memory:")
  createTables(result)


suite "trap hits":
  test "a hit is saved at once and filled in when the trap ends":
    let db = newDb()
    let id = db.insertTrapHit(TrapHit(
      date: "2026-09-22 10:00:00", remoteIP: "45.9.1.10", httpMethod: "GET",
      requestURI: "/.env", userAgent: "curl/8", trap: "env", tactic: "drip"))
    check id > 0

    # before it ends, the row exists with nothing sent yet
    check getTrapTotals(db).hits == 1
    check getTrapTotals(db).bytes == 0

    db.finishTrapHit(id, 840, 120, "AKIAEXAMPLE")
    let totals = getTrapTotals(db)
    check totals.hits == 1
    check totals.bytes == 840
    check totals.seconds == 120

  test "the reports group and count the hits":
    let db = newDb()
    for i in 1 .. 3:
      let id = db.insertTrapHit(TrapHit(
        date: "2026-09-22 10:00:00", remoteIP: "45.9.1.10", httpMethod: "GET",
        requestURI: "/.env", userAgent: "x", trap: "env", tactic: "drip"))
      db.finishTrapHit(id, 100, 10, "")
    let id = db.insertTrapHit(TrapHit(
      date: "2026-09-22 10:00:00", remoteIP: "203.0.113.5", httpMethod: "GET",
      requestURI: "/.git/config", userAgent: "x", trap: "git", tactic: "drip"))
    db.finishTrapHit(id, 50, 5, "")

    let ips = getTopTrappedIPs(db, 10)
    check ips.len == 2
    check ips[0][0] == "45.9.1.10" # the busiest first
    check ips[0][^1] == "3"        # last column is the hit count

    let uris = getTopTrappedURIs(db, 10)
    check uris[0][0] == "/.env"
    check uris[0][^1] == "3"

    let traps = getTopTraps(db, 10)
    check traps[0][0] == "env"

  test "credentials typed into the fake login are reported":
    let db = newDb()
    let id = db.insertTrapHit(TrapHit(
      date: "2026-09-22 10:00:00", remoteIP: "66.66.66.66", httpMethod: "POST",
      requestURI: "/wp-login.php", userAgent: "x", trap: "wordpress", tactic: "login"))
    db.finishTrapHit(id, 1300, 25, "tried admin:hunter2")

    let creds = getTrappedCredentials(db, 10)
    check creds.len == 1
    check creds[0][0] == "66.66.66.66"
    check creds[0][1] == "tried admin:hunter2"

    # a drip hit has no credentials, so it is left out
    let id2 = db.insertTrapHit(TrapHit(
      date: "2026-09-22 10:00:00", remoteIP: "1.1.1.1", httpMethod: "GET",
      requestURI: "/.env", userAgent: "x", trap: "env", tactic: "drip"))
    db.finishTrapHit(id2, 10, 1, "")
    check getTrappedCredentials(db, 10).len == 1


# live traps in this process, talked to over a real socket
let tempDir = getTempDir() / "nginwho_test_trap"
removeDir(tempDir)
createDir(tempDir)


proc startTrap(port, dripMs: int): string =
  ## Runs a trap and returns the path of its database
  result = tempDir / ("trap_" & $port & ".db")
  asyncCheck trap(TrapConfig(enabled: true, port: port, maxConnections: 10,
      maxSeconds: 60, dripMinMs: dripMs, dripMaxMs: dripMs, bombs: true, bombAfter: 100), result)


const
  slowPort = 18090 # a full fake .env takes over 15 seconds here
  fastPort = 18091
  bombPort = 18092
let
  slowDb = startTrap(slowPort, 20)
  fastDb = startTrap(fastPort, 0)


proc ask(httpMethod, path, ip: string, port: int, userAgent: string): string =
  ## Asks a trap for a path as `ip` and returns the whole response once the trap is done
  proc run(): Future[string] {.async.} =
    let socket = newAsyncSocket()
    defer: socket.close()
    await socket.connect("127.0.0.1", Port(port))
    await socket.send(httpMethod & " " & path & " HTTP/1.1\r\nHost: x\r\nX-Real-IP: " & ip &
        "\r\nUser-Agent: " & userAgent & "\r\n\r\n")
    while true:
      let data = await socket.recv(4096)
      if data == "":
        break
      result.add(data)
  return waitFor(run())


proc get(path, ip: string, port = fastPort, userAgent = "curl"): string =
  ## The body a trap sends for a path
  return ask("GET", path, ip, port, userAgent).split("\r\n\r\n", maxsplit = 1)[1]


proc head(path, ip: string): string =
  ## The response head a trap sends for a path
  return ask("HEAD", path, ip, fastPort, "curl")


proc lastCanary(): string =
  ## The trap closes the connection after saving the hit, so it is there by now
  getDbConnection(fastDb).getValue(sql"SELECT detail FROM trap_hits ORDER BY id DESC LIMIT 1")


suite "live trap":
  test "a bot that hangs up ends its trap":
    proc hangUpEarly() {.async.} =
      let socket = newAsyncSocket()
      await socket.connect("127.0.0.1", Port(slowPort))
      await socket.send("GET /.env HTTP/1.1\r\nHost: x\r\nX-Real-IP: 45.9.1.10\r\n\r\n")
      discard await socket.recvLine() # the status line, then leave
      socket.close()

    waitFor hangUpEarly()
    waitFor sleepAsync(1000) # a moment for the trap to notice

    let totals = getTrapTotals(getDbConnection(slowDb))
    check totals.hits == 1
    check totals.bytes > 0 # the row is only filled in once the trap has ended
    check totals.bytes < 50

  test "the canary saved is the secret the bot got":
    for path in ["/.env", "/.aws/credentials", "/config.json", "/.ssh/id_rsa"]:
      let body = get(path, "45.9.1.10")
      check lastCanary() != ""
      check lastCanary() in body

    check get("/.git/config", "45.9.1.10").contains(lastCanary())
    check lastCanary().startsWith("ghp_")

  test "no trap can be cached by a CDN":
    # a drip, a maze, a login, an endless body, a bomb download and a miss
    for path in ["/.env", "/.git/objects", "/wp-login.php", "/xmlrpc.php",
        "/backup.tar.gz", "/posts/hello"]:
      check "Cache-Control: no-store" in head(path, "45.9.1.11")

  test "a file without a secret saves no canary":
    discard get("/.git/HEAD", "45.9.1.10")
    check lastCanary() == ""
    discard get("/etc/passwd", "45.9.1.10")
    check lastCanary() == ""

  test "the same bot sees the same key, another bot a different one":
    let key = get("/.ssh/id_rsa", "45.9.1.10")
    check get("/.ssh/id_rsa", "45.9.1.10") == key
    check get("/.ssh/id_rsa", "203.0.113.5") != key

  test "the bomb comes after bomb_after hits, not on it":
    # bomb_after is 2 here, so the first two hits are played with and the third is bombed
    let bombDb = tempDir / ("trap_" & $bombPort & ".db")
    asyncCheck trap(TrapConfig(enabled: true, port: bombPort, maxConnections: 10,
        maxSeconds: 60, dripMinMs: 0, dripMaxMs: 0, bombs: true, bombAfter: 2), bombDb)
    waitFor sleepAsync(200)

    for _ in 1 .. 3:
      discard get("/.env", "70.70.70.70", bombPort)
    let tactics = getDbConnection(bombDb).getAllRows(
        sql"SELECT tactic FROM trap_hits ORDER BY id")
    check tactics.len == 3
    check tactics[0][0] == "drip"
    check tactics[1][0] == "drip"
    check tactics[2][0] == "bomb"

  test "listed user agents are trapped whatever they ask for":
    const agentPort = 18094
    let agentDb = tempDir / ("trap_" & $agentPort & ".db")
    asyncCheck trap(TrapConfig(enabled: true, port: agentPort, maxConnections: 10,
        maxSeconds: 60, dripMinMs: 0, dripMaxMs: 0, bombs: true, bombAfter: 100,
        agents: @[("deepseek", some(maze)), ("gptbot", none(Tactic))]), agentDb)
    waitFor sleepAsync(200)

    # a set tactic wins, even over the one the path would get
    discard get("/posts/hello", "80.0.0.1", agentPort, "Mozilla/5.0 (compatible; DeepSeekBot)")
    discard get("/.env", "80.0.0.1", agentPort, "DeepSeekBot")
    # no tactic set: the default, what any bot gets for the path and a drip for a page
    discard get("/posts/hello", "80.0.0.2", agentPort, "GPTBot/1.2")
    discard get("/wp-login.php", "80.0.0.2", agentPort, "GPTBot/1.2")
    # anyone else asking for a normal page is not trapped
    check get("/posts/hello", "80.0.0.3", agentPort, "Mozilla/5.0") == "404 Not Found\n"

    let hits = getDbConnection(agentDb).getAllRows(
        sql"SELECT request_uri, trap, tactic FROM trap_hits ORDER BY id")
    check hits.len == 4
    check hits[0] == @["/posts/hello", "agent", "maze"]
    check hits[1] == @["/.env", "env", "maze"]
    check hits[2] == @["/posts/hello", "agent", "drip"]
    check hits[3] == @["/wp-login.php", "wordpress", "login"]

    # the maze shows the path, a script in it must not run on our site
    let maze = get("/%3Cscript%3Ex%3C/script%3E/", "80.0.0.4", agentPort, "DeepSeekBot")
    check "<script>" notin maze
    check "&lt;script&gt;" in maze

  test "user agents are matched anywhere in the header, case ignored":
    let cfg = TrapConfig(agents: @[("deepseek", some(drip)), ("bot", some(bomb))])
    check findAgent("Mozilla/5.0 (DEEPSEEKBOT)", cfg).get.name == "deepseek"
    check findAgent("SomeBot", cfg).get.tactic == some(bomb)
    check findAgent("Mozilla/5.0", cfg).isNone

  test "long values are cut and a flood from one IP stops being saved":
    discard get("/wp-login.php", "90.0.0.1", userAgent = "x".repeat(5000))
    let db = getDbConnection(fastDb)
    check db.getValue(sql"SELECT length(user_agent) FROM trap_hits WHERE remote_ip = '90.0.0.1'") == "1024"
    for _ in 2 .. 1001:
      discard get("/wp-login.php", "90.0.0.1")
    check db.getValue(sql"SELECT COUNT(*) FROM trap_hits WHERE remote_ip = '90.0.0.1'") == "1000"
