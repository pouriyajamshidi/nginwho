## Runs the static server in this process and talks to it over a real socket

import std/[unittest, asyncdispatch, os]
from std/asyncnet import AsyncSocket, newAsyncSocket, connect, send, recv, close
from std/net import Port
from std/strutils import split, splitLines, startsWith, endsWith, strip, contains, count

from db_connector/db_sqlite import getValue, sql

from server import serve, accessLogLine
from nginx import parseLogEntry
from std/options import none

from trap import TrapConfig, Tactic, trapHook
from database import getDbConnection

let tempDir = getTempDir() / "nginwho_test_server"
let root = tempDir / "site"
let logPath = tempDir / "access.log"
const port = Port(18089)

removeDir(tempDir)
createDir(root / "posts" / "hello")
writeFile(root / "index.html", "home")
writeFile(root / "posts" / "hello" / "index.html", "hello")
writeFile(root / "404.html", "custom 404")
writeFile(root / "style.css", "body{}")

asyncCheck serve(root, logPath, port, "127.0.0.1")

# the same site with the trap on and no nginx in front
const trapPort = Port(18093)
let trapLogPath = tempDir / "trap_access.log"
let trapDb = tempDir / "trap.db"
asyncCheck serve(root, trapLogPath, trapPort, "127.0.0.1", trapHook(TrapConfig(enabled: true,
    maxConnections: 10, maxSeconds: 60, dripMinMs: 0, dripMaxMs: 0, bombs: true, bombAfter: 100,
    agents: @[("deepseek", none(Tactic))]), trapDb))


proc request(raw: string, port = port): string =
  ## Sends a raw request and returns everything the server sends back until it closes
  proc run(): Future[string] {.async.} =
    let socket = newAsyncSocket()
    defer: socket.close()
    await socket.connect("127.0.0.1", port)
    await socket.send(raw)
    while true:
      let data = await socket.recv(4096)
      if data == "":
        break
      result.add(data)
  waitFor run()


proc get(path: string, headers = "", port = port): string =
  request("GET " & path & " HTTP/1.1\r\nHost: x\r\n" & headers & "Connection: close\r\n\r\n", port)


proc body(response: string): string =
  response.split("\r\n\r\n", maxsplit = 1)[1]


suite "server":
  test "serves index.html for the root":
    let response = get("/")
    check response.startsWith("HTTP/1.1 200 OK")
    check "Content-Type: text/html" in response
    check response.body == "home"

  test "redirects a directory without the trailing slash":
    let response = get("/posts/hello?a=1")
    check response.startsWith("HTTP/1.1 301")
    check "Location: /posts/hello/?a=1" in response
    check get("/posts/hello/").body == "hello"

  test "sends the custom 404 page":
    let response = get("/missing")
    check response.startsWith("HTTP/1.1 404")
    check response.body == "custom 404"
    check get("/style.css/").startsWith("HTTP/1.1 404")

  test "never leaves the root":
    check get("/../../etc/passwd").startsWith("HTTP/1.1 400")
    check get("/posts/%2e%2e/%2e%2e/../etc/passwd").startsWith("HTTP/1.1 400")

  test "only allows GET and HEAD":
    check request("POST / HTTP/1.1\r\n\r\n").startsWith("HTTP/1.1 405")
    let head = request("HEAD /style.css HTTP/1.1\r\nConnection: close\r\n\r\n")
    check "Content-Length: 6" in head
    check head.body == ""

  test "answers 304 when the file did not change":
    let etag = get("/style.css").split("ETag: ")[1].split("\r\n")[0]
    check get("/style.css", "If-None-Match: " & etag & "\r\n").startsWith("HTTP/1.1 304")

  test "keeps the connection open for more requests":
    let response = request("GET / HTTP/1.1\r\n\r\nGET /style.css HTTP/1.1\r\nConnection: close\r\n\r\n")
    check response.count("HTTP/1.1 200 OK") == 2

  test "rejects broken requests":
    check request("hello\r\n\r\n").startsWith("HTTP/1.1 400")
    check request("GET / HTTP/1.1\r\nno colon\r\n\r\n").startsWith("HTTP/1.1 400")

  test "writes logs the nginx parser understands":
    discard get("/posts/hello/", "Referer: https://example.com/\r\nUser-Agent: Mozilla/5.0 (X11)\r\n")
    let log = parseLogEntry(readFile(logPath).strip().splitLines()[^1], "")
    check log.nonDefault == ""
    check log.remoteIP == "127.0.0.1"
    check log.httpMethod == "GET"
    check log.requestURI == "/posts/hello"
    check log.statusCode == "200"
    check log.responseSize == "5"
    check log.referrer == "https://example.com"
    check log.userAgent == "Mozilla/5.0 (X11)"

  test "escapes quotes in logs like nginx":
    let line = accessLogLine("1.2.3.4", "GET / HTTP/1.1", 200, 0, "", "a\"b")
    check line.endsWith("\"GET / HTTP/1.1\" 200 0 \"-\" \"a\\x22b\"\n")


suite "server with the trap":
  test "probes are trapped, real files and typos are served as usual":
    check get("/", port = trapPort).body == "home"
    check get("/typo", port = trapPort).body == "custom 404"

    let env = get("/.env", port = trapPort)
    check env.startsWith("HTTP/1.1 200")
    check "AWS_ACCESS_KEY_ID" in env.body

    let hits = getDbConnection(trapDb).getValue(sql"SELECT request_uri FROM trap_hits")
    check hits == "/.env"
    # like nginx's access_log off for the trap, it keeps its own record
    check "/.env" notin readFile(trapLogPath)
    check "/typo" in readFile(trapLogPath)

  test "a listed user agent is trapped even on a real page":
    let page = get("/", "User-Agent: DeepSeekBot\r\n", port = trapPort)
    check page.startsWith("HTTP/1.1 200")
    check page.body != "home"
    check get("/", "User-Agent: Mozilla/5.0\r\n", port = trapPort).body == "home"
