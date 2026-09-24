## Plays with bots that probe for files we do not have.
## nginx hands its 403s and 404s to this server, the rest is up to us.
## Every hit is saved in the `trap_hits` table with what we did about it

import std/asyncdispatch
from std/asyncnet import AsyncSocket, send, close, getPeerAddr, newAsyncSocket,
    setSockOpt, bindAddr, listen, accept
from std/net import Port, Domain, SOBool, OptReuseAddr
from std/httpcore import HttpCode, Http200, Http401, Http404
from std/random import Rand, initRand, rand, sample
from std/hashes import hash
from std/tables import Table, toTable, `[]`, `[]=`, initTable, hasKey, mgetOrPut, pairs, clear
from std/strutils import toLowerAscii, contains, endsWith, startsWith, replace, split, strip
from std/strformat import fmt
from std/times import epochTime, now, format
from std/uri import decodeUrl
from std/logging import info, error
from db_connector/db_sqlite import DbConn

from nginx import dateFormat
from server import Request, TrapHook, readRequest, readBody, header, responseHead, headTimeout
from database import TrapHit, getDbConnection, createTables, insertTrapHit, finishTrapHit


type
  TrapConfig* = object
    enabled*: bool
    port*: int = 7777
    maxConnections*: int = 200
    maxSeconds*: int = 900
    dripMinMs*: int = 500
    dripMaxMs*: int = 700
    bombs*: bool = true
    bombAfter*: int = 3 # trapped hits from one IP in a day before it gets a bomb

  Trap = enum
    ## What the bot was after
    noTrap = "none"
    envFile = "env"
    creds = "creds"
    gitRepo = "git"
    wordpress = "wordpress"
    phpFile = "php"
    configFile = "config"
    backup = "backup"
    adminPanel = "admin"
    apiDebug = "api"
    rce = "rce"
    wellKnown = "well-known"

  Tactic = enum
    ## What we do about it
    drip = "drip"       # a fake file, one byte at a time
    endless = "endless" # a body that never ends
    maze = "maze"       # fake folder listings that lead to more folders
    login = "login"     # a fake login that never lets them in
    bomb = "bomb"       # a gzip bomb


const
  envTemplate = staticRead("traps/env.txt")
  credentialsTemplate = staticRead("traps/credentials.txt")
  gitConfigTemplate = staticRead("traps/git_config.txt")
  configTemplate = staticRead("traps/config.json")
  passwdTemplate = staticRead("traps/passwd.txt")
  actuatorTemplate = staticRead("traps/actuator_env.json")
  loginTemplate = staticRead("traps/login.html")
  phpinfoTemplate = staticRead("traps/phpinfo.html")
  # 1 MiB of zeros gzipped. gzip members can be glued together, so sending this
  # file over and over unpacks into one huge stream on their side
  zerosGz = staticRead("traps/zeros.gz")

  bombMembers = 10_000 # 1 MiB of zeros each, about 10 GB unpacked
  maxBodyBytes = 8192 # of a fake login POST

  apps = ["acme", "northwind", "helios", "lumen", "vertex", "cobalt", "meridian", "quanta"]
  users = ["admin", "deploy", "jenkins", "svc-backup", "mgarcia", "twong", "pkoch"]

var
  active = 0                          # trapped connections right now
  hitsToday = initTable[string, int]() # how often we saw an IP today
  today = ""


type
  Rng = ref object
    ## Rand in a ref so the async procs can carry it across an await
    state: Rand

  Played = ref object
    ## What a trap sent so far. A ref so the count survives a bot hanging up
    ## in the middle, which is how most traps end
    bytes: int
    detail: string # the fake secret handed out, or the credentials they tried


proc newRng(seed: int): Rng =
  Rng(state: initRand(seed))


proc rand(rng: Rng, slice: HSlice[int, int]): int =
  rng.state.rand(slice)


proc anyOf(path: string, needles: openArray[string]): bool =
  for needle in needles:
    if path.contains(needle):
      return true


proc classify*(path: string): Trap =
  ## What the bot was looking for. The patterns come from tmp/TODO.md
  let p = path.toLowerAscii

  # Spring boot endpoints first, so /actuator/env is not read as a plain .env file
  if p.anyOf(["actuator", "jolokia", "heapdump"]): return apiDebug
  if p.anyOf([".env", "environ", "sendgrid"]) or p.endsWith("/env"): return envFile
  if p.anyOf([".git", ".svn", ".hg", ".bzr"]): return gitRepo
  if p.anyOf(["wp-", "wordpress", "xmlrpc", "wlwmanifest", "rest_route"]): return wordpress
  if p.anyOf([".aws", "aws.json", "aws.yml", "aws.yaml", "credential", ".ssh", "id_rsa",
              "id_ed25519", ".npmrc", ".pypirc", ".netrc", ".s3cfg", ".boto", "rclone",
              "secret", "firebase", "terraform", "gcp", "stripe", "serviceaccount",
              "service-account", "service_account", "sa.json", "key.json", "privatekey",
              "private-key", "keyfile", ".key", ".pem", ".bash", ".zsh", ".claude", ".mcp",
              ".cursor", ".codex"]):
    return creds
  if p.anyOf([".sql", ".bak", ".backup", ".old", ".zip", ".tar", ".gz", ".tgz", ".rar",
              ".7z", ".swp", ".log", "dump", "backup"]):
    return backup
  if p.anyOf(["passwd", "/bin/sh", "../", "%2e%2e", "%5c", "jndi", "${", "shell", "cgi-bin",
              "/cmd", "getcmd", "eval", ".sh", ".asp", ".jsp", ".cgi"]):
    return rce
  # admin and login pages before .php, so a login page like /administrator/index.php
  # gets the fake login that harvests credentials, not the generic php trap
  if p.anyOf(["admin", "login", "signin", "sign-in", "signup", "register", "dashboard",
              "cpanel", "backoffice", "webmail", "/manager", "file-manager", "console",
              "portal", "panel", "secure", "account", "/auth", "reset-password",
              "forgot-password"]):
    return adminPanel
  if p.anyOf([".php", "phpinfo", "phpmyadmin", "adminer", "_profiler", "_ignition",
              "artisan", "_debugbar", "livewire", "telescope"]):
    return phpFile
  if p.anyOf(["config", "appsettings", "settings", "application.yml", "application.properties",
              "docker", ".vscode", ".idea", "sftp", ".htaccess", ".htpasswd", "serverless",
              "vercel", "netlify", ".travis", "gradle", "package.json", "composer.json",
              "manifest.json", ".vite", "values.yaml", ".toml", ".ds_store"]):
    return configFile
  if p.anyOf(["/api", "graphql", "swagger", "openapi", "/debug", "server-status",
              "server-info", "/info", "/health", "/mcp", "/sse", "/metrics", "/solr",
              "/vendor", "autodiscover", "/owa", "/hudson", "/jenkins", "/nacos", "/druid"]):
    return apiDebug
  if p.contains(".well-known/"): return wellKnown

  return noTrap


proc token(rng: Rng, length: int,
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"): string =
  for _ in 1 .. length:
    result.add(alphabet[rng.state.rand(alphabet.high)])


proc fakeValues(rng: Rng): Table[string, string] =
  ## Believable looking secrets. They are all made up and lead nowhere
  let app = rng.state.sample(apps)
  return {
    "{{APP}}": app,
    "{{HOST}}": app & ".io",
    "{{IP}}": fmt"10.{rng.rand(1 .. 254)}.{rng.rand(1 .. 254)}.{rng.rand(1 .. 254)}",
    "{{USER}}": rng.state.sample(users),
    "{{PASS}}": token(rng, 18),
    "{{PASS2}}": token(rng, 18),
    "{{PASS3}}": token(rng, 18),
    "{{AWS_KEY}}": "AKIA" & token(rng, 16, "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"),
    "{{AWS_KEY2}}": "AKIA" & token(rng, 16, "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"),
    "{{AWS_KEY3}}": "AKIA" & token(rng, 16, "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"),
    "{{AWS_SECRET}}": token(rng, 40, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/"),
    "{{AWS_SECRET2}}": token(rng, 40, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/"),
    "{{AWS_SECRET3}}": token(rng, 40, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/"),
    "{{STRIPE}}": "sk_live_" & token(rng, 24),
    "{{TOKEN}}": "ghp_" & token(rng, 36),
    "{{HEX}}": token(rng, 64, "0123456789abcdef"),
    "{{B64}}": token(rng, 43) & "=",
    "{{ID}}": token(rng, 24),
    "{{VERSION}}": fmt"{rng.rand(4 .. 6)}.{rng.rand(0 .. 9)}.{rng.rand(0 .. 9)}",
    "{{ERROR}}": "",
  }.toTable


proc fill(text: string, values: Table[string, string]): string =
  result = text
  for placeholder, value in values.pairs:
    result = result.replace(placeholder, value)


proc fakeFile(trap: Trap, path: string, values: Table[string, string], rng: Rng):
    tuple[body, contentType, canary: string] =
  ## The fake file a bot gets for the path it asked for, and the fake secret in it
  ## that we can trace back to them. A file without a secret has no canary
  let p = path.toLowerAscii
  let awsKey = values["{{AWS_KEY}}"]

  case trap
  of envFile:
    return (fill(envTemplate, values), "text/plain", awsKey)
  of creds:
    if p.endsWith(".pem") or p.contains("id_rsa") or p.contains("key"):
      let alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/"
      # the first line is enough to recognize the key
      let firstLine = token(rng, 64, alphabet)
      var key = "-----BEGIN RSA PRIVATE KEY-----\n" & firstLine & "\n"
      for _ in 2 .. 25:
        key.add(token(rng, 64, alphabet) & "\n")
      return (key & "-----END RSA PRIVATE KEY-----\n", "text/plain", firstLine)
    return (fill(credentialsTemplate, values), "text/plain", awsKey)
  of gitRepo:
    if p.endsWith("head"):
      return ("ref: refs/heads/main\n", "text/plain", "")
    return (fill(gitConfigTemplate, values), "text/plain", values["{{TOKEN}}"])
  of phpFile:
    return (fill(phpinfoTemplate, values), "text/html", awsKey)
  of apiDebug:
    return (fill(actuatorTemplate, values), "application/json", awsKey)
  of rce:
    return (fill(passwdTemplate, values), "text/plain", "")
  of configFile, backup, wordpress, adminPanel, wellKnown, noTrap:
    return (fill(configTemplate, values), "application/json", awsKey)


proc endlessChunk(trap: Trap, rng: Rng, index: int,
    values: Table[string, string]): string =
  ## One more piece of a body that never ends
  case trap
  of backup:
    let
      email = token(rng, 8) & "@" & values["{{HOST}}"]
      password = "$2y$10$" & token(rng, 53, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789./")
    "INSERT INTO users VALUES (" & $index & ", '" & email & "', '" & password & "');\n"
  of wordpress:
    "<member><name>" & token(rng, 12) & "</name><value><string>" &
        token(rng, 40) & "</string></value></member>\n"
  of gitRepo:
    token(rng, 40, "0123456789abcdef") & "\trefs/heads/" & token(rng, 10) & "\n"
  else:
    "{\"id\": " & $index & ", \"token\": \"" & token(rng, 32) & "\"},\n"


proc mazePage(rng: Rng, path: string): string =
  ## A folder listing whose links all lead to more folders
  result = fmt"""<!DOCTYPE html>
<html><head><title>Index of {path}</title></head>
<body><h1>Index of {path}</h1><hr><pre><a href="../">../</a>
"""
  for _ in 1 .. rng.rand(8 .. 20):
    let name = token(rng, rng.rand(4 .. 12), "abcdefghijklmnopqrstuvwxyz0123456789_-")
    let isDir = rng.rand(1 .. 3) > 1
    let link = if isDir: name & "/" else: name & ".tar.gz"
    result.add(fmt"""<a href="{link}">{link}</a>""" &
        fmt"                 2026-0{rng.rand(1 .. 9)}-{rng.rand(10 .. 28)} {rng.rand(10 .. 23)}:{rng.rand(10 .. 59)}" &
        fmt"  {rng.rand(1000 .. 999999)}" & "\n")
  result.add("</pre><hr></body></html>\n")


proc tacticFor(trap: Trap, path: string, repeatOffender: bool, cfg: TrapConfig): Tactic =
  let p = path.toLowerAscii

  result =
    case trap
    of wordpress:
      if p.anyOf(["login", "wp-admin"]): login
      elif p.contains("xmlrpc"): endless
      else: drip
    of adminPanel: login
    of backup:
      if p.anyOf([".gz", ".zip", ".tar", ".7z", ".rar", ".tgz"]): bomb else: endless
    of phpFile:
      if p.anyOf(["phpinfo", "info.php"]): drip else: bomb
    of gitRepo:
      if p.endsWith("/config") or p.endsWith("head"): drip else: maze
    of apiDebug:
      if p.anyOf(["actuator", "env", "config"]): drip else: endless
    else: drip

  # someone who keeps coming back has earned a bomb
  if repeatOffender and result != login:
    result = bomb
  if result == bomb and not cfg.bombs:
    result = endless


proc sendOrFail(client: AsyncSocket, data: string) {.async.} =
  ## asyncnet quietly ignores a closed connection by default. A trap needs to know,
  ## or it keeps playing to a bot that already left
  await client.send(data, flags = {})


proc dripBody(client: AsyncSocket, body: string, cfg: TrapConfig, rng: Rng,
    deadline: float, played: Played) {.async.} =
  ## Sends a fake file one byte at a time. They almost never get to the end
  for c in body:
    if epochTime() > deadline:
      break
    await client.sendOrFail($c)
    played.bytes.inc
    await sleepAsync(rng.rand(cfg.dripMinMs .. cfg.dripMaxMs))


proc dripEndless(client: AsyncSocket, trap: Trap, values: Table[string, string],
    cfg: TrapConfig, rng: Rng, deadline: float, played: Played) {.async.} =
  var index = 0
  while epochTime() < deadline:
    let chunk = endlessChunk(trap, rng, index, values)
    await client.sendOrFail(chunk)
    played.bytes.inc(chunk.len)
    index.inc
    await sleepAsync(rng.rand(cfg.dripMinMs .. cfg.dripMaxMs))


proc sendBomb(client: AsyncSocket, deadline: float, played: Played) {.async.} =
  ## About 10 MB on the wire, about 10 GB once they unpack it
  for _ in 1 .. bombMembers:
    if epochTime() > deadline:
      break
    await client.sendOrFail(zerosGz)
    played.bytes.inc(zerosGz.len)


proc submittedCredentials(body: string): string =
  ## Pulls the username and password out of a posted login form
  var user, password: string
  for field in body.split('&'):
    let pair = field.split('=', maxsplit = 1)
    if pair.len != 2:
      continue
    case pair[0]
    of "log", "username", "user", "email", "name": user = decodeUrl(pair[1])
    of "pwd", "password", "pass", "passwd": password = decodeUrl(pair[1])
    else: discard

  if user == "" and password == "":
    return ""
  return fmt"tried {user}:{password}"


proc playLogin(client: AsyncSocket, req: Request, values: Table[string, string],
    rng: Rng, deadline: float, played: Played) {.async.} =
  ## A login page that takes its time and then says the password was wrong
  var page = values

  if req.httpMethod == "POST":
    let body = await client.readBody(req, maxBodyBytes)
    played.detail = submittedCredentials(body)
    # a real check would be quick. this one thinks about it for a while
    await sleepAsync(rng.rand(10_000 .. 30_000))
    page["{{ERROR}}"] = "<div class=\"error\"><strong>Error:</strong> " &
        "The password you entered is incorrect. Please try again.</div>"

  let body = fill(loginTemplate, page)
  let status = if req.httpMethod == "POST": Http401 else: Http200
  await client.send(responseHead(status, false, [
    ("Content-Type", "text/html; charset=UTF-8"),
    ("Content-Length", $body.len),
    ("Cache-Control", "no-store"),
  ]))
  if req.httpMethod != "HEAD":
    await client.send(body)
    played.bytes = body.len


proc play(client: AsyncSocket, req: Request, trap: Trap, tactic: Tactic,
    cfg: TrapConfig, rng: Rng, played: Played) {.async.} =
  ## Runs one trap until the bot leaves or the time runs out.
  ## Progress goes into `played` as it happens, so a bot hanging up still leaves a record
  let
    deadline = epochTime() + cfg.maxSeconds.float
    values = fakeValues(rng)

  case tactic
  of login:
    await client.playLogin(req, values, rng, deadline, played)
  of bomb:
    # a download keeps its gzip through Cloudflare, a page gets unpacked by the client
    let download = req.path.toLowerAscii.anyOf([".gz", ".zip", ".tar", ".7z", ".rar", ".tgz"])
    var headers = @[("Content-Type", if download: "application/gzip" else: "text/plain")]
    if not download:
      headers.add(("Content-Encoding", "gzip"))
    await client.send(responseHead(Http200, false, headers))
    if req.httpMethod != "HEAD":
      await client.sendBomb(deadline, played)
  of maze:
    let body = mazePage(rng, req.path)
    await client.send(responseHead(Http200, false, [
      ("Content-Type", "text/html"), ("Content-Length", $body.len)]))
    if req.httpMethod != "HEAD":
      await client.dripBody(body, cfg, rng, deadline, played)
  of endless:
    await client.send(responseHead(Http200, false, [("Content-Type", "text/plain")]))
    if req.httpMethod != "HEAD":
      await client.dripEndless(trap, values, cfg, rng, deadline, played)
  of drip:
    let (body, contentType, canary) = fakeFile(trap, req.path, values, rng)
    played.detail = canary
    await client.send(responseHead(Http200, false, [
      ("Content-Type", contentType), ("Content-Length", $body.len)]))
    if req.httpMethod != "HEAD":
      await client.dripBody(body, cfg, rng, deadline, played)


proc sendNotFound(client: AsyncSocket) {.async.} =
  ## nginx turns this into the real 404 page of the site
  const body = "404 Not Found\n"
  await client.send(responseHead(Http404, false, [
    ("Content-Type", "text/plain"), ("Content-Length", $body.len)]))
  await client.send(body)


proc isRepeatOffender(ip: string, cfg: TrapConfig): bool =
  ## Counts hits per IP per day. Yesterday's counts are dropped
  let day = now().format("yyyy-MM-dd")
  if day != today:
    today = day
    hitsToday.clear()

  hitsToday.mgetOrPut(ip, 0).inc
  # "after N hits": the first N get played with, the next one gets the bomb
  return hitsToday[ip] > cfg.bombAfter


proc trapRequest(client: AsyncSocket, req: Request, ip: string, cfg: TrapConfig,
    db: DbConn): Future[bool] {.async.} =
  ## Plays with the bot when the request is a probe. Returns false when it is not one
  ## or the trap is full, so the caller answers as usual
  let trap = classify(req.path)
  if trap == noTrap or active >= cfg.maxConnections:
    return false

  let tactic = tacticFor(trap, req.path, isRepeatOffender(ip, cfg), cfg)
  info(fmt"Trapping {ip} in the {tactic} for {req.path} ({trap})")

  # the same bot asking for the same file twice sees the same fake content
  let rng = newRng(hash(ip & req.path))
  let started = epochTime()

  # the hit is saved before the trap starts, so we know who tried what right away.
  # a slow drip can hold a bot that already hung up for a long time before a send fails
  let id = db.insertTrapHit(TrapHit(
    date: now().format(dateFormat),
    remoteIP: ip,
    httpMethod: req.httpMethod,
    requestURI: req.path & req.query,
    userAgent: req.header("User-Agent"),
    trap: $trap,
    tactic: $tactic,
  ))

  let played = Played()
  active.inc
  try:
    await client.play(req, trap, tactic, cfg, rng, played)
  except CatchableError:
    # a bot hanging up mid trap is the normal ending
    discard
  finally:
    active.dec
    # fill in what we ended up sending and how long we held them
    db.finishTrapHit(id, played.bytes, int(epochTime() - started), played.detail)
  return true


proc handle(client: AsyncSocket, cfg: TrapConfig, db: DbConn) {.async.} =
  defer: client.close()

  try:
    let reading = client.readRequest()
    if not await reading.withTimeout(headTimeout):
      return
    let req = reading.read()
    if req.httpMethod == "":
      return

    # nginx sits in front and knows the real IP thanks to Cloudflare's header
    var ip = req.header("X-Real-IP")
    if ip == "":
      ip = client.getPeerAddr()[0]

    if not await client.trapRequest(req, ip, cfg, db):
      await client.sendNotFound()
  except CatchableError:
    # a failure before the trap even starts, nothing to record
    discard


proc trapHook*(cfg: TrapConfig, dbPath: string): TrapHook =
  ## For --serve, where no nginx sits in front: the server hands its misses to the trap itself
  let db = getDbConnection(dbPath)
  createTables(db)
  return proc (client: AsyncSocket, req: Request, remoteIP: string): Future[bool] =
    client.trapRequest(req, remoteIP, cfg, db)


proc trap*(cfg: TrapConfig, dbPath: string, address = "127.0.0.1") {.async.} =
  ## Listens for the requests nginx could not answer
  let db = getDbConnection(dbPath)
  createTables(db)

  let server = newAsyncSocket(Domain.AF_INET)
  server.setSockOpt(OptReuseAddr, true)
  try:
    server.bindAddr(Port(cfg.port), address)
    server.listen()
  except OSError as e:
    error(fmt"Trap could not listen on {address}:{cfg.port}: {e.msg}")
    quit(1)
  info(fmt"Trap is open on {address}:{cfg.port}")

  while true:
    try:
      let client = await server.accept()
      asyncCheck handle(client, cfg, db)
    except OSError as e:
      error(fmt"Trap could not accept a connection: {e.msg}")
