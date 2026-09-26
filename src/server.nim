## A small static file server that writes nginx style access logs

import std/[asyncdispatch, net, httpcore, os]
from std/strutils import find, contains, strip, split, startsWith, endsWith,
    toHex, replace, removePrefix, toLowerAscii, parseInt
from std/times import fromUnix, utc, format, now, getTime, toUnix
from std/asyncnet import AsyncSocket, recvLine, recv, send, close, getPeerAddr,
    newAsyncSocket, setSockOpt, bindAddr, listen, accept
from std/uri import decodeUrl
from std/strformat import fmt
from std/mimetypes import newMimetypes, getMimetype
from std/logging import info, error


const
  maxLine = 8192
  maxHeaders = 100
  headTimeout* = 10_000 # milliseconds to send the headers, also the keep-alive timeout
  chunkBytes = 64 * 1024


type
  Request* = object
    line*: string # the request line as it was sent, for the access log
    httpMethod*: string
    path*: string
    query*: string
    version*: string
    headers*: HttpHeaders

  TrapHook* = proc (client: AsyncSocket, req: Request,
      remoteIP: string, miss: bool): Future[bool]
    ## Sees every request first. `miss` is true when the server can't serve it, like
    ## nginx's error_page to the trap. Returns false when it does not take one, and
    ## the server answers as usual


let mimes = newMimetypes()


proc readRequest*(client: AsyncSocket): Future[Request] {.async.} =
  ## Reads the request line and headers. An empty `line` means the client left,
  ## an empty `httpMethod` means the request is broken
  result.headers = newHttpHeaders()
  result.line = await client.recvLine(maxLength = maxLine)
  if result.line in ["", "\r\n"] or result.line.len == maxLine:
    return

  for i in 0 .. maxHeaders:
    let line = await client.recvLine(maxLength = maxLine)
    if line == "\r\n":
      break
    let colon = line.find(':')
    if line == "" or line.len == maxLine or colon < 1 or i == maxHeaders:
      return
    result.headers.add(line[0 ..< colon].strip(), line[colon + 1 .. ^1].strip())

  let parts = result.line.split(' ')
  if parts.len != 3 or not parts[1].startsWith("/") or not parts[2].startsWith("HTTP/1."):
    return

  let target = parts[1].split('?', maxsplit = 1)
  result.path = decodeUrl(target[0], decodePlus = false)
  if target.len == 2:
    result.query = "?" & target[1]
  result.version = parts[2]
  result.httpMethod = parts[0]


proc header*(req: Request, name: string): string =
  if req.headers.hasKey(name): $req.headers[name] else: ""


proc readBody*(client: AsyncSocket, req: Request, limit: int): Future[
    string] {.async.} =
  ## Reads a small request body, such as a submitted login form. Bigger bodies are cut short
  var length = 0
  try:
    length = min(parseInt(req.header("Content-Length")), limit)
  except ValueError:
    return
  if length > 0:
    result = await client.recv(length)


proc httpDate*(unixTime: int64): string =
  times.fromUnix(unixTime).utc.format("ddd, dd MMM yyyy HH:mm:ss 'GMT'")


proc escapeLog(value: string): string =
  ## Escapes quotes and unprintable bytes the same way nginx does
  for c in value:
    if c == '"' or c == '\\' or c < ' ' or c > '~':
      result.add("\\x" & toHex(ord(c), 2))
    else:
      result.add(c)


proc accessLogLine*(remoteIP, request: string, status, bytesSent: int,
    referrer, userAgent: string): string =
  ## Builds a line in nginx's default "combined" format
  let time = now().format("dd/MMM/yyyy:HH:mm:ss ") & now().format(
      "zzz").replace(":", "")
  let referrer = if referrer == "": "-" else: escapeLog(referrer)
  fmt"""{remoteIP} - - [{time}] "{escapeLog(request)}" {status} {bytesSent} "{referrer}" "{escapeLog(userAgent)}"""" & "\n"


proc writeAccessLog(path, line: string) =
  # opening the file each time keeps working after logrotate moves it
  try:
    let file = open(path, fmAppend)
    defer: file.close()
    file.write(line)
  except IOError as e:
    error(fmt"Could not write to {path}: {e.msg}")


proc responseHead*(status: HttpCode, keepAlive: bool, headers: openArray[(
    string, string)]): string =
  result = "HTTP/1.1 " & $status & "\r\n"
  result.add("Server: nginwho\r\n")
  result.add("Date: " & httpDate(times.getTime().toUnix) & "\r\n")
  for (name, value) in headers:
    result.add(name & ": " & value & "\r\n")
  result.add("Connection: " & (if keepAlive: "keep-alive" else: "close") & "\r\n\r\n")


proc sendText(client: AsyncSocket, req: Request, status: HttpCode,
    keepAlive: bool, headers: seq[(string, string)] = @[]): Future[
        int] {.async.} =
  ## Sends a short plain text body such as "404 Not Found"
  let body = $status & "\n"
  var all = headers
  all.add(("Content-Type", "text/plain"))
  all.add(("Content-Length", $body.len))
  await client.send(responseHead(status, keepAlive, all))
  if req.httpMethod != "HEAD":
    await client.send(body)
    return body.len


proc sendFile(client: AsyncSocket, req: Request, path: string, status: HttpCode,
    keepAlive: bool): Future[tuple[status: HttpCode,
        bytesSent: int]] {.async.} =
  ## Sends a file in chunks so big files don't sit in memory
  let file = open(path)
  defer: file.close()

  let
    size = file.getFileSize()
    modified = getFileInfo(path).lastWriteTime.toUnix
    lastModified = httpDate(modified)
    # same as nginx: hex mtime and size
    etag = "\"" & toHex(modified).strip(trailing = false, chars = {'0'}) & "-" &
        toHex(size).strip(trailing = false, chars = {'0'}) & "\""

  var headers = @[
    ("Content-Type", mimes.getMimetype(path.splitFile.ext.strip(chars = {'.'}),
        "application/octet-stream")),
    ("Last-Modified", lastModified),
    ("ETag", etag),
  ]

  if status == Http200 and (req.header("If-None-Match") in [etag, "*"] or
      req.header("If-Modified-Since") == lastModified):
    await client.send(responseHead(Http304, keepAlive, headers))
    return (Http304, 0)

  result.status = status
  headers.add(("Content-Length", $size))
  await client.send(responseHead(status, keepAlive, headers))
  if req.httpMethod == "HEAD":
    return

  var buffer = newString(chunkBytes)
  while true:
    let n = file.readBuffer(buffer[0].addr, buffer.len)
    if n <= 0:
      break
    await client.send(buffer[0].addr, n)
    result.bytesSent += n


proc isFile(path: string): bool =
  try: getFileInfo(path).kind == pcFile
  except OSError: false


proc resolve(root, urlPath: string): string =
  ## Same as try_files $uri $uri/ =404. Returns the file to send,
  ## "/" when a directory is asked for without the trailing slash and "" when nothing is found
  let path = root / urlPath
  if isFile(path) and not urlPath.endsWith("/"):
    return path
  try:
    if getFileInfo(path).kind == pcDir:
      if not urlPath.endsWith("/"):
        return "/"
      if isFile(path / "index.html"):
        return path / "index.html"
  except OSError:
    discard


proc respond(client: AsyncSocket, req: Request, root: string, keepAlive: bool):
    Future[tuple[status: HttpCode, bytesSent: int]] {.async.} =
  if req.httpMethod notin ["GET", "HEAD"]:
    return (Http405, await client.sendText(req, Http405, keepAlive))

  # never leave the root
  if "\0" in req.path or "/../" in req.path & "/":
    return (Http400, await client.sendText(req, Http400, keepAlive))

  let file = resolve(root, req.path)
  if file == "/":
    let location = req.path & "/" & req.query
    return (Http301, await client.sendText(req, Http301, keepAlive, @[(
        "Location", location)]))
  if file != "":
    return await client.sendFile(req, file, Http200, keepAlive)

  if isFile(root / "404.html"):
    return await client.sendFile(req, root / "404.html", Http404, keepAlive)
  return (Http404, await client.sendText(req, Http404, keepAlive))


proc handleClient(client: AsyncSocket, root, logPath: string,
    trapHook: TrapHook) {.async.} =
  defer: client.close()

  try:
    var remoteIP = client.getPeerAddr()[0]
    remoteIP.removePrefix("::ffff:") # IPv4 clients on an IPv6 socket

    while true:
      let reading = client.readRequest()
      if not await reading.withTimeout(headTimeout):
        return
      let req = reading.read()
      if req.line in ["", "\r\n"]:
        return

      # the trap gets a look first: what would be a 404 or 405, and listed user agents.
      # it keeps its own record
      if trapHook != nil and req.httpMethod != "":
        let miss = req.httpMethod notin ["GET", "HEAD"] or resolve(root, req.path) == ""
        if await trapHook(client, req, remoteIP, miss):
          return

      # a request body is never read, so the connection can't be reused after one
      let keepAlive = req.httpMethod != "" and req.version == "HTTP/1.1" and
          req.header("Connection").toLowerAscii != "close" and
          req.header("Content-Length") in ["", "0"] and
          req.header("Transfer-Encoding") == ""

      let (status, bytesSent) =
        if req.httpMethod == "": (Http400, await client.sendText(req, Http400, false))
        else: await client.respond(req, root, keepAlive)

      writeAccessLog(logPath, accessLogLine(remoteIP, req.line, status.int,
          bytesSent, req.header("Referer"), req.header("User-Agent")))

      if not keepAlive:
        return
  except CatchableError:
    # clients disconnecting mid response is normal
    discard


proc serve*(root, logPath: string, port: Port, address = "::",
    trapHook: TrapHook = nil) {.async.} =
  let server = newAsyncSocket(if ':' in address: Domain.AF_INET6 else: Domain.AF_INET)
  server.setSockOpt(OptReuseAddr, true)
  try:
    server.bindAddr(port, address)
    server.listen()
  except OSError as e:
    # ports below 1024 need root or CAP_NET_BIND_SERVICE
    error(fmt"Could not listen on [{address}]:{port}: {e.msg}")
    quit(1)
  info(fmt"Serving {root} on [{address}]:{port}")

  while true:
    try:
      let client = await server.accept()
      asyncCheck handleClient(client, root, logPath, trapHook)
    except OSError as e:
      error(fmt"Could not accept a connection: {e.msg}")
