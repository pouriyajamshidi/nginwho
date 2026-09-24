from std/times import parse, format
from std/strutils import splitWhitespace, replace, endsWith, startsWith, strip, contains, join, rfind, splitLines
from std/os import findExe, fileExists
from std/osproc import execCmd
from std/strformat import fmt
from std/logging import info, error


type Log* = object
  date*: string
  remoteIP*: string
  httpMethod*: string
  requestURI*: string
  statusCode*: string
  responseSize*: string
  referrer*: string
  userAgent*: string
  nonDefault*: string
  remoteUser*: string
  authenticatedUser*: string


const
  dateFormat* = "yyyy-MM-dd HH:mm:ss" # how dates are saved in the database
  readChunkBytes* = 1024 * 1024


proc convertDateFormat*(nginxDate: string): string =
  parse(nginxDate, "d-MMM-yyyy:HH:mm:ss").format(dateFormat)


proc isStaticAsset*(requestURI: string): bool =
  ## Fonts, scripts and styles are not stored, they only add noise
  # TODO: Decide whether to exclude these or not
  requestURI.endsWith(".woff2") or requestURI.endsWith(".js") or requestURI.endsWith(".css")


proc ensureNginxLogExists*(logPath: string) =
  info("Ensuring nginx log exists")

  if not fileExists(logPath):
    error(fmt"nginx log file not found at: {logPath}")
    quit(1)

proc ensureNginxExists*() =
  info("Ensuring nginx command exists")

  if findExe("nginx") == "":
    error("nginx command not found")
    quit(1)


proc testNginxConfig(): int =
  info("Testing nginx configuration")

  return execCmd("nginx -t")


proc reloadNginx*() =
  info("Attempting to soft-reload nginx")

  if testNginxConfig() != 0:
    error("nginx configuration test failed... Aborting reload")
    return

  if execCmd("nginx -s reload") != 0:
    error("nginx process reload failed")
  else:
    info("nginx process reloaded successfully")


proc parseLogEntry*(logLine: string, omit: string): Log =
  var log: Log

  let matches: seq[string] = logLine.splitWhitespace()

  if matches.len >= 12:
    log.remoteIP = matches[0]

    # Nginx 1.24.0 has decided to write weird and incorrect dates
    try:
      log.date = convertDateFormat(matches[3].replace("\"", "").replace("[",
          "").replace("/", "-"))
    except ValueError as e:
      error(fmt"Failed parsing log date: {e.msg}")
      log.nonDefault = logLine
      return log

    log.httpMethod = matches[5].replace("\"", "")

    var requestURI = matches[6].replace("\"", "")
    if requestURI.endsWith("/") and len(requestURI) > 1:
      requestURI = requestURI.strip(leading = false, chars = {'/'})
    log.requestURI = requestURI

    log.statusCode = matches[8]
    log.responseSize = matches[9]

    var referrer = matches[10].replace("\"", "")
    if omit != "" and referrer.contains(omit):
      log.referrer = ""
    elif referrer == "-":
      log.referrer = ""
    else:
      if referrer.endsWith("/"):
        referrer = referrer.strip(leading = false, chars = {'/'})
      log.referrer = referrer

    log.userAgent = matches[11..^1].join(" ").replace("\"", "")
    # nginx writes "" for an empty User-Agent header. store it like a missing one,
    # an empty value breaks the insert of the whole batch
    if log.userAgent == "":
      log.userAgent = "-"
    log.nonDefault = ""
  else:
    error(fmt"Could not parse: {logLine}")
    log.nonDefault = logLine

  return log


proc readNewLines*(path: string, offset: var int64, maxBytes = readChunkBytes): seq[string] =
  ## Reads the complete lines added to the file since `offset`, up to `maxBytes`, and moves `offset` forward
  let file = open(path)
  defer: file.close()

  # only allocate what was added, a full chunk for a few new lines wastes memory
  let toRead = min(maxBytes, file.getFileSize() - offset)
  if toRead <= 0:
    return

  file.setFilePos(offset)
  var data = newString(toRead)
  data.setLen(file.readChars(data))

  # leave a half written last line for the next read
  let lastNewline = data.rfind('\n')
  if lastNewline == -1:
    # a line longer than maxBytes never fits in one read, skip it instead of getting stuck
    if data.len == maxBytes:
      offset += maxBytes
    return

  offset += lastNewline + 1
  # cut in place instead of copying the chunk
  data.setLen(lastNewline)
  return data.splitLines()


proc offsetAfterLastInserted*(path: string, lastLog: Log): int64 =
  ## Returns the file offset right after the last line that matches `lastLog`,
  ## the last log saved in the database. Returns 0 when no line matches
  if lastLog.date == "":
    return 0

  let file = open(path)
  defer: file.close()

  var line: string
  while file.readLine(line):
    # parsing every line is slow, most lines are from another IP
    if not line.startsWith(lastLog.remoteIP & " "):
      continue

    let log = parseLogEntry(line, "")
    # keep going to the last match, the same request can repeat in the same second
    if log.date == lastLog.date and
    log.httpMethod == lastLog.httpMethod and
    log.requestURI == lastLog.requestURI:
      result = file.getFilePos()
