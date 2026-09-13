from std/times import getTime, format
from std/strutils import splitWhitespace, replace, endsWith, strip, contains, join, rfind, splitLines
from json import JsonNode, getStr, items
from os import findExe, fileExists
from osproc import execCmd
from strformat import fmt
from logging import info, error, warn, fatal

from types import Cidrs, Log, Logs
from utils import convertDateFormat
from consts import NGINX_CMD, NGINX_TEST_CMD, NGINX_RELOAD_CMD,
    DATE_FORMAT, NGINX_SET_REAL_IP_FROM, NGINX_REAL_IP_HEADER, NGINX_CF_REAL_IP_HEADER


proc populateReverseProxyFile*(filePath: string, cidrs: Cidrs): bool =
  info(fmt"Populating CIDRs file in {filePath}")

  let now: string = getTime().format(DATE_FORMAT)

  if cidrs.etagChanged:
    try:
      let file: File = open(filePath, fmWrite)
      defer: file.close()

      file.write("# Cloudflare ranges\n")
      file.write("# Last update: ", now, "\n")
      file.write("# Last etag: ", cidrs.etag, "\n\n")
      file.write("# IPv4 CIDRs\n")

      for cidr in cidrs.ipv4:
        file.write(NGINX_SET_REAL_IP_FROM, " ", cidr.getStr(), ";", "\n")

      file.write("\n# IPv6 CIDRs\n")

      for cidr in cidrs.ipv6:
        file.write(NGINX_SET_REAL_IP_FROM, " ", cidr.getStr(), ";", "\n")

      file.write("\n\n", NGINX_REAL_IP_HEADER, " ", NGINX_CF_REAL_IP_HEADER, "\n")
      return true
    except:
      error(fmt"Could not open {filePath}")
      return false

  info("CIDR tag has not changed")
  return false


proc ensureNginxLogExists*(logPath: string) =
  info("Ensuring nginx log exists")

  if not fileExists(logPath):
    error(fmt"nginx log file not found at: {logPath}")
    quit(1)

proc ensureNginxExists*() =
  info("Ensuring nginx command exists")

  let result: string = findExe(NGINX_CMD)
  if result == "":
    error("nginx command not found")
    quit(1)


proc testNginxConfig(): int =
  info("Testing nginx configuration")

  return execCmd(command = NGINX_TEST_CMD)


proc reloadNginx*() =
  info("Attempting to soft-reload nginx")

  let testResult: int = testNginxConfig()
  if testResult != 0:
    error("nginx configuration test failed... Aborting reload")
    return


  let result: int = execCmd(command = NGINX_RELOAD_CMD)
  if result != 0:
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
    except Exception as e:
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


proc readNewLines*(path: string, offset: var int64): seq[string] =
  ## Reads the complete lines added to the file since `offset` and moves `offset` forward
  let file = open(path)
  defer: file.close()

  file.setFilePos(offset)
  let data = file.readAll()

  # leave a half written last line for the next read
  let lastNewline = data.rfind('\n')
  if lastNewline == -1:
    return

  offset += lastNewline + 1
  return data[0 ..< lastNewline].splitLines()


proc dropAlreadyInserted*(logs: Logs, lastLog: Log): Logs =
  ## Drops the logs up to and including `lastLog`, the last log saved in the database
  if lastLog.date == "":
    return logs

  # search from the end so repeated requests in the same second are not inserted again
  for i in countdown(logs.high, 0):
    if logs[i].date == lastLog.date and
    logs[i].remoteIP == lastLog.remoteIP and
    logs[i].httpMethod == lastLog.httpMethod and
    logs[i].requestURI == lastLog.requestURI:
      return logs[i+1..^1]

  return logs
