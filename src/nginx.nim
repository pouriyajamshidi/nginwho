import std/[asyncdispatch, times]
from json import JsonNode, getStr, items
from os import findExe, fileExists
from osproc import execCmd
from strformat import fmt
from logging import info, error, warn, fatal

from types import Cidrs
from consts import NGINX_CMD, NGINX_TEST_CMD, NGINX_RELOAD_CMD, ONE_MINUTE,
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


proc reloadNginx() =
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


proc reloadNginxAt*(hour: int = 3, minute: int = 0) {.async.} =
  info(fmt"Preparing to soft-reload nginx at {hour}:{minute}")

  while true:
    let now: DateTime = getTime().local()
    if now.hour == hour and now.minute == minute:
      reloadNginx()

    await sleepAsync(ONE_MINUTE)

