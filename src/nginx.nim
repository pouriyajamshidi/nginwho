import std/[os, osproc, times]
from consts import NGINX_PROCESS_NAME, NGINX_TEST_CMD, NGINX_RELOAD_CMD, DATE_FORMAT

from logging import addHandler, newConsoleLogger, ConsoleLogger, info, error, warn, fatal


var logger: ConsoleLogger = newConsoleLogger(fmtStr="[$date -- $time] - $levelname: ")


proc ensureNginxExists*() =
  info("Ensuring nginx command exists")

  let result: string = findExe(NGINX_PROCESS_NAME)
  if result == "":
    error("nginx command not found")
    quit(1)


proc testNginxConfig*(): int =
  info("Testing nginx configuration")

  return execCmd(command=NGINX_TEST_CMD)


proc reloadNginx*() =
  let now: string = getTime().format(DATE_FORMAT)

  let result: int = execCmd(command=NGINX_RELOAD_CMD)
  if result != 0:
    error("nginx process reload failed")
  else:
    info("nginx process reloaded successfully")
