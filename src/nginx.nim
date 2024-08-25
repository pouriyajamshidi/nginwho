from os import findExe
from osproc import execCmd
from logging import info, error, warn, fatal

from consts import NGINX_CMD, NGINX_TEST_CMD, NGINX_RELOAD_CMD


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
