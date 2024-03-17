import std/[os, osproc, strformat, times]


proc ensureNginxExists() =
  let now: string = getTime().format("yyyy-MM-dd HH:mm:ss")

  let result: string = findExe(NGINX_PROCESS_NAME)
  if result == "":
    quit(fmt"{now} - nginx command not found", 1)


proc testNginxConfig(): int =
  let now: string = getTime().format("yyyy-MM-dd HH:mm:ss")
  echo fmt"{now} - Testing nginx configuration"

  return execCmd(command=NGINX_TEST_CMD)


proc reloadNginx() =
  let now: string = getTime().format("yyyy-MM-dd HH:mm:ss")

  let result: int = execCmd(command=NGINX_RELOAD_CMD)
  if result != 0:
    echo fmt"{now} - nginx process reload failed"
  else:
    echo fmt"{now} - nginx process reloaded successfully"

