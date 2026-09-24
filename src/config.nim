## Reads /etc/nginwho/nginwho.conf. Command line flags win over it

from std/parsecfg import loadConfig, Config, getSectionValue
from std/strutils import parseInt, parseBool
from std/strformat import fmt
from std/os import fileExists
from std/logging import info, error

from trap import TrapConfig


type
  Args* = object
    ## Settings from the config file and the command line. The values here are the defaults
    logPath*: string = "/var/log/nginx/access.log"
    dbPath*: string = "/var/log/nginwho.db"
    interval*: int = 10_000 # milliseconds
    omitReferrer*: string
    showRealIPs*: bool
    blockUntrustedCidrs*: bool
    processNginxLogs*: bool = true
    serve*: bool
    root*: string = "/var/www/html"
    port*: int = 80
    report*: bool
    migrateV1ToV2Db*: bool
    v1DbPath*: string
    v2DbPath*: string
    trap*: TrapConfig


const defaultConfigFile* = "/etc/nginwho/nginwho.conf"


proc parsePort*(value: string): int =
  result = parseInt(value)
  if result < 1 or result > 65535:
    raise newException(ValueError, "must be between 1 and 65535")


proc parseInterval*(value: string): int =
  ## Seconds in, milliseconds out
  let seconds = parseInt(value)
  if seconds < 1:
    raise newException(ValueError, "must be at least 1")
  return seconds * 1000


proc getString(config: Config, section, key: string, fallback: string): string =
  let value = config.getSectionValue(section, key)
  return if value == "": fallback else: value


proc get[T](config: Config, section, key: string, fallback: T, parse: proc (value: string): T): T =
  ## Parses the value with `parse`. A missing or bad value keeps `fallback`
  let value = config.getSectionValue(section, key)
  if value == "":
    return fallback
  try:
    return parse(value)
  except ValueError as e:
    error(fmt"Bad value '{value}' for {key} in [{section}]: {e.msg}. Keeping the default")
    return fallback


proc readConfigFile*(path: string, args: var Args) =
  ## Fills `args` from the config file. A missing file is fine, the defaults stand
  if not fileExists(path):
    return

  info(fmt"Reading config file {path}")

  var config: Config
  try:
    config = loadConfig(path)
  except CatchableError as e:
    error(fmt"Could not read {path}: {e.msg}")
    quit(1)

  args.dbPath = config.getString("database", "path", args.dbPath)

  args.logPath = config.getString("nginx", "log_path", args.logPath)
  args.interval = config.get("nginx", "interval", args.interval, parseInterval)
  args.omitReferrer = config.getString("nginx", "omit_referrer", args.omitReferrer)
  args.showRealIPs = config.get("nginx", "show_real_ips", args.showRealIPs, parseBool)
  args.blockUntrustedCidrs = config.get("nginx", "block_untrusted_cidrs", args.blockUntrustedCidrs, parseBool)
  args.processNginxLogs = config.get("nginx", "process_logs", args.processNginxLogs, parseBool)

  args.serve = config.get("server", "enabled", args.serve, parseBool)
  args.root = config.getString("server", "root", args.root)
  args.port = config.get("server", "port", args.port, parsePort)

  args.trap.enabled = config.get("trap", "enabled", args.trap.enabled, parseBool)
  args.trap.port = config.get("trap", "port", args.trap.port, parsePort)
  args.trap.maxConnections = config.get("trap", "max_connections", args.trap.maxConnections, parseInt)
  args.trap.maxSeconds = config.get("trap", "max_seconds", args.trap.maxSeconds, parseInt)
  args.trap.dripMinMs = config.get("trap", "drip_min_ms", args.trap.dripMinMs, parseInt)
  args.trap.dripMaxMs = config.get("trap", "drip_max_ms", args.trap.dripMaxMs, parseInt)
  args.trap.bombs = config.get("trap", "bombs", args.trap.bombs, parseBool)
  args.trap.bombAfter = config.get("trap", "bomb_after", args.trap.bombAfter, parseInt)
