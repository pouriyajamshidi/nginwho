## Reads /etc/nginwho/nginwho.conf. Command line flags win over it

from std/parsecfg import loadConfig, Config, getSectionValue
from std/strutils import parseInt, parseBool, parseEnum, toLowerAscii
from std/strformat import fmt
from std/os import fileExists
from std/tables import hasKey, `[]`, pairs
from std/options import some, none
from std/logging import info, error

from trap import TrapConfig, Agent, Tactic
from cdn import Cdn


const
  defaultConfigFile* = "/etc/nginwho/nginwho.conf"
  defaultDbPath* = "/var/lib/nginwho/nginwho.db"
  oldDbPath* = "/var/log/nginwho.db" # where versions before 2.5.0 kept it
  nginxLogPath* = "/var/log/nginx/access.log"
  serveLogPath* = "/var/log/nginwho/access.log"


type
  Args* = object
    ## Settings from the config file and the command line. The values here are the defaults
    logPath*: string        # empty means nginxLogPath, or serveLogPath with --serve
    dbPath*: string = defaultDbPath
    interval*: int = 10_000 # milliseconds
    omitReferrer*: string
    cdn*: Cdn = Cloudflare
    showRealIPs*: bool
    blockUntrustedCidrs*: bool
    processNginxLogs*: bool
    serve*: bool
    root*: string = "/var/www/html"
    port*: int = 80
    report*: bool
    trap*: TrapConfig



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


proc parseCdn*(value: string): Cdn =
  try:
    return parseEnum[Cdn](value.toLowerAscii())
  except ValueError:
    raise newException(ValueError, "must be cloudflare or fastly")


proc parseTactic*(value: string): Tactic =
  try:
    return parseEnum[Tactic](value.toLowerAscii())
  except ValueError:
    raise newException(ValueError, "must be drip, endless, maze, login or bomb")


proc atLeast(min: int): proc (value: string): int =
  ## A parser for whole numbers that can't go below `min`
  return proc (value: string): int =
    result = parseInt(value)
    if result < min:
      raise newException(ValueError, fmt"must be at least {min}")


proc getString(config: Config, section, key: string, fallback: string): string =
  let value = config.getSectionValue(section, key)
  return if value == "": fallback else: value


proc get[T](config: Config, section, key: string, fallback: T, parse: proc (
    value: string): T): T =
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
  ## Fills `args` from the config file. A missing file is fine, the defaults stand.
  ## Raises IOError when the file can't be read
  if not fileExists(path):
    return

  info(fmt"Reading config file {path}")

  var config: Config
  try:
    config = loadConfig(path)
  except CatchableError as e:
    raise newException(IOError, fmt"Could not read {path}: {e.msg}")

  args.dbPath = config.getString("database", "path", args.dbPath)

  args.logPath = config.getString("nginx", "log_path", args.logPath)
  args.interval = config.get("nginx", "interval", args.interval, parseInterval)
  args.omitReferrer = config.getString("nginx", "omit_referrer",
      args.omitReferrer)
  args.cdn = config.get("nginx", "cdn", args.cdn, parseCdn)
  args.showRealIPs = config.get("nginx", "show_real_ips", args.showRealIPs, parseBool)
  args.blockUntrustedCidrs = config.get("nginx", "block_untrusted_cidrs",
      args.blockUntrustedCidrs, parseBool)
  args.processNginxLogs = config.get("nginx", "process_logs",
      args.processNginxLogs, parseBool)

  args.serve = config.get("server", "enabled", args.serve, parseBool)
  args.root = config.getString("server", "root", args.root)
  args.port = config.get("server", "port", args.port, parsePort)

  args.trap.enabled = config.get("trap", "enabled", args.trap.enabled, parseBool)
  args.trap.port = config.get("trap", "port", args.trap.port, parsePort)
  args.trap.maxConnections = config.get("trap", "max_connections",
      args.trap.maxConnections, atLeast(1))
  args.trap.maxSeconds = config.get("trap", "max_seconds", args.trap.maxSeconds,
      atLeast(1))
  args.trap.dripMinMs = config.get("trap", "drip_min_ms", args.trap.dripMinMs,
      atLeast(0))
  args.trap.dripMaxMs = config.get("trap", "drip_max_ms", args.trap.dripMaxMs,
      atLeast(0))
  args.trap.bombs = config.get("trap", "bombs", args.trap.bombs, parseBool)
  args.trap.bombAfter = config.get("trap", "bomb_after", args.trap.bombAfter,
      atLeast(0))

  # the pause between drips is picked from min to max, which can't be an empty range
  if args.trap.dripMinMs > args.trap.dripMaxMs:
    error(fmt"drip_min_ms ({args.trap.dripMinMs}) is above drip_max_ms ({args.trap.dripMaxMs}) " &
        "in [trap]. Keeping the defaults for both")
    args.trap.dripMinMs = TrapConfig().dripMinMs
    args.trap.dripMaxMs = TrapConfig().dripMaxMs

  # user agents to always trap. a name on its own gets the default: what any bot
  # gets for that path, and a drip for a normal page
  if config.hasKey("trap.agents"):
    for name, value in config["trap.agents"].pairs:
      var agent: Agent = (name.toLowerAscii(), none(Tactic))
      if value != "":
        try:
          agent.tactic = some(parseTactic(value))
        except ValueError as e:
          error(fmt"Bad value '{value}' for {name} in [trap.agents]: {e.msg}. Keeping the default")
      args.trap.agents.add(agent)
