## Reads /etc/nginwho/nginwho.conf. Command line flags win over it

from std/parsecfg import loadConfig, Config, getSectionValue
from std/strutils import parseInt, parseBool
from std/strformat import fmt
from std/os import fileExists
from std/logging import info, error

from types import Args


proc getString(config: Config, section, key: string, fallback: string): string =
  let value = config.getSectionValue(section, key)
  return if value == "": fallback else: value


proc getInt(config: Config, section, key: string, fallback: int): int =
  let value = config.getSectionValue(section, key)
  if value == "":
    return fallback
  try:
    return parseInt(value)
  except ValueError:
    error(fmt"Bad number '{value}' for {key} in [{section}], using {fallback}")
    return fallback


proc getBool(config: Config, section, key: string, fallback: bool): bool =
  let value = config.getSectionValue(section, key)
  if value == "":
    return fallback
  try:
    return parseBool(value)
  except ValueError:
    error(fmt"Bad true/false value '{value}' for {key} in [{section}], using {fallback}")
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
  args.interval = config.getInt("nginx", "interval", args.interval div 1000) * 1000
  args.omitReferrer = config.getString("nginx", "omit_referrer", args.omitReferrer)
  args.showRealIPs = config.getBool("nginx", "show_real_ips", args.showRealIPs)
  args.blockUntrustedCidrs = config.getBool("nginx", "block_untrusted_cidrs", args.blockUntrustedCidrs)
  args.processNginxLogs = config.getBool("nginx", "process_logs", args.processNginxLogs)

  args.serve = config.getBool("server", "enabled", args.serve)
  args.root = config.getString("server", "root", args.root)
  args.port = config.getInt("server", "port", args.port)

  args.trap.enabled = config.getBool("trap", "enabled", args.trap.enabled)
  args.trap.port = config.getInt("trap", "port", args.trap.port)
  args.trap.maxConnections = config.getInt("trap", "max_connections", args.trap.maxConnections)
  args.trap.maxSeconds = config.getInt("trap", "max_seconds", args.trap.maxSeconds)
  args.trap.dripMinMs = config.getInt("trap", "drip_min_ms", args.trap.dripMinMs)
  args.trap.dripMaxMs = config.getInt("trap", "drip_max_ms", args.trap.dripMaxMs)
  args.trap.bombs = config.getBool("trap", "bombs", args.trap.bombs)
  args.trap.bombAfter = config.getInt("trap", "bomb_after", args.trap.bombAfter)
