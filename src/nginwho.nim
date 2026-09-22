import std/asyncdispatch
from std/strformat import fmt
from std/strutils import parseInt, parseBool
from db_connector/db_sqlite import DbConn
from std/os import getFileInfo, FileInfo, FileId, dirExists, fileExists

from std/parseopt import CmdLineKind, initOptParser, next
from std/logging import addHandler, newConsoleLogger, ConsoleLogger, info, error,
    warn, fatal, setLogFilter, lvlError

from consts import VERSION, NGINWHO_DB_FILE, NGINWHO_CONFIG_FILE, MAX_INSERT_ATTEMPTS,
    READ_CHUNK_BYTES, TEN_SECONDS, SERVER_DEFAULT_ROOT, SERVER_DEFAULT_PORT, NGINX_CIDR_FILE,
    NGINX_DEFAULT_LOG_PATH, TRAP_DEFAULT_PORT, TRAP_MAX_CONNECTIONS, TRAP_MAX_SECONDS,
    TRAP_DRIP_MIN_MS, TRAP_DRIP_MAX_MS, TRAP_BOMB_AFTER
from types import Args, Log, Logs, TrapConfig
from utils import isStaticAsset
from nginx import ensureNginxExists, ensureNginxLogExists, parseLogEntry,
    readNewLines, offsetAfterLastInserted
from cloudflare import fetchAndProcessIPCidrs
from nftables import acceptOnly, ensureNftExists
from database import getDbConnection, closeDbConnection,
    createTables, insertLogs, migrateV1ToV2, getLastRow
from report import report
from server import serve
from trap import trap
from config import readConfigFile
from std/net import Port

var logger: ConsoleLogger = newConsoleLogger(
    fmtStr = "[$date -- $time] - $levelname: ")
addHandler(logger)



proc usage(errorCode: int = 0) =
  echo """

  --help, -h              : Show help
  --version, -v           : Display version and quit
  --dbPath                : Path to SQLite database to log reports (default: /var/log/nginwho.db)
  --logPath               : Path to nginx access logs (default: /var/log/nginx/access.log)
  --interval              : Refresh interval in seconds (default: 10)
  --omitReferrer          : Omit a specific referrer from being logged (default: none)
  --showRealIps           : Show real IP of visitors by getting Cloudflare CIDRs to include in nginx config.
                            Self-updates every six hours (default: false)
  --blockUntrustedCidrs   : Block untrusted IP addresses using nftables. Only allows Cloudflare CIDRs (default: false)
  --processNginxLogs      : Process nginx logs (default: true)
  --serve                 : Serve static files and write nginx style logs to '--logPath' (default: false)
  --root                  : Directory to serve files from (default: /var/www/html)
  --port                  : Port to serve on, IPv4 and IPv6 (default: 80)
  --report                : Enter report mode and query the database for statistics
  --config                : Path to the config file (default: /etc/nginwho/nginwho.conf).
                            Command line flags win over it
  --trap                  : Play with bots that probe for files we do not have.
                            nginx forwards its 403s and 404s to us (default: false)
  --trapPort              : Port the trap listens on, on localhost only (default: 7777)

  --migrateV1ToV2Db       : Migrate V1 database to V2 and exit (default: false).
                            Use with '--v1DbPath' and '--v2DbPath' flags
  --v1DbPath              : Path and name of the V1 database (e.g: /var/log/nginwho_v1.db)
  --v2DbPath              : Path and name of the V2 database (e.g: /var/log/nginwho.db)

  """
  quit(errorCode)


proc validateArgs(args: Args) =
  if not args.processNginxLogs and
  not args.showRealIPs and
  not args.blockUntrustedCidrs and
  not args.serve and
  not args.trap.enabled and
  not args.migrateV1ToV2Db:
    error("Provided flags say do nothing... Exiting")
    usage(1)


proc getArgs(): Args =
  var args: Args = (
      logPath: NGINX_DEFAULT_LOG_PATH,
      dbPath: NGINWHO_DB_FILE,
      interval: TEN_SECONDS,
      omitReferrer: "",
      showRealIPs: false,
      blockUntrustedCidrs: false,
      processNginxLogs: true,
      serve: false,
      root: SERVER_DEFAULT_ROOT,
      port: SERVER_DEFAULT_PORT,
      report: false,
      migrateV1ToV2Db: false,
      v1DbPath: "",
      v2DbPath: "",
      trap: TrapConfig(
        enabled: false,
        port: TRAP_DEFAULT_PORT,
        maxConnections: TRAP_MAX_CONNECTIONS,
        maxSeconds: TRAP_MAX_SECONDS,
        dripMinMs: TRAP_DRIP_MIN_MS,
        dripMaxMs: TRAP_DRIP_MAX_MS,
        bombs: true,
        bombAfter: TRAP_BOMB_AFTER,
      ),
    )

  # the config file comes first so that command line flags can win over it
  var configPath = NGINWHO_CONFIG_FILE
  var configParser = initOptParser()
  while true:
    configParser.next()
    case configParser.kind
    of cmdEnd: break
    of cmdShortOption, cmdLongOption:
      if configParser.key == "config": configPath = configParser.val
    of cmdArgument: discard
  readConfigFile(configPath, args)

  var p = initOptParser()

  while true:
    p.next()
    case p.kind
    of cmdEnd: break
    of cmdShortOption, cmdLongOption:
      try:
        case p.key
        of "report": args.report = true
        of "config": discard # already read
        of "trap": args.trap.enabled = p.val == "" or parseBool(p.val)
        of "trapPort":
          let port = parseInt(p.val)
          if port < 1 or port > 65535:
            raise newException(ValueError, "must be between 1 and 65535")
          args.trap.port = port
        of "help", "h": usage()
        of "version", "v":
          echo VERSION
          quit(0)

        of "v1DbPath": args.v1DbPath = p.val
        of "v2DbPath": args.v2DbPath = p.val
        of "migrateV1ToV2Db": args.migrateV1ToV2Db = true

        of "logPath": args.logPath = p.val
        of "dbPath": args.dbPath = p.val
        of "interval":
          let seconds = parseInt(p.val)
          if seconds < 1:
            raise newException(ValueError, "must be at least 1")
          args.interval = seconds * 1000 # convert seconds to milliseconds
        of "omitReferrer": args.omitReferrer = p.val
        of "showRealIps": args.showRealIPs = p.val == "" or parseBool(p.val)
        of "blockUntrustedCidrs": args.blockUntrustedCidrs = p.val == "" or parseBool(p.val)
        of "processNginxLogs": args.processNginxLogs = p.val == "" or parseBool(p.val)
        of "serve": args.serve = p.val == "" or parseBool(p.val)
        of "root": args.root = p.val
        of "port":
          let port = parseInt(p.val)
          if port < 1 or port > 65535:
            raise newException(ValueError, "must be between 1 and 65535")
          args.port = port
      except ValueError as e:
        error(fmt"Bad value '{p.val}' for --{p.key}: {e.msg}")
        usage(1)
    of cmdArgument: discard

  if args.migrateV1ToV2Db:
    if args.v1DbPath == "" or args.v2DbPath == "":
      error("Migration needs '--v1DbPath' and '--v2DbPath' flags")
      usage(1)
    migrateV1ToV2(args.v1DbPath, args.v2DbPath)

  validateArgs(args)

  return args


proc processAndRecordLogs(args: Args) {.async.} =
  info("Processing log entries")

  let db: DbConn = getDbConnection(args.dbPath)
  defer: closeDbConnection(db)

  createTables(db)

  var
    offset: int64 = 0
    fileId: FileId
    failedInserts = 0

  while true:
    var fileInfo: FileInfo
    try:
      fileInfo = getFileInfo(args.logPath)
    except OSError as e:
      warn(fmt"Could not read {args.logPath}: {e.msg}")
      await sleepAsync(args.interval)
      continue

    var
      logs: Logs
      lines: seq[string]
      previousOffset: int64

    try:
      # first run, rotated or truncated log. skip the lines saved before a restart,
      # a new log has none of them so this starts from the beginning
      if fileInfo.id.file != fileId or fileInfo.size < offset:
        fileId = fileInfo.id.file
        offset = offsetAfterLastInserted(args.logPath, getLastRow(db))

      if fileInfo.size == offset:
        info(fmt"{args.logPath} has no new logs... sleeping")
        await sleepAsync(args.interval)
        continue

      previousOffset = offset
      lines = readNewLines(args.logPath, offset)
    except IOError as e:
      warn(fmt"Could not read {args.logPath}: {e.msg}")
      await sleepAsync(args.interval)
      continue

    for line in lines:
      if line.len() == 0:
        continue

      let log = parseLogEntry(line, args.omitReferrer)

      if isStaticAsset(log.requestURI):
        continue

      logs.add(log)

    info(fmt"Got {len(logs)} logs to process")

    if len(logs) == 0:
      info("Database is up to date with the latest logs")
    elif insertLogs(db, logs):
      failedInserts = 0
    else:
      failedInserts += 1
      # read the same lines again next time, but don't get stuck on logs that can never be saved
      if failedInserts < MAX_INSERT_ATTEMPTS:
        warn(fmt"Will retry these logs in {args.interval div 1000} seconds")
        offset = previousOffset
      else:
        error(fmt"Dropping {len(logs)} logs after {MAX_INSERT_ATTEMPTS} failed inserts")
        failedInserts = 0

    # a big log is read in chunks, keep going without waiting until it is caught up
    let moreToRead = failedInserts == 0 and fileInfo.size - previousOffset > READ_CHUNK_BYTES
    await sleepAsync(if moreToRead: 0 else: args.interval)


proc runPreChecks(args: Args) =
  info("Running pre-checks based on provided user arguments")

  if args.serve:
    if not dirExists(args.root):
      error(fmt"Directory to serve not found at: {args.root}")
      quit(1)
    # the server creates the log, nginx is not needed
    if not fileExists(args.logPath):
      writeFile(args.logPath, "")
  elif args.processNginxLogs:
    ensureNginxLogExists(args.logPath)
    ensureNginxExists()

  if args.blockUntrustedCidrs:
    ensureNftExists()


proc main() =
  # parse args first so --help and --version print nothing else
  let args: Args = getArgs()

  if args.report:
    # info logs would get mixed with the report output
    setLogFilter(lvlError)
    report(args.dbPath)

  info("Starting nginwho")

  runPreChecks(args)

  if args.serve:
    asyncCheck serve(args.root, args.logPath, Port(args.port))

  if args.trap.enabled:
    asyncCheck trap(args.trap, args.dbPath)

  if args.processNginxLogs:
    asyncCheck processAndRecordLogs(args)

  if args.showRealIPs:
    warn("Do not forget to add `include /etc/nginx/nginwho;` in your nginx config file")
    asyncCheck fetchAndProcessIPCidrs(args.blockUntrustedCidrs)

  if args.blockUntrustedCidrs and not args.showRealIPs:
    acceptOnly(NGINX_CIDR_FILE)

  # blocking CIDRs from the nginx file alone runs once and has nothing to wait for
  if hasPendingOperations():
    runForever()

when is_main_module:
  main()
