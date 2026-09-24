import std/asyncdispatch
from std/strformat import fmt
from std/strutils import parseBool, splitLines, startsWith, split, strip
from db_connector/db_sqlite import DbConn, DbError
from std/os import getFileInfo, FileInfo, FileId, dirExists, fileExists, createDir, parentDir
from std/net import Port
from std/parseopt import CmdLineKind, initOptParser, next
from std/logging import addHandler, newConsoleLogger, info, error, warn, setLogFilter, lvlError

from nginx import Log, isStaticAsset, readChunkBytes, ensureNginxExists, ensureNginxLogExists,
    parseLogEntry, readNewLines, offsetAfterLastInserted
from cloudflare import fetchAndProcessIPCidrs
from nftables import ensureNftExists
from database import getDbConnection, closeDbConnection,
    createTables, insertLogs, migrateV1ToV2, getLastRow
from report import report
from server import serve
from trap import trap
from config import Args, readConfigFile, parsePort, parseInterval, defaultConfigFile,
    defaultDbPath, oldDbPath, nginxLogPath, serveLogPath


proc nimbleVersion(): string =
  ## Reads the version from nginwho.nimble at compile time
  for line in staticRead("../nginwho.nimble").splitLines:
    if line.startsWith("version"):
      return line.split('=')[1].strip.strip(chars = {'"'})

const
  version* = nimbleVersion()
  maxInsertAttempts = 3

addHandler(newConsoleLogger(fmtStr = "[$date -- $time] - $levelname: "))



proc usage(errorCode: int = 0) =
  echo """

  --help, -h              : Show help
  --version, -v           : Display version and quit
  --dbPath                : Path to SQLite database to log reports (default: /var/lib/nginwho/nginwho.db)
  --logPath               : Path to nginx access logs (default: /var/log/nginx/access.log,
                            or /var/log/nginwho/access.log with '--serve')
  --interval              : Refresh interval in seconds (default: 10)
  --omitReferrer          : Omit a specific referrer from being logged (default: none)
  --showRealIps           : Show real IP of visitors by getting Cloudflare CIDRs to include in nginx config.
                            Self-updates every six hours (default: false)
  --blockUntrustedCidrs   : Block untrusted IP addresses using nftables. Only allows Cloudflare CIDRs (default: false)
  --processNginxLogs      : Process nginx logs (default: false)
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
  --v2DbPath              : Path and name of the V2 database (e.g: /var/lib/nginwho/nginwho.db)

  """
  quit(errorCode)


proc validateArgs(args: Args) =
  if not args.processNginxLogs and
  not args.report and
  not args.showRealIPs and
  not args.blockUntrustedCidrs and
  not args.serve and
  not args.trap.enabled and
  not args.migrateV1ToV2Db:
    error("Provided flags say do nothing... Exiting")
    usage(1)


proc getArgs(): Args =
  # Args() and not `var args: Args`, only the constructor fills in the defaults
  var args = Args()

  # the config file comes first so that command line flags can win over it
  var configPath = defaultConfigFile
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
        of "trapPort": args.trap.port = parsePort(p.val)
        of "help", "h": usage()
        of "version", "v":
          echo version
          quit(0)

        of "v1DbPath": args.v1DbPath = p.val
        of "v2DbPath": args.v2DbPath = p.val
        of "migrateV1ToV2Db": args.migrateV1ToV2Db = true

        of "logPath": args.logPath = p.val
        of "dbPath": args.dbPath = p.val
        of "interval": args.interval = parseInterval(p.val)
        of "omitReferrer": args.omitReferrer = p.val
        of "showRealIps": args.showRealIPs = p.val == "" or parseBool(p.val)
        of "blockUntrustedCidrs": args.blockUntrustedCidrs = p.val == "" or parseBool(p.val)
        of "processNginxLogs": args.processNginxLogs = p.val == "" or parseBool(p.val)
        of "serve": args.serve = p.val == "" or parseBool(p.val)
        of "root": args.root = p.val
        of "port": args.port = parsePort(p.val)
      except ValueError as e:
        error(fmt"Bad value '{p.val}' for --{p.key}: {e.msg}")
        usage(1)
    of cmdArgument: discard

  # the server writes its own log, the nginx one belongs to nginx
  if args.logPath == "":
    args.logPath = if args.serve: serveLogPath else: nginxLogPath

  # older versions kept the database in /var/log. keep using it until it is moved
  if args.dbPath == defaultDbPath and not fileExists(defaultDbPath) and fileExists(oldDbPath):
    warn(fmt"Using the old database at {oldDbPath}. Stop nginwho and move it to {defaultDbPath}")
    args.dbPath = oldDbPath

  if args.migrateV1ToV2Db and (args.v1DbPath == "" or args.v2DbPath == ""):
    error("Migration needs '--v1DbPath' and '--v2DbPath' flags")
    usage(1)

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
      logs: seq[Log]
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
      if failedInserts < maxInsertAttempts:
        warn(fmt"Will retry these logs in {args.interval div 1000} seconds")
        offset = previousOffset
      else:
        error(fmt"Dropping {len(logs)} logs after {maxInsertAttempts} failed inserts")
        failedInserts = 0

    # a big log is read in chunks, keep going without waiting until it is caught up
    let moreToRead = failedInserts == 0 and fileInfo.size - previousOffset > readChunkBytes
    await sleepAsync(if moreToRead: 0 else: args.interval)


proc runPreChecks(args: Args) =
  info("Running pre-checks based on provided user arguments")

  if args.serve:
    if not dirExists(args.root):
      error(fmt"Directory to serve not found at: {args.root}")
      quit(1)
    # the server creates the log, nginx is not needed
    if not fileExists(args.logPath):
      createDir(args.logPath.parentDir)
      writeFile(args.logPath, "")
  elif args.processNginxLogs:
    ensureNginxLogExists(args.logPath)

  # only --showRealIps runs nginx, to test and reload its config. reading its log needs no nginx
  if args.showRealIPs:
    ensureNginxExists()

  if args.blockUntrustedCidrs:
    ensureNftExists()


proc main() =
  # parse args first so --help and --version print nothing else
  let args: Args = getArgs()

  if args.migrateV1ToV2Db:
    migrateV1ToV2(args.v1DbPath, args.v2DbPath)
    return

  if args.report:
    # info logs would get mixed with the report output
    setLogFilter(lvlError)
    report(args.dbPath)
    return

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

  if args.showRealIPs or args.blockUntrustedCidrs:
    asyncCheck fetchAndProcessIPCidrs(args.showRealIPs, args.blockUntrustedCidrs)

  runForever()

when isMainModule:
  try:
    main()
  except DbError, IOError, OSError:
    # these end the program when they happen at start, or in an async task
    error(getCurrentExceptionMsg())
    quit(1)
