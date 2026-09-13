import std/[strutils, strformat, asyncdispatch]
from db_connector/db_sqlite import DbConn
from std/os import getFileInfo, FileInfo, FileId

from parseopt import CmdLineKind, initOptParser, next
from logging import addHandler, newConsoleLogger, ConsoleLogger, info, error,
    warn, fatal

import consts
from types import Args, Log, Logs
from nginx import ensureNginxExists, ensureNginxLogExists, parseLogEntry,
    readNewLines, dropAlreadyInserted
from cloudflare import fetchAndProcessIPCidrs
from nftables import acceptOnly, ensureNftExists
from database import getDbConnection, closeDbConnection,
    createTables, insertLogs, migrateV1ToV2, getLastRow
from report import report

var logger: ConsoleLogger = newConsoleLogger(
    fmtStr = "[$date -- $time] - $levelname: ")
addHandler(logger)



proc usage(errorCode: int = 0) =
  echo """

  --help, -h              : Show help
  --version, -v           : Display version and quit
  --dbPath,               : Path to SQLite database to log reports (default: /var/log/nginwho.db)
  --logPath,              : Path to nginx access logs (default: /var/log/nginx/access.log)
  --interval              : Refresh interval in seconds (default: 10)
  --omitReferrer          : Omit a specific referrer from being logged (default: none)
  --showRealIps           : Show real IP of visitors by getting Cloudflare CIDRs to include in nginx config.
                            Self-updates every six hours (default: false)
  --blockUntrustedCidrs   : Block untrusted IP addresses using nftables. Only allows Cloudflare CIDRs (default: false)
  --processNginxLogs      : Process nginx logs (default: true)
  --report                : Enter report mode and query the database for statistics

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
      report: false,
      migrateV1ToV2Db: false,
      v1DbPath: "",
      v2DbPath: "",
    )

  var p = initOptParser()

  while true:
    p.next()
    case p.kind
    of cmdEnd: break
    of cmdShortOption, cmdLongOption:
      case p.key
      of "report": args.report = true
      of "help", "h": usage()
      of "version", "v":
        echo VERSION
        quit(0)

      of "v1DbPath": args.v1DbPath = p.val
      of "v2DbPath": args.v2DbPath = p.val
      of "migrateV1ToV2Db": args.migrateV1ToV2Db = true

      of "logPath": args.logPath = p.val
      of "dbPath": args.dbPath = p.val
      of "interval": args.interval = parseInt(p.val) * 1000 # convert seconds to milliseconds
      of "omitReferrer": args.omitReferrer = p.val
      of "showRealIps": args.showRealIPs = p.val == "" or parseBool(p.val)
      of "blockUntrustedCidrs": args.blockUntrustedCidrs = p.val == "" or parseBool(p.val)
      of "processNginxLogs": args.processNginxLogs = p.val == "" or parseBool(p.val)
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

    # the log was rotated or truncated, start from the beginning
    if fileInfo.id.file != fileId or fileInfo.size < offset:
      fileId = fileInfo.id.file
      offset = 0

    if fileInfo.size == offset:
      info(fmt"{args.logPath} has no new logs... sleeping")
      await sleepAsync(args.interval)
      continue

    let fromStart = offset == 0
    let previousOffset = offset
    var logs: Logs

    for line in readNewLines(args.logPath, offset):
      if line.len() == 0:
        continue

      let log = parseLogEntry(line, args.omitReferrer)

      # TODO: Decide whether to exclude these or not
      if log.requestURI.endsWith(".woff2") or
      log.requestURI.endsWith(".js") or
      # log.requestURI.endsWith(".xml") or
      log.requestURI.endsWith(".css"):
        continue

      logs.add(log)

    info(fmt"Got {len(logs)} logs to process")

    # only a read from the start of the file can have logs that are already in the database
    if fromStart:
      logs = dropAlreadyInserted(logs, getLastRow(db))

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

    await sleepAsync(args.interval)


proc runPreChecks(args: Args) =
  info("Running pre-checks based on provided user arguments")

  if args.processNginxLogs:
    ensureNginxLogExists(args.logPath)
    ensureNginxExists()

  if args.blockUntrustedCidrs:
    ensureNftExists()


proc main() =
  # parse args first so --help and --version print nothing else
  let args: Args = getArgs()

  info("Starting nginwho")

  if args.report:
    report(args.dbPath)

  runPreChecks(args)

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
