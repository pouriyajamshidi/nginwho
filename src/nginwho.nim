import std/[strutils, strformat, asyncdispatch]
from db_connector/db_sqlite import DbConn
from std/os import getFileInfo, FileInfo, FileId

from parseopt import CmdLineKind, initOptParser, next
from logging import addHandler, newConsoleLogger, ConsoleLogger, info, error,
    warn, fatal

import consts
from types import Args, Log, Logs
from nginx import ensureNginxExists, ensureNginxLogExists
from cloudflare import fetchAndProcessIPCidrs
from nftables import acceptOnly, ensureNftExists
from database import getDbConnection, closeDbConnection,
    createTables, insertLogs, migrateV1ToV2, getLastRow
from report import report
from utils import convertDateFormat

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
  info("Getting user provided arguments")

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
      of "interval": args.interval = parseInt(p.val) * 1000 # convert to seconds
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


proc parseLogEntry(logLine: string, omit: string): Log =
  var log: Log

  let matches: seq[string] = logLine.splitWhitespace()

  if matches.len >= 12:
    log.remoteIP = matches[0]

    # Nginx 1.24.0 has decided to write weird and incorrect dates
    try:
      log.date = convertDateFormat(matches[3].replace("\"", "").replace("[",
          "").replace("/", "-"))
    except Exception as e:
      error(fmt"Failed parsing log date: {e.msg}")
      log.nonDefault = logLine
      return log

    log.httpMethod = matches[5].replace("\"", "")

    var requestURI = matches[6].replace("\"", "")
    if requestURI.endsWith("/") and len(requestURI) > 1:
      requestURI = requestURI.strip(leading = false, chars = {'/'})
    log.requestURI = requestURI

    log.statusCode = matches[8]
    log.responseSize = matches[9]

    var referrer = matches[10].replace("\"", "")
    if omit != "" and referrer.contains(omit):
      log.referrer = ""
    elif referrer == "-":
      log.referrer = ""
    else:
      if referrer.endsWith("/"):
        referrer = referrer.strip(leading = false, chars = {'/'})
      log.referrer = referrer

    log.userAgent = matches[11..^1].join(" ").replace("\"", "")
    log.nonDefault = ""
  else:
    error(fmt"Could not parse: {logLine}")
    log.nonDefault = logLine

  return log


proc readNewLines(path: string, offset: var int64): seq[string] =
  ## Reads the complete lines added to the file since `offset` and moves `offset` forward
  let file = open(path)
  defer: file.close()

  file.setFilePos(offset)
  let data = file.readAll()

  # leave a half written last line for the next read
  let lastNewline = data.rfind('\n')
  if lastNewline == -1:
    return

  offset += lastNewline + 1
  return data[0 ..< lastNewline].splitLines()


proc processAndRecordLogs(args: Args) {.async.} =
  info("Processing log entries")

  let db: DbConn = getDbConnection(args.dbPath)
  defer: closeDbConnection(db)

  createTables(db)

  var
    offset: int64 = 0
    fileId: FileId

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
      let lastLog = getLastRow(db)

      # search from the end so repeated requests in the same second are not inserted again
      if lastLog.date != "":
        for i in countdown(logs.high, 0):
          if logs[i].date == lastLog.date and
          logs[i].remoteIP == lastLog.remoteIP and
          logs[i].httpMethod == lastLog.httpMethod and
          logs[i].requestURI == lastLog.requestURI:
            logs = logs[i+1..^1]
            break

    if len(logs) > 0:
      insertLogs(db, logs)
    else:
      info("Database is up to date with the latest logs")

    await sleepAsync(args.interval)


proc runPreChecks(args: Args) =
  info("Running pre-checks based on provided user arguments")

  if args.processNginxLogs:
    ensureNginxLogExists(args.logPath)
    ensureNginxExists()

  if args.blockUntrustedCidrs:
    ensureNftExists()


proc main() =
  info("Starting nginwho")

  let args: Args = getArgs()

  if args.report:
    report(args.dbPath)

  runPreChecks(args)

  if args.processNginxLogs:
    asyncCheck processAndRecordLogs(args)

  if args.showRealIPs:
    warn("Do not forget to add `include /etc/nginx/nginwho;` in your nginx config file")
    asyncCheck fetchAndProcessIPCidrs(args.blockUntrustedCidrs)

  if args.blockUntrustedCidrs and not args.showRealIPs:
    asyncCheck acceptOnly(NGINX_CIDR_FILE)

  runForever()

when is_main_module:
  main()
