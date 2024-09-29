import std/[strutils, strformat, re, asyncdispatch]
from db_connector/db_sqlite import DbConn

from parseopt import CmdLineKind, initOptParser, next
from logging import addHandler, newConsoleLogger, ConsoleLogger, info, error,
    warn, fatal

import consts
from types import Args, Log, Logs
from nginx import ensureNginxExists, ensureNginxLogExists
from cloudflare import fetchAndProcessIPCidrs
from nftables import acceptOnly, ensureNftExists
from database import getDbConnection, closeDbConnection,
    createTables, insertLog, migrateV1ToV2
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
      migrateV1ToV2Db: false,
      v1DbPath: "",
      v2DbPath: "",
    )

  var
    v1DbPath: string
    v2DbPath: string

  var p = initOptParser()

  while true:
    p.next()
    case p.kind
    of cmdEnd: break
    of cmdShortOption, cmdLongOption:
      case p.key
      of "help", "h": usage()
      of "version", "v":
        echo VERSION
        quit(0)

      of "v1DbPath": v1DbPath = p.val
      of "v2DbPath": v2DbPath = p.val
      of "migrateV1ToV2":
        if v1DbPath == "" or v2DbPath == "":
          error("Migration needs '--v1DbPath' and '--v2DbPath' flags")
          usage(1)
        migrateV1ToV2("nginwho_v1.db", "nginwho_v2.db")

      of "logPath": args.logPath = p.val
      of "dbPath": args.dbPath = p.val
      of "interval": args.interval = parseInt(p.val) * 1000 # convert to seconds
      of "omitReferrer": args.omitReferrer = p.val
      of "showRealIps": args.showRealIPs = parseBool(p.val)
      of "blockUntrustedCidrs": args.blockUntrustedCidrs = parseBool(p.val)
      of "processNginxLogs": args.processNginxLogs = parseBool(p.val)
    of cmdArgument: discard

  validateArgs(args)

  return args

proc parseLogEntry(logLine: string, omit: string): Log =
  var log: Log

  let matches: seq[string] = logLine.split(re"[ ]+")

  if matches.len >= 12:
    log.remoteIP = matches[0]

    log.date = convertDateFormat(matches[3].replace("\"", "").replace("[",
        "").replace("/", "-"))

    log.httpMethod = matches[5].replace("\"", "")
    log.requestURI = matches[6].replace("\"", "")
    log.statusCode = matches[8]
    log.responseSize = parseInt(matches[9])

    let referrer = matches[10].replace("\"", "")
    if omit != "" and referrer.contains(omit):
      log.referrer = ""
    elif referrer == "-":
      log.referrer = ""
    else:
      log.referrer = referrer

    log.userAgent = matches[11..^1].join(" ").replace("\"", "")
    log.nonStandard = ""
  else:
    error(fmt"Could not parse: {logLine}")
    log.nonStandard = logLine

  return log


proc processAndRecordLogs(args: Args) {.async.} =
  info("Processing log entries")

  let db: DbConn = getDbConnection(args.dbPath)
  defer: closeDbConnection(db)

  createTables(db)

  while true:
    var logs: Logs

    for line in lines(args.logPath):
      if line.len() == 0:
        await sleepAsync(FIVE_SECONDS)
        continue
      let log = parseLogEntry(line, args.omitReferrer)
      logs.add(log)

    insertLog(db, logs)

    await sleepAsync args.interval


proc runPreChecks(args: Args) =
  info("Running pre-checks based on provided user arguments")

  if args.processNginxLogs:
    ensureNginxLogExists(args.logPath)
    # TODO: Enable me
    # ensureNginxExists()

  if args.blockUntrustedCidrs:
    ensureNftExists()


proc main() =
  info("Starting nginwho")

  let args: Args = getArgs()

  runPreChecks(args)

  if args.processNginxLogs:
    asyncCheck processAndRecordLogs(args)

  if args.showRealIPs:
    asyncCheck fetchAndProcessIPCidrs(args.blockUntrustedCidrs)

  if args.blockUntrustedCidrs and not args.showRealIPs:
    asyncCheck acceptOnly(NGINX_CIDR_FILE)

  runForever()

when is_main_module:
  main()
