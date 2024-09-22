import std/[strutils, strformat, re, asyncdispatch]
from times import parse, Datetime, format
from db_connector/db_sqlite import DbConn


from parseopt import CmdLineKind, initOptParser, next
from logging import addHandler, newConsoleLogger, ConsoleLogger, info, error,
    warn, fatal

import consts
from types import Args, Log, Logs
from nginx import ensureNginxExists, ensureNginxLogExists
from cloudflare import fetchAndProcessIPCidrs
from nftables import acceptOnly, ensureNftExists
from database import getDbConnection, closeDbConnection, writeToDatabase, createTables, insertLog


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
  --omit-referrer         : Omit a specific referrer from being logged (default: none)
  --show-real-ips         : Show real IP of visitors by getting Cloudflare CIDRs to include in nginx config.
                            Self-updates every six hours (default: false)
  --block-untrusted-cidrs : Block untrusted IP addresses using nftables. Only allows Cloudflare CIDRs (default: false)
  --analyze-nginx-logs    : Whether to analyze nginx logs or not. (default: true)

  """
  quit(errorCode)


proc validateArgs(args: Args) =
  if not args.analyzeNginxLogs and
  not args.showRealIPs and
  not args.blockUntrustedCidrs:
    error("Provided flags mean do nothing... Exiting")
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
      analyzeNginxLogs: true
    )

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
      of "logPath": args.logPath = p.val
      of "dbPath": args.dbPath = p.val
      of "interval": args.interval = parseInt(p.val) * 1000 # convert to seconds
      of "omit-referrer": args.omitReferrer = p.val
      of "show-real-ips": args.showRealIPs = parseBool(p.val)
      of "block-untrusted-cidrs": args.blockUntrustedCidrs = parseBool(p.val)
      of "analyze-nginx-logs": args.analyzeNginxLogs = parseBool(p.val)
    of cmdArgument: discard

  validateArgs(args)

  return args

proc convertDateFormat*(nginxDate: string): string =
  let parsedDate: DateTime = parse(nginxDate, "d-MMM-yyyy:HH:mm:ss")

  return parsedDate.format("yyyy-MM-dd HH:mm:ss")

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

    # writeToDatabase(logs, db)
    insertLog(db, logs)

    await sleepAsync args.interval


proc runPreChecks(args: Args) =
  info("Running pre-checks based on provided user arguments")

  if args.analyzeNginxLogs:
    ensureNginxLogExists(args.logPath)
    # TODO: Enable me
    # ensureNginxExists()

  if args.blockUntrustedCidrs:
    ensureNftExists()


proc main() =
  info("Starting nginwho")

  let args: Args = getArgs()

  runPreChecks(args)

  if args.analyzeNginxLogs:
    asyncCheck processAndRecordLogs(args)

  if args.showRealIPs:
    asyncCheck fetchAndProcessIPCidrs(args.blockUntrustedCidrs)

  if args.blockUntrustedCidrs and not args.showRealIPs:
    asyncCheck acceptOnly(NGINX_CIDR_FILE)

  runForever()

when is_main_module:
  main()
