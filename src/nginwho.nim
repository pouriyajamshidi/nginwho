import std/[strutils, os, strformat, re, asyncdispatch]
import db_connector/db_sqlite

from parseopt import CmdLineKind, initOptParser, next
from logging import addHandler, newConsoleLogger, ConsoleLogger, info, error, warn, fatal

import consts
from cloudflare import fetchAndProcessIPCidrs
from nftables import acceptOnly


var logger: ConsoleLogger = newConsoleLogger(fmtStr="[$date -- $time] - $levelname: ")
addHandler(logger)


type Log = object
  remoteIP: string
  remoteUser: string
  authenticatedUser: string
  date: string
  httpMethod: string
  requestURI: string
  statusCode: string
  responseSize: string
  referrer: string
  userAgent: string
  nonStandard: string


type
  Logs = seq[Log]

  Args = tuple[
    logPath: string,
    dbPath: string,
    interval: int,
    omitReferrer: string,
    showRealIPs: bool,
    blockUntrustedCidrs: bool,
    analyzeNginxLogs: bool
  ]


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
  info("Getting user provided logs")

  var args: Args = (
      logPath: NGINX_DEFAULT_LOG_PATH,
      dbPath:NGINWHO_DB_FILE,
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


proc writeToDatabase(logs: var seq[Log], db: DbConn) =
  info("Writing data to database")

  db.exec(sql"""CREATE TABLE IF NOT EXISTS nginwho
                (
                  id                  INTEGER PRIMARY KEY,
                  date                TEXT NOT NULL,
                  remoteIP            TEXT NOT NULL,
                  httpMethod          TEXT NOT NULL,
                  requestURI          TEXT NOT NULL,
                  statusCode          TEXT NOT NULL,
                  responseSize        TEXT NOT NULL,
                  referrer            TEXT NOT NULL,
                  userAgent           TEXT NOT NULL,
                  nonStandard         TEXT,
                  remoteUser          TEXT NOT NULL,
                  authenticatedUser   TEXT NOT NULL
                )"""
  )

  let lastEntryDate: Row = db.getRow(sql"SELECT date FROM nginwho WHERE TRIM(date) <> '' ORDER BY rowid DESC LIMIT 1;")
  var lastEntryDateValue: string

  if lastEntryDate[0] == "":
    info("First time fetcing date from DB")
  else:
    lastEntryDateValue = lastEntryDate[0]

  #TODO: Expand the conditional check (perhaps on user-agent and URL) to 
  # avoid missing entries on busy servers
  if logs[^1].date == lastEntryDateValue:
    info("Rows are already written to DB")
    return

  db.exec(sql"BEGIN")

  for log in logs:
    db.exec(sql"""INSERT INTO nginwho
                  (
                    date,
                    remoteIP,
                    httpMethod,
                    requestURI,
                    statusCode,
                    responseSize,
                    referrer,
                    userAgent,
                    nonStandard,
                    remoteUser,
                    authenticatedUser) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    log.date,
                    log.remoteIP,
                    log.httpMethod,
                    log.requestURI,
                    log.statusCode,
                    log.responseSize,
                    log.referrer,
                    log.userAgent,
                    log.nonStandard,
                    log.remoteUser,
                    log.authenticatedUser
    )

  db.exec(sql"COMMIT")
  

proc parseLogEntry(logLine: string, omit: string): Log =
  info("Parsing log entries")

  var log: Log

  let matches: seq[string] = logLine.split(re"[ ]+")

  if matches.len >= 12:
    log.remoteIP = matches[0].replace("\"", "")
    log.date = matches[3].replace("\"", "").replace("[", "").replace("/", "-")
    log.httpMethod = matches[5].replace("\"", "")
    log.requestURI = matches[6].replace("\"", "")
    log.statusCode = matches[8].replace("\"", "")
    log.responseSize = matches[9].replace("\"", "")

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


proc processLogs(args: Args) {.async.} =
  info("Processing log entries")

  if not fileExists(args.logPath):
    error(fmt"nginx log file not found: {args.logPath}")
    quit(1)

  let db: DbConn = open(args.dbPath, "", "", "")
  defer: db.close()

  while true:
    var logs: Logs

    for line in lines(args.logPath):
      if line.len() == 0:
        await sleepAsync(FIVE_SECONDS)
        continue
      let log = parseLogEntry(line, args.omitReferrer)
      logs.add(log)

    writeToDatabase(logs, db)

    await sleepAsync args.interval


proc main() =
  info("Starting nginwho")

  let args: Args = getArgs()

  if args.analyzeNginxLogs:
    asyncCheck processLogs(args)

  if args.showRealIPs:
    asyncCheck fetchAndProcessIPCidrs(args.blockUntrustedCidrs)
  
  if args.blockUntrustedCidrs and not args.showRealIPs:
    asyncCheck acceptOnly(NGINX_CIDR_FILE)

  runForever()

when is_main_module:
  main()
