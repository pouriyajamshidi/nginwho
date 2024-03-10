import std/[strutils, os, strformat, re]
import db_connector/db_sqlite
from parseopt import CmdLineKind, initOptParser, next


const
    NGINX_DEFAULT_LOG_PATH = "/var/log/nginx/access.log"
    DB_FILE = "/var/log/nginwho.db"
    TEN_SECONDS = 10000
    VERSION = "0.5.0"


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
  Flags = tuple[
    logPath: string,
    dbPath: string,
    interval: int,
    omitReferrer: string
  ]
  Logs = seq[Log]


proc usage() =
  echo """

  --help, -h         : show help
  --version, -v      : Display version and quit
  --dbPath,          : Path to SQLite database to log reports (default: /var/log/nginwho.db)
  --logPath,         : Path to nginx access logs (default: /var/log/nginx/access.log)
  --interval         : Refresh interval in seconds (default: 10)
  --omit-referrer    : omit a specific referrer from being logged

  """
  quit()


proc getArgs(): Flags =
  var flags: Flags = (
      logPath: NGINX_DEFAULT_LOG_PATH,
      dbPath:DB_FILE,
      interval: TEN_SECONDS,
      omitReferrer: ""
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
      of "logPath": flags.logPath = p.val
      of "dbPath": flags.dbPath = p.val
      of "interval": flags.interval = parseInt(p.val)
      of "omit-referrer": flags.omitReferrer = p.val
    of cmdArgument: discard

  if flags.dbPath == "": flags.dbPath = DB_FILE
  if flags.logPath == "": flags.logPath = NGINX_DEFAULT_LOG_PATH
  if flags.interval == 0: flags.interval = TEN_SECONDS

  return flags


proc writeToDatabase(logs: var seq[Log], db: DbConn) =
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
    echo "First time fetcing date from DB"
  else:
    lastEntryDateValue = lastEntryDate[0]

  #TODO: Expand the conditional check (perhaps on user-agent and URL) to 
  # avoid missing entries on busy servers
  if logs[^1].date == lastEntryDateValue:
    echo "Rows are already written to DB"
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
    echo fmt"Could not parse: {logLine}"
    log.nonStandard = logLine

  return log


proc main() = 
  let args: Flags = getArgs()

  if not fileExists(args.logPath):
    echo fmt"File not found: {args.logPath}"
    quit(1)

  let db: DbConn = open(args.dbPath, "", "", "")
  defer: db.close()

  while true:
    var logs: Logs

    for line in lines(args.logPath):
      let log = parseLogEntry(line, args.omitReferrer)
      logs.add(log)

    writeToDatabase(logs, db)
    sleep args.interval
  

when is_main_module:
  main()