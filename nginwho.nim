import std/[strutils, os, strformat, re]
import db_connector/db_sqlite
from parseopt import CmdLineKind, initOptParser, next


const
    NGINX_DEFAULT_LOG_PATH = "/var/log/nginx/access.log"
    DB_FILE = "/var/log/nginwho.db"
    TEN_SECONDS = 10000
    VERSION = "0.3.0"


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
    nginxLogPath: string,
    dbPath: string,
    interval: int
  ]
  Logs = seq[Log]


proc usage() =
  echo """

  --help, -h        : show help
  --version         : Display version and quit
  --dbPath,         : Path to SQLite database to log reports (default: /var/log/nginwho.db)
  --nginxLogPath,   : Path to nginx access logs (default: /var/log/nginx/access.log)
  --interval        : Refresh interval in seconds (default: 10)

  """
  quit()


proc getArgs(): Flags =
  var flags: Flags = (nginxLogPath: NGINX_DEFAULT_LOG_PATH, dbPath:DB_FILE, interval: TEN_SECONDS)

  var p = initOptParser()

  while true:
    p.next()
    case p.kind
    of cmdEnd: break
    of cmdShortOption, cmdLongOption:
      case p.key
      of "help", "h": usage()
      of "version":
        echo VERSION
        quit(0)
      of "nginxLogPath": flags.nginxLogPath = p.val
      of "dbPath": flags.dbPath = p.val
      of "interval": flags.interval = parseInt(p.val)
    of cmdArgument: discard

  return flags


proc writeToDatabase(logs: var seq[Log], databaseName: string) =
  let db = open(databaseName, "", "", "")

  db.exec(sql"""CREATE TABLE IF NOT EXISTS nginwho
                (
                  id                  INTEGER PRIMARY KEY,
                  remoteIP            TEXT NOT NULL,
                  remoteUser          TEXT NOT NULL,
                  authenticatedUser   TEXT NOT NULL,
                  date                TEXT NOT NULL,
                  httpMethod          TEXT NOT NULL,
                  requestURI          TEXT NOT NULL,
                  statusCode          TEXT NOT NULL,
                  responseSize        TEXT NOT NULL,
                  referrer            TEXT NOT NULL,
                  userAgent           TEXT NOT NULL,
                  nonStandard         TEXT
                )"""
    )

  let lastEntryDate = db.getRow(sql"SELECT date FROM nginwho WHERE TRIM(date) <> '' ORDER BY rowid DESC LIMIT 1;")
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
                    remoteUser,
                    authenticatedUser,
                    nonStandard) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
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
  db.close()
  

proc parseLogEntry(logLine: string): Log =
  var log: Log

  let matches = logLine.split(re"[ ]+")

  if matches.len >= 12:
    log.remoteIP = matches[0].replace("\"", "")
    log.date = matches[3].replace("\"", "").replace("[", "").replace("/", "-")
    log.httpMethod = matches[5].replace("\"", "")
    log.requestURI = matches[6].replace("\"", "")
    log.statusCode = matches[8].replace("\"", "")
    log.responseSize = matches[9].replace("\"", "")

    var referrer = matches[10].replace("\"", "")
    #TODO: Try `contains` instead
    # if referrer.contains("thegraynode.io"):
    if referrer.startsWith("https://thegraynode.io") or referrer.startsWith("https://www.thegraynode.io"):
      referrer = ""
    elif referrer == "-":
      referrer = ""
    else:
      log.referrer = referrer
      
    log.userAgent = matches[11..^1].join(" ").replace("\"", "")
    log.nonStandard = ""
  else:
    echo fmt"Could not parse: {logLine}"
    log.nonStandard = logLine

  return log


proc main() = 
  let args = getArgs()

  while true:
    var logs: Logs

    for line in lines(args.nginxLogPath):
      let log = parseLogEntry(line)
      logs.add(log)

    writeToDatabase(logs, args.dbPath)
    # logs = newSeq[Log]()
    sleep args.interval
  

when is_main_module:
  main()