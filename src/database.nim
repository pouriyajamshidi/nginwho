import db_connector/db_sqlite
from std/strformat import fmt
from logging import info, warn, error

from types import Log


proc getDbConnection*(dbPath: string): DbConn =
  try:
    let connection: DbConn = open(dbPath, "", "", "")
    return connection
  except db_sqlite.DbError as e:
    error(fmt"Could not open or connect to database: {e.msg}")
    quit(1)

proc closeDbConnection*(db: DbConn) =
  try:
    db.close()
  except db_sqlite.DbError as e:
    warn(fmt"Could not close database: {e.msg}")

proc createTables*(db: DbConn) =
  info("Creating database tables")

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


proc writeToDatabase*(logs: var seq[Log], db: DbConn) =
  info("Writing data to database")

  let lastEntryDate: Row = db.getRow(sql"SELECT date FROM nginwho WHERE TRIM(date) <> '' ORDER BY rowid DESC LIMIT 1;")
  var lastEntryDateValue: string

  if lastEntryDate[0] == "":
    info("First time fetching date from DB")
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
