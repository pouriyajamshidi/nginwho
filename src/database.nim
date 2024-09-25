import db_connector/db_sqlite
from std/strformat import fmt
from strutils import parseInt
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

  db.exec(sql"BEGIN")

  db.exec(sql"""CREATE TABLE IF NOT EXISTS date
          (
            id INTEGER PRIMARY KEY,
            date TEXT UNIQUE NOT NULL,
            count INTEGER NOT NULL DEFAULT 1
          )"""
  )

  db.exec(sql"""CREATE TABLE IF NOT EXISTS remoteIP
          (
            id INTEGER PRIMARY KEY,
            remoteIP TEXT UNIQUE NOT NULL,
            count INTEGER NOT NULL DEFAULT 1
          )"""
  )

  db.exec(sql"""CREATE TABLE IF NOT EXISTS httpMethod
          (
            id INTEGER PRIMARY KEY,
            httpMethod TEXT UNIQUE NOT NULL,
            count INTEGER NOT NULL DEFAULT 1
          )"""
  )

  db.exec(sql"""CREATE TABLE IF NOT EXISTS requestURI
          (
            id INTEGER PRIMARY KEY,
            requestURI TEXT UNIQUE NOT NULL,
            count INTEGER NOT NULL DEFAULT 1
          )"""
  )

  db.exec(sql"""CREATE TABLE IF NOT EXISTS statusCode
          (
            id INTEGER PRIMARY KEY,
            statusCode TEXT UNIQUE NOT NULL,
            count INTEGER NOT NULL DEFAULT 1
          )"""
  )

  db.exec(sql"""CREATE TABLE IF NOT EXISTS responseSize
          (
            id INTEGER PRIMARY KEY,
            responseSize TEXT UNIQUE NOT NULL,
            count INTEGER NOT NULL DEFAULT 1
          )"""
  )

  db.exec(sql"""CREATE TABLE IF NOT EXISTS referrer
          (
            id INTEGER PRIMARY KEY,
            referrer TEXT UNIQUE NOT NULL,
            count INTEGER NOT NULL DEFAULT 1
          )"""
  )

  db.exec(sql"""CREATE TABLE IF NOT EXISTS userAgent
          (
            id INTEGER PRIMARY KEY,
            userAgent TEXT UNIQUE NOT NULL,
            count INTEGER NOT NULL DEFAULT 1
          )"""
  )

  # TODO: separate this into its own table
  db.exec(sql"""CREATE TABLE IF NOT EXISTS nonStandard
          (
            id INTEGER PRIMARY KEY,
            nonStandard TEXT UNIQUE,
            count INTEGER NOT NULL DEFAULT 1
          )"""
  )

  db.exec(sql"""CREATE TABLE IF NOT EXISTS remoteUser
          (
            id INTEGER PRIMARY KEY,
            remoteUser TEXT UNIQUE,
            count INTEGER NOT NULL DEFAULT 1
          )"""
  )

  db.exec(sql"""CREATE TABLE IF NOT EXISTS authenticatedUser
          (
            id INTEGER PRIMARY KEY,
            authenticatedUser TEXT UNIQUE,
            count INTEGER NOT NULL DEFAULT 1
          )"""
  )

  db.exec(sql"""CREATE TABLE IF NOT EXISTS nginwho
          (
            id INTEGER PRIMARY KEY,
            date_id INTEGER NOT NULL,
            remoteIP_id INTEGER NOT NULL,
            httpMethod_id INTEGER NOT NULL,
            requestURI_id INTEGER NOT NULL,
            statusCode_id INTEGER NOT NULL,
            responseSize_id INTEGER NOT NULL,
            referrer_id INTEGER NOT NULL,
            userAgent_id INTEGER NOT NULL,
            nonStandard_id INTEGER,
            remoteUser_id INTEGER,
            authenticatedUser_id INTEGER,
            FOREIGN KEY (date_id) REFERENCES date(id),
            FOREIGN KEY (remoteIP_id) REFERENCES remoteIP(id),
            FOREIGN KEY (httpMethod_id) REFERENCES httpMethod(id),
            FOREIGN KEY (requestURI_id) REFERENCES requestURI(id),
            FOREIGN KEY (statusCode_id) REFERENCES statusCode(id),
            FOREIGN KEY (responseSize_id) REFERENCES responseSize(id),
            FOREIGN KEY (referrer_id) REFERENCES referrer(id),
            FOREIGN KEY (userAgent_id) REFERENCES userAgent(id),
            FOREIGN KEY (nonStandard_id) REFERENCES nonStandard(id),
            FOREIGN KEY (remoteUser_id) REFERENCES remoteUser(id),
            FOREIGN KEY (authenticatedUser_id) REFERENCES authenticatedUser(id)
          )"""
  )

  db.exec(sql"COMMIT")

  info("Created database tables")

proc getOrInsertId(db: DbConn, table, column, value: string): int64 =
  let row = db.getRow(sql("SELECT id, count FROM ? WHERE ? = ?"), table, column, value)

  if row[0].len == 0:
    # db.exec(sql("INSERT INTO ? (?, count) VALUES (?, 1)"), table, column, value)
    # let insertedRow = db.getRow(sql("SELECT id FROM ? WHERE ? = ?"),
    #     table, column, value)
    # let rowId = parseInt(insertedRow[0]).int64
    return 0

  let rowId = parseInt(row[0]).int64
  let newCount = parseInt(row[1]) + 1
  db.exec(sql("UPDATE ? SET count = ? WHERE id = ?"), table, newCount, rowId)

  return rowId

proc insertLog*(db: DbConn, logs: var seq[Log]) =
  info("Writing data to database")

  db.exec(sql"BEGIN")

  for log in logs:

    let
      dateId = getOrInsertId(db, "date", "date", log.date)
      remoteIPId = getOrInsertId(db, "remoteIP", "remoteIP", log.remoteIP)
      httpMethodId = getOrInsertId(db, "httpMethod", "httpMethod",
          log.httpMethod)
      requestURIId = getOrInsertId(db, "requestURI", "requestURI",
          log.requestURI)
      statusCodeId = getOrInsertId(db, "statusCode", "statusCode",
          log.statusCode)
      responseSizeId = getOrInsertId(db, "responseSize", "responseSize",
          $log.responseSize)
      referrerId = getOrInsertId(db, "referrer", "referrer", log.referrer)
      userAgentId = getOrInsertId(db, "userAgent", "userAgent", log.userAgent)
      nonStandardId = getOrInsertId(db, "nonStandard", "nonStandard",
          log.nonStandard)
      remoteUserId = getOrInsertId(db, "remoteUser", "remoteUser",
          log.remoteUser)
      authenticatedUserId = getOrInsertId(db, "authenticatedUser", "user",
          log.authenticatedUser)

    db.exec(sql"""INSERT INTO nginwho 
            (
              date_id,
              remoteIP_id,
              httpMethod_id,
              requestURI_id,
              statusCode_id,
              responseSize_id,
              referrer_id,
              userAgent_id,
              nonStandard_id,
              remoteUser_id,
              authenticatedUser_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            dateId,
            remoteIPId,
            httpMethodId,
            requestURIId,
            statusCodeId,
            responseSizeId,
            referrerId,
            userAgentId,
            nonStandardId,
            remoteUserId,
            authenticatedUserId
    )

  db.exec(sql"COMMIT")

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
