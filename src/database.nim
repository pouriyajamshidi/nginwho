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

  db.exec(sql"""CREATE TABLE IF NOT EXISTS remoteIP
          (
            id INTEGER PRIMARY KEY,
            ip TEXT UNIQUE NOT NULL,
            count INTEGER NOT NULL DEFAULT 1
          )"""
  )

  db.exec(sql"""CREATE TABLE IF NOT EXISTS httpMethod
          (
            id INTEGER PRIMARY KEY,
            method TEXT UNIQUE NOT NULL,
            count INTEGER NOT NULL DEFAULT 1
          )"""
  )

  db.exec(sql"""CREATE TABLE IF NOT EXISTS requestURI
          (
            id INTEGER PRIMARY KEY,
            uri TEXT UNIQUE NOT NULL,
            count INTEGER NOT NULL DEFAULT 1
          )"""
  )

  db.exec(sql"""CREATE TABLE IF NOT EXISTS statusCode
          (
            id INTEGER PRIMARY KEY,
            code TEXT UNIQUE NOT NULL,
            count INTEGER NOT NULL DEFAULT 1
          )"""
  )

  db.exec(sql"""CREATE TABLE IF NOT EXISTS referrer
          (
            id INTEGER PRIMARY KEY,
            ref TEXT UNIQUE NOT NULL,
            count INTEGER NOT NULL DEFAULT 1
          )"""
  )

  db.exec(sql"""CREATE TABLE IF NOT EXISTS userAgent
          (
            id INTEGER PRIMARY KEY,
            agent TEXT UNIQUE NOT NULL,
            count INTEGER NOT NULL DEFAULT 1
          )"""
  )

  db.exec(sql"""CREATE TABLE IF NOT EXISTS remoteUser
          (
            id INTEGER PRIMARY KEY,
            user TEXT UNIQUE NOT NULL,
            count INTEGER NOT NULL DEFAULT 1
          )"""
  )

  db.exec(sql"""CREATE TABLE IF NOT EXISTS authenticatedUser
          (
            id INTEGER PRIMARY KEY,
            user TEXT UNIQUE NOT NULL,
            count INTEGER NOT NULL DEFAULT 1
          )"""
  )

  db.exec(sql"""CREATE TABLE IF NOT EXISTS nginwho
          (
            id INTEGER PRIMARY KEY,
            date TEXT NOT NULL,
            remoteIP_id INTEGER NOT NULL,
            httpMethod_id INTEGER NOT NULL,
            requestURI_id INTEGER NOT NULL,
            statusCode_id INTEGER NOT NULL,
            responseSize INTEGER NOT NULL,
            referrer_id INTEGER NOT NULL,
            userAgent_id INTEGER NOT NULL,
            nonStandard TEXT,
            remoteUser_id INTEGER NOT NULL,
            authenticatedUser_id INTEGER NOT NULL,
            FOREIGN KEY (remoteIP_id) REFERENCES remoteIP(id),
            FOREIGN KEY (httpMethod_id) REFERENCES httpMethod(id),
            FOREIGN KEY (requestURI_id) REFERENCES requestURI(id),
            FOREIGN KEY (statusCode_id) REFERENCES statusCode(id),
            FOREIGN KEY (referrer_id) REFERENCES referrer(id),
            FOREIGN KEY (userAgent_id) REFERENCES userAgent(id),
            FOREIGN KEY (remoteUser_id) REFERENCES remoteUser(id),
            FOREIGN KEY (authenticatedUser_id) REFERENCES authenticatedUser(id)
          )"""
  )

  db.exec(sql"COMMIT")

  info("Created database tables")

proc getOrInsertId(db: DbConn, table, column, value: string): int64 =
  let row = db.getRow(sql("SELECT id, count FROM ? WHERE ? = ?"), table, column, value)

  if row[0].len == 0:
    db.exec(sql("INSERT INTO ? (?, count) VALUES (?, 1)"), table, column, value)
    let insertedRow = db.getRow(sql("SELECT id, count FROM ? WHERE ? = ?"), table, column, value)
    let rowId = parseInt(insertedRow[0]).int64
    return rowId

  let rowId = parseInt(row[0]).int64
  let newCount = parseInt(row[1]) + 1
  db.exec(sql("UPDATE ? SET count = ? WHERE id = ?"), table, newCount, rowId)

  return rowId

proc insertLog*(db: DbConn, logs: var seq[Log]) =
  info("Writing data to database")

  db.exec(sql"BEGIN")

  for log in logs:

    let
      remoteIPId = getOrInsertId(db, "remoteIP", "ip", log.remoteIP)
      httpMethodId = getOrInsertId(db, "httpMethod", "method", log.httpMethod)
      requestURIId = getOrInsertId(db, "requestURI", "uri", log.requestURI)
      statusCodeId = getOrInsertId(db, "statusCode", "code", log.statusCode)
      referrerId = getOrInsertId(db, "referrer", "ref", log.referrer)
      userAgentId = getOrInsertId(db, "userAgent", "agent", log.userAgent)
      remoteUserId = getOrInsertId(db, "remoteUser", "user", log.remoteUser)
      authenticatedUserId = getOrInsertId(db, "authenticatedUser", "user",
          log.authenticatedUser)

    db.exec(sql"""INSERT INTO nginwho 
            (
              date,
              remoteIP_id,
              httpMethod_id,
              requestURI_id,
              statusCode_id,
              responseSize,
              referrer_id,
              userAgent_id,
              nonStandard,
              remoteUser_id,
              authenticatedUser_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            log.date,
            remoteIPId,
            httpMethodId,
            requestURIId,
            statusCodeId,
            log.responseSize,
            referrerId,
            userAgentId,
            log.nonStandard,
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
