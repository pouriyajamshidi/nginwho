import db_connector/db_sqlite
from std/strformat import fmt
from strutils import parseInt
from logging import info, warn, error

from types import Log

# TODO: Implement a hashing mechanism to make sure we do not write duplicates
# ensure that we account for both standard and nonStandard logs

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

  # TODO: Implement indexing:
  # -- Create indexes for better query performance
  # CREATE INDEX idx_logs_timestamp ON logs (timestamp);
  # CREATE INDEX idx_logs_ip_address_id ON logs (ip_address_id);
  # CREATE INDEX idx_logs_request_uri_id ON logs (request_uri_id);
  # CREATE INDEX idx_logs_user_agent_id ON logs (user_agent_id);

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

proc insertOrUpdateColumn(db: DbConn, table, column, value: string): int64 =
  let row = db.getRow(sql(fmt"SELECT id, count FROM {table} WHERE {column} = ?"), value)

  if row[0] == "":
    info(fmt"Inserting value {value} into column {column} in table {table}")

    let insertedRowId = db.insertID(sql(
        fmt"INSERT INTO {table} ({column}, count) VALUES (?, 1)"), value)

    return insertedRowId

  info(fmt"Updating value {value} into column {column} in table {table}")

  let updatedRowId = parseInt(row[0]).int64

  let newCount = parseInt(row[1]) + 1
  db.exec(sql(fmt"UPDATE {table} SET count = ? WHERE id = ?"), newCount, updatedRowId)

  return updatedRowId

proc insertLog*(db: DbConn, logs: var seq[Log]) =
  info("Writing data to database")

  db.exec(sql"BEGIN")

  let insertQuery = """
    INSERT INTO nginwho 
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
     ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  """

  let preparedStmt = db.prepare(insertQuery)
  defer: preparedStmt.finalize()

  for log in logs:
    let
      dateId = insertOrUpdateColumn(db, "date", "date", log.date)
      remoteIPId = insertOrUpdateColumn(db, "remoteIP", "remoteIP", log.remoteIP)
      httpMethodId = insertOrUpdateColumn(db, "httpMethod", "httpMethod",
          log.httpMethod)
      requestURIId = insertOrUpdateColumn(db, "requestURI", "requestURI",
          log.requestURI)
      statusCodeId = insertOrUpdateColumn(db, "statusCode", "statusCode",
          log.statusCode)
      responseSizeId = insertOrUpdateColumn(db, "responseSize", "responseSize",
          $log.responseSize)
      referrerId = insertOrUpdateColumn(db, "referrer", "referrer", log.referrer)
      userAgentId = insertOrUpdateColumn(db, "userAgent", "userAgent", log.userAgent)
      nonStandardId = insertOrUpdateColumn(db, "nonStandard", "nonStandard",
          log.nonStandard)
      remoteUserId = insertOrUpdateColumn(db, "remoteUser", "remoteUser",
          log.remoteUser)
      authenticatedUserId = insertOrUpdateColumn(db, "authenticatedUser",
          "authenticatedUser", log.authenticatedUser)

    # db.exec(sql"""INSERT INTO nginwho
    #         (
    #           date_id,
    #           remoteIP_id,
    #           httpMethod_id,
    #           requestURI_id,
    #           statusCode_id,
    #           responseSize_id,
    #           referrer_id,
    #           userAgent_id,
    #           nonStandard_id,
    #           remoteUser_id,
    #           authenticatedUser_id
    #         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
    #         dateId,
    #         remoteIPId,
    #         httpMethodId,
    #         requestURIId,
    #         statusCodeId,
    #         responseSizeId,
    #         referrerId,
    #         userAgentId,
    #         nonStandardId,
    #         remoteUserId,
    #         authenticatedUserId
    # )
    db.exec(
      preparedStmt,
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
