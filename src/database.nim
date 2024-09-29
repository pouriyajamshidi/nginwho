import db_connector/db_sqlite
from std/strformat import fmt
from std/os import fileExists
from std/strutils import parseInt, contains
from logging import info, warn, error

from types import Log, Logs
from utils import convertDateFormat

# TODO:
#  1. Implement a hashing mechanism to make sure we do not write duplicates
#     ensure that we account for both standard and nonStandard logs
#  2. create a separate table for `nonStandard`

proc getDbConnection*(dbPath: string): DbConn =
  info(fmt"Opening Database connection to {dbPath}")

  try:
    let connection: DbConn = open(dbPath, "", "", "")
    return connection
  except db_sqlite.DbError as e:
    error(fmt"Could not open or connect to database: {e.msg}")
    quit(1)

proc closeDbConnection*(db: DbConn) =
  info("Closing Database connection")

  try:
    db.close()
  except db_sqlite.DbError as e:
    warn(fmt"Could not close database: {e.msg}")

proc showData() =
  discard """
  SELECT
    nginwho.id,
    date.date,
    remoteIP.remoteIP,
    httpMethod.httpMethod,
    requestURI.requestURI,
    statusCode.statusCode,
    responseSize.responseSize,
    referrer.referrer,
    userAgent.userAgent,
    nonStandard.nonStandard,
    remoteUser.remoteUser,
    authenticatedUser.authenticatedUser
  FROM nginwho
  JOIN date ON nginwho.date_id = date.id
  JOIN remoteIP ON nginwho.remoteIP_id = remoteIP.id
  JOIN httpMethod ON nginwho.httpMethod_id = httpMethod.id
  JOIN requestURI ON nginwho.requestURI_id = requestURI.id
  JOIN statusCode ON nginwho.statusCode_id = statusCode.id
  JOIN responseSize ON nginwho.responseSize_id = responseSize.id
  JOIN referrer ON nginwho.referrer_id = referrer.id
  JOIN userAgent ON nginwho.userAgent_id = userAgent.id
  JOIN nonStandard ON nginwho.nonStandard_id = nonStandard.id
  JOIN remoteUser ON nginwho.remoteUser_id = remoteUser.id
  JOIN authenticatedUser ON nginwho.authenticatedUser_id = authenticatedUser.id
  ORDER BY nginwho.id ASC
  """

proc createTables*(db: DbConn) =
  info("Creating database tables")

  # TODO: Implement indexing:
  # -- Create indexes for better query performance
  # CREATE INDEX idx_logs_timestamp ON logs (timestamp);
  # CREATE INDEX idx_logs_ip_address_id ON logs (ip_address_id);
  # CREATE INDEX idx_logs_request_uri_id ON logs (request_uri_id);
  # CREATE INDEX idx_logs_user_agent_id ON logs (user_agent_id);

  db.exec(sql"BEGIN TRANSACTION")

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
    let insertedRowId = db.insertID(sql(
        fmt"INSERT INTO {table} ({column}, count) VALUES (?, 1)"), value)

    return insertedRowId

  let updatedRowId = parseInt(row[0]).int64
  let newCount = parseInt(row[1]) + 1

  db.exec(sql(fmt"UPDATE {table} SET count = ? WHERE id = ?"), newCount, updatedRowId)

  return updatedRowId

proc insertLog*(db: DbConn, logs: var seq[Log]) =
  info(fmt"Writing {len(logs)} logs to database")

  db.exec(sql"BEGIN TRANSACTION")

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

proc insertLogV1*(logs: var seq[Log], db: DbConn) {.deprecated: "use insertLog instead".} =
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
    info("First time fetching date from DB")
  else:
    lastEntryDateValue = lastEntryDate[0]

  if logs[^1].date == lastEntryDateValue:
    info("Rows are already written to DB")
    return

  db.exec(sql"BEGIN TRANSACTION")

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

proc migrateV1ToV2*(v1DbName, v2DbName: string) =
  info(fmt"Migrating v1 database at '{v1DbName}' to v2 database at '{v2DbName}'")

  if not fileExists(v1DbName):
    error(fmt("V1 database does not exist at {v1DbName}"))
    quit(1)


  let v1Db = getDbConnection(v1DbName)
  let v2Db = getDbConnection(v2DbName)

  defer:
    closeDbConnection(v1Db)
    closeDbConnection(v2Db)

  createTables(v2Db)

  let selectStatement = sql"""
    SELECT date, remoteIP, httpMethod, requestURI, statusCode, responseSize, 
           referrer, userAgent, remoteUser, authenticatedUser
    FROM nginwho
    WHERE date IS NOT NULL AND date != ''
    LIMIT ? OFFSET ?
  """

  const migrationBatchSize = 10_000

  var
    logs: Logs
    batchCount = 0
    offset = 0
    totalProcessedRecords = 0

  while true:
    info(fmt"Processing records in batches of {migrationBatchSize} and offset {offset}")

    let rows = v1Db.getAllRows(selectStatement, migrationBatchSize, offset)
    if rows.len == 0:
      break

    for row in rows:
      let httpMethod = row[2]
      if httpMethod.contains("\\") or httpMethod.contains("x") or
          httpMethod.contains("{"):
        warn(fmt"Skipping due to bad format: {row}")

      let log = Log(
        date: convertDateFormat(row[0]),
        remoteIP: row[1],
        httpMethod: httpMethod,
        requestURI: row[3],
        statusCode: row[4],
        responseSize: parseInt(row[5]),
        referrer: row[6],
        userAgent: row[7],
        remoteUser: row[8],
        authenticatedUser: row[9]
      )

      logs.add(log)

      batchCount += 1
      if batchCount >= migrationBatchSize:
        insertLog(v2Db, logs)

        batchCount = 0
        logs = Logs(@[])

    offset += migrationBatchSize
    totalProcessedRecords += rows.len

  # if there are leftovers, add them
  if batchCount > 0:
    insertLog(v2Db, logs)

  info(fmt"Processed {totalProcessedRecords} records")

  quit(0)
