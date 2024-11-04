import db_connector/db_sqlite
from std/tables import initTable, mgetOrPut, pairs
from std/strformat import fmt
from std/os import fileExists
from std/strutils import parseInt, contains, split, endsWith, formatFloat, ffDecimal
from std/times import format, epochTime
from logging import info, warn, error

from types import Log, Logs
from utils import convertDateFormat


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
    quit(1)


proc showData*() =
  discard """
  SELECT
    nginwho.id,
    date.date,
    remote_ips.remote_ip,
    http_methods.http_method,
    request_uris.request_uri,
    status_codes.status_code,
    response_sizes.response_size,
    referrers.referrer,
    user_agents.user_agent,
    non_defaults.non_default,
    remote_users.remote_user,
    authenticated_users.authenticated_user
  FROM nginwho
  JOIN date ON nginwho.date_id = date.id
  JOIN remote_ip ON nginwho.remote_ip_id = remote_ip.id
  JOIN http_method ON nginwho.httpMethod_id = http_method.id
  JOIN request_uri ON nginwho.requestURI_id = request_uri.id
  JOIN status_code ON nginwho.statusCode_id = status_code.id
  JOIN response_size ON nginwho.responseSize_id = response_size.id
  JOIN referrer ON nginwho.referrer_id = referrer.id
  JOIN user_agent ON nginwho.userAgent_id = user_agent.id
  JOIN nondefault ON nginwho.nondefault_id = nondefault.id
  JOIN remote_user ON nginwho.remoteUser_id = remote_user.id
  JOIN authenticated_user ON nginwho.authenticated_user_id = authenticated_user.id
  ORDER BY nginwho.id ASC
  LIMIT 10
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

  let columns = [
    "date",
    "remote_ip",
    "http_method",
    "request_uri",
    "status_code",
    "response_size",
    "referrer",
    "user_agent",
    "non_default",
    "remote_user",
    "authenticated_user"
  ]

  for column in columns:
    db.exec(sql(fmt"""CREATE TABLE IF NOT EXISTS {column}s
        (
          id INTEGER PRIMARY KEY,
          {column} TEXT UNIQUE NOT NULL,
          count INTEGER NOT NULL DEFAULT 1
        )"""
      )
    )

  db.exec(sql"""CREATE TABLE IF NOT EXISTS nginwho
    (
      id INTEGER PRIMARY KEY,
      date_id INTEGER NOT NULL,
      remote_ip_id INTEGER NOT NULL,
      http_method_id INTEGER NOT NULL,
      request_uri_id INTEGER NOT NULL,
      status_code_id INTEGER NOT NULL,
      response_size_id INTEGER NOT NULL,
      referrer_id INTEGER,
      user_agent_id INTEGER NOT NULL,
      remote_user_id INTEGER,
      authenticated_user_id INTEGER,
      FOREIGN KEY (date_id) REFERENCES dates(id),
      FOREIGN KEY (remote_ip_id) REFERENCES remote_ips(id),
      FOREIGN KEY (http_method_id) REFERENCES http_methods(id),
      FOREIGN KEY (request_uri_id) REFERENCES request_uris(id),
      FOREIGN KEY (status_code_id) REFERENCES status_codes(id),
      FOREIGN KEY (response_size_id) REFERENCES response_sizes(id),
      FOREIGN KEY (referrer_id) REFERENCES referrers(id),
      FOREIGN KEY (user_agent_id) REFERENCES user_agents(id),
      FOREIGN KEY (remote_user_id) REFERENCES remote_users(id),
      FOREIGN KEY (authenticated_user_id) REFERENCES authenticated_users(id)
    )"""
  )

  db.exec(sql"COMMIT")


proc normalizeNginwhoTable(db: DbConn, logs: seq[Log]) =
  info("Populating the nginwho table")

  let defaultQuery = sql"""
    INSERT INTO nginwho (
      date_id,
      remote_ip_id,
      http_method_id,
      request_uri_id,
      status_code_id,
      response_size_id,
      referrer_id,
      user_agent_id,
      remote_user_id,
      authenticated_user_id
    )
    SELECT
      (SELECT id FROM dates WHERE date = ?),
      (SELECT id FROM remote_ips WHERE remote_ip = ?),
      (SELECT id FROM http_methods WHERE http_method = ?),
      (SELECT id FROM request_uris WHERE request_uri = ?),
      (SELECT id FROM status_codes WHERE status_code = ?),
      (SELECT id FROM response_sizes WHERE response_size = ?),
      (SELECT id FROM referrers WHERE referrer = ?),
      (SELECT id FROM user_agents WHERE user_agent = ?),
      (SELECT id FROM remote_users WHERE remote_user = ?),
      (SELECT id FROM authenticated_users WHERE authenticated_user = ?)
  """

  for log in logs:
    if log.nonDefault != "":
      continue

    db.exec(defaultQuery,
      log.date,
      log.remoteIP,
      log.httpMethod,
      log.requestURI,
      log.statusCode,
      log.responseSize,
      log.referrer,
      log.userAgent,
      log.remoteUser,
      log.authenticatedUser
    )


proc upsert(db: DbConn, table, column: string, values: seq[string]) =
  info(fmt"Processing {table} table")

  if len(values) < 1:
    info(fmt"No values to insert in {table} table")
    return

  let insertQuery = fmt"""
    INSERT INTO {table} ({column}, count)
    VALUES (?, ?)
    ON CONFLICT ({column})
    DO UPDATE SET
      count = count + excluded.count
  """

  var valueCounts = initTable[string, int]()
  for value in values:
    valueCounts.mgetOrPut(value, 0).inc

  for value, count in valueCounts.pairs:
    db.exec(sql(insertQuery), value, count)

  # NOTE: Left for potential future rewrite
  # let preparedStmt = db.prepare(insertQuery)
  # defer: preparedStmt.finalize()

  # for value, count in valueCounts.pairs:
  #   echo(fmt"Binding {value} to {count}")
  #   preparedStmt.bindParam(1, value)
  #   preparedStmt.bindParam(2, count)

  # db.exec(preparedStmt)


proc rowExists(db: DbConn, log: Log): bool =
  info("Checking record existence in database")

  let selectStatement = sql"""
    SELECT 
      d.date,
      r.remote_ip,
      u.request_uri
    FROM nginwho n
    JOIN dates d ON n.date_id = d.id
    JOIN remote_ips r ON n.remote_ip_id = r.id
    JOIN request_uris u ON n.request_uri_id = u.id
    ORDER BY n.id DESC
    LIMIT 1
  """

  let lastRow: Row = db.getRow(selectStatement)

  if len(lastRow) == 0:
    return false

  let
    date = lastRow[0]
    remoteIP = lastRow[1]
    requestURI = lastRow[2]

  if log.date == date and
    log.remoteIP == remoteIP and
    log.requestURI == requestURI:
    return true

  return false


proc insertLogs*(db: DbConn, logs: seq[Log], migrate_mode = false) =
  let logsLen = len(logs)
  if logsLen < 1:
    warn("No logs received")
    return

  if not migrate_mode:
    if rowExists(db, logs[^1]):
      info("Database is up to date with the latest logs")
      return

  info(fmt"Inserting {logsLen} logs to database")

  var
    dates: seq[string]
    remoteIPs: seq[string]
    httpMethods: seq[string]
    requestURIs: seq[string]
    statusCodes: seq[string]
    responseSizes: seq[string]
    referrers: seq[string]
    userAgents: seq[string]
    nonDefaults: seq[string]
    remoteUsers: seq[string]
    authenticatedUsers: seq[string]

  for log in logs:
    if len(log.date) > 0: dates.add(log.date)
    if len(log.remoteIP) > 0: remoteIPs.add(log.remoteIP)
    if len(log.httpMethod) > 0: httpMethods.add(log.httpMethod)
    if len(log.requestURI) > 0: requestURIs.add(log.requestURI)
    if len(log.statusCode) > 0: statusCodes.add(log.statusCode)
    if len(log.responseSize) > 0: responseSizes.add(log.responseSize)
    if len(log.referrer) > 0: referrers.add(log.referrer)
    if len(log.userAgent) > 0: userAgents.add(log.userAgent)
    if len(log.nonDefault) > 0: nonDefaults.add(log.nonDefault)
    if len(log.remoteUser) > 0: remoteUsers.add(log.remoteUser)
    if len(log.authenticatedUser) > 0: authenticatedUsers.add(
        log.authenticatedUser)

  db.exec(sql"BEGIN TRANSACTION")

  upsert(db, "dates", "date", dates)
  upsert(db, "remote_ips", "remote_ip", remoteIPs)
  upsert(db, "http_methods", "http_method", httpMethods)
  upsert(db, "request_uris", "request_uri", requestURIs)
  upsert(db, "status_codes", "status_code", statusCodes)
  upsert(db, "response_sizes", "response_size", responseSizes)
  upsert(db, "referrers", "referrer", referrers)
  upsert(db, "user_agents", "user_agent", userAgents)
  upsert(db, "non_defaults", "non_default", nonDefaults)
  upsert(db, "remote_users", "remote_user", remoteUsers)
  upsert(db, "authenticated_users", "authenticated_user", authenticatedUsers)

  normalizeNginwhoTable(db, logs)

  db.exec(sql"COMMIT")


proc insertLogV1(db: DbConn, logs: var seq[
    Log]) {.deprecated: "use insertLogs instead".} =
  info("Writing data to database")

  db.exec(sql"""CREATE TABLE IF NOT EXISTS nginwho
          (
            id                  INTEGER PRIMARY KEY,
            date                TEXT NOT NULL,
            remoteIP            TEXT NOT NULL,
            httpMethod          TEXT NOT NULL,
            requesnonDefault   TEXT NOT NULL,
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
              nonDefault,
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
              log.nonDefault,
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

  var totalRecords: string

  try:
    totalRecords = v1db.getRow(sql"SELECT COUNT(*) from nginwho")[0]
    info(fmt"{v1DbName} contains {totalRecords} records")
  except DbError as e:
    error(fmt"Could not count rows in {v1DbName}: {e.msg}")
    let recoveryCommand = fmt"sqlite3 {v1DbName} '.recover' | sqlite3 {v1DbName.split('.')[0]}_recovered.db"
    info(fmt"Retry after recovering your DB with: {recoveryCommand}")
    quit(1)

  createTables(v2Db)

  let selectStatement = sql"""
    SELECT date, remoteIP, httpMethod, requestURI, statusCode, responseSize,
           referrer, userAgent, remoteUser, authenticatedUser
    FROM nginwho
    WHERE date IS NOT NULL AND date != ''
    LIMIT ? OFFSET ?
  """

  const migrationBatchSize = 100_000

  var
    logs: Logs
    batchCount = 0
    offset = 0
    totalRecordsToProcess = parseInt(totalRecords)

  while totalRecordsToProcess > 0:
    info(fmt"🔥 Processing records from offset {offset} in batches of {migrationBatchSize}")

    var rows: seq[Row]

    try:
      rows = v1Db.getAllRows(selectStatement, migrationBatchSize, offset)
      if len(rows) == 0:
        break
    except DbError as e:
      error(fmt"Could not get rows with limit of {migrationBatchSize} from offset {offset}: {e.msg}")
      break

    for row in rows:
      var httpMethod = row[2]
      if httpMethod.contains("\\") or httpMethod.contains("{"):
        warn(fmt"Experimentally adding: {row}")
        logs.add(Log(nonDefault: $row))
        continue

      if httpMethod == "":
        httpMethod = "Invalid"

      let requestURI = row[3]
      if requestURI.endsWith(".woff2") or
      requestURI.endsWith(".js") or
      requestURI.endsWith(".xml") or
      requestURI.endsWith(".css"):
        continue

      logs.add(
        Log(
          date: convertDateFormat(row[0]),
          remoteIP: row[1],
          httpMethod: httpMethod,
          requestURI: requestURI,
          statusCode: row[4],
          responseSize: row[5],
          referrer: row[6],
          userAgent: row[7],
          remoteUser: row[8],
          authenticatedUser: row[9]
        )
      )

      batchCount += 1
      if batchCount >= migrationBatchSize:
        let start = epochTime()
        insertLogs(v2Db, logs, true)
        let elapsed = epochTime() - start
        let elapsedStr = elapsed.formatFloat(format = ffDecimal, precision = 3)
        info(fmt"Row insertion took {elapsedStr} seconds")

        batchCount = 0
        logs = @[]

    offset += migrationBatchSize
    totalRecordsToProcess = abs(totalRecordsToProcess - offset)

  # if there are leftovers, add them
  if batchCount > 0:
    info(fmt"Adding {batchCount} leftovers")
    insertLogs(v2Db, logs, true)

  info(fmt"Processed {totalRecords} records")

  quit(0)
