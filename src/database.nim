import db_connector/db_sqlite
from std/tables import initTable, mgetOrPut, pairs
from std/strformat import fmt
from std/os import fileExists
from std/strutils import parseInt, contains, split, endsWith, formatFloat, ffDecimal
from std/sequtils import any
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


proc getTopIPs*(db: DbConn, num: uint = 3): seq[Row] =
  info(fmt"Getting top {num} visitor IPs")

  let statement = fmt"""
  SELECT
    remote_ip, count
  FROM remote_ips
  ORDER BY count DESC
  LIMIT {num}
  """

  let rows = db.getAllRows(sql(statement))

  if len(rows) < 1:
    warn("No records found")
    return

  return rows


proc getTopURIs*(db: DbConn, num: uint = 3): seq[Row] =
  info(fmt"Getting top {num} URIs")

  let statement = fmt"""
  SELECT
    request_uri, count
  FROM request_uris
  ORDER BY count DESC
  LIMIT {num}
  """

  let rows = db.getAllRows(sql(statement))

  if len(rows) < 1:
    warn("No records found")
    return

  return rows


proc getTopReferres*(db: DbConn, num: uint = 3): seq[Row] =
  info(fmt"Getting top {num} referrers")

  let statement = fmt"""
  SELECT
    referrer, count
  FROM referrers
  ORDER BY count DESC
  LIMIT {num}
  """

  let rows = db.getAllRows(sql(statement))

  if len(rows) < 1:
    warn("No records found")
    return

  return rows


proc getTopUnsuccessfulRequests*(db: DbConn, num: uint = 3): seq[Row] =
  info(fmt"Getting top {num} unsuccessful requests")

  let statement = fmt"""
  SELECT
    d.date,
    sc.status_code,
    ru.request_uri,
    hm.http_method,
    ua.user_agent,
    COUNT(*) as occurrence_count
  FROM nginwho n
  JOIN dates d ON n.date_id = d.id
  JOIN status_codes sc ON n.status_code_id = sc.id
  JOIN request_uris ru ON n.request_uri_id = ru.id
  JOIN http_methods hm ON n.http_method_id = hm.id
  JOIN user_agents ua ON n.user_agent_id = ua.id
  WHERE
      d.date >= date('now', '-30 days')
      AND CAST(sc.status_code AS INTEGER) NOT BETWEEN 200 AND 399
      AND hm.http_method = 'GET'
  GROUP BY d.date, sc.status_code, ru.request_uri
  ORDER BY occurrence_count DESC
  LIMIT {num}
  """

  let rows = db.getAllRows(sql(statement))

  if len(rows) < 1:
    warn("No records found")
    return

  var count = 1
  for row in rows:
    echo(fmt"{count}) {row[0]} - {row[1]} - {row[3]} - {row[2]} - seen {row[5]} -- user agent: {row[4]}")
    count += 1

  return rows


proc getNonDefaults*(db: DbConn, num: uint = 3): seq[Row] =
  info(fmt"Getting top {num} non-default logs")

  let statement = fmt"""
  SELECT
    non_default, count
  FROM non_defaults
  ORDER BY count DESC
  LIMIT {num}
  """

  let rows = db.getAllRows(sql(statement))

  if len(rows) < 1:
    warn("No records found")
    return

  return rows


proc createTables*(db: DbConn) =
  info("Creating database tables")

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

  # TODO: Check how these can be utilized
  # db.exec(sql"""
  #   CREATE INDEX IF NOT EXISTS idx_nginwho_date ON nginwho(date_id);
  #   CREATE INDEX IF NOT EXISTS idx_nginwho_remote_ip ON nginwho(remote_ip_id);
  #   CREATE INDEX IF NOT EXISTS idx_nginwho_http_method ON nginwho(http_method_id);
  #   CREATE INDEX IF NOT EXISTS idx_nginwho_request_uri ON nginwho(request_uri_id);
  #   CREATE INDEX IF NOT EXISTS idx_nginwho_referrer ON nginwho(referrer_id);
  #   CREATE INDEX IF NOT EXISTS idx_nginwho_user_agent ON nginwho(user_agent_id);
  # """)

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
    # TODO: handle non-defaults
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


proc getLastRow*(db: DbConn): Log =
  info("Getting the last record from database")

  let selectStatement = sql"""
    SELECT 
      d.date,
      ri.remote_ip,
      hm.http_method,
      ru.request_uri
    FROM nginwho n
    JOIN dates d ON n.date_id = d.id
    JOIN remote_ips ri ON n.remote_ip_id = ri.id
    JOIN http_methods hm on n.http_method_id = hm.id
    JOIN request_uris ru ON n.request_uri_id = ru.id
    ORDER BY n.id DESC
    LIMIT 1
  """

  let row = db.getRow(selectStatement)

  let hasResult = any(row, proc (s: string): bool = s != "")
  if not hasResult:
    info("No rows in database yet")
    return

  return Log(
    date: row[0],
    remoteIP: row[1],
    httpMethod: row[2],
    requestURI: row[3],
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


proc insertLogs*(db: DbConn, logs: seq[Log]) =
  let logsLen = len(logs)
  if logsLen < 1:
    warn("No logs received")
    return

  info(fmt"Inserting {logsLen} logs into database")

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


proc insertLogV1*(db: DbConn, logs: var seq[
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
        insertLogs(v2Db, logs)
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
    insertLogs(v2Db, logs)

  info(fmt"Processed {totalRecords} records")

  quit(0)
