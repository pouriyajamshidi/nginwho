from db_connector/db_sqlite import DbConn, DbError, Row, SqlPrepared, sql, open,
    close, exec, tryExec, insertID, prepare, getRow, getAllRows, getValue, dbError
from db_connector/sqlite3 import PStmt, bind_text, step, reset, finalize,
    SQLITE_OK, SQLITE_DONE, SQLITE_TRANSIENT
from std/tables import initTable, mgetOrPut, pairs
from std/strformat import fmt
from std/os import fileExists, setFilePermissions, FilePermission, createDir, parentDir
from std/strutils import parseInt
from std/logging import info, warn, error

from nginx import Log


type
  TrapHit* = object
    ## A row of the trap_hits table
    date*: string
    remoteIP*: string
    httpMethod*: string
    requestURI*: string
    userAgent*: string
    trap*: string   # what they were looking for
    tactic*: string # what we did to them
    bytesSent*: int
    seconds*: int
    detail*: string # the fake secret we handed out, or the credentials they tried
    body*: string   # the start of a POST body, like a login form or the code they hoped to run


const
  # dates are saved as unix seconds, 4 bytes instead of a 19 character string.
  # strftime instead of unixepoch because unixepoch needs SQLite 3.38
  toUnix = "CAST(strftime('%s', ?) AS INTEGER)"
  # an empty `since` means all time
  toUnixOrAll = "IFNULL(CAST(strftime('%s', ?) AS INTEGER), 0)"
  fromUnix = "datetime(n.date, 'unixepoch')"

  lookupColumns = [
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

  nginwhoTable = """
    (
      id INTEGER PRIMARY KEY,
      date INTEGER NOT NULL,
      remote_ip_id INTEGER NOT NULL,
      http_method_id INTEGER NOT NULL,
      request_uri_id INTEGER NOT NULL,
      status_code_id INTEGER NOT NULL,
      response_size_id INTEGER NOT NULL,
      referrer_id INTEGER,
      user_agent_id INTEGER NOT NULL,
      remote_user_id INTEGER,
      authenticated_user_id INTEGER,
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

  # trap hits are rare next to normal logs, so their values are kept as they are
  # instead of being spread over lookup tables
  trapHitsTable = """
    CREATE TABLE IF NOT EXISTS trap_hits
    (
      id INTEGER PRIMARY KEY,
      date INTEGER NOT NULL,
      remote_ip TEXT NOT NULL,
      http_method TEXT NOT NULL,
      request_uri TEXT NOT NULL,
      user_agent TEXT NOT NULL,
      trap TEXT NOT NULL,
      tactic TEXT NOT NULL,
      bytes_sent INTEGER NOT NULL,
      seconds INTEGER NOT NULL,
      detail TEXT,
      body TEXT
    )"""


proc getDbConnection*(dbPath: string): DbConn =
  ## Raises DbError when the database can't be opened
  info(fmt"Opening Database connection to {dbPath}")

  let isNewFile = dbPath != ":memory:" and not fileExists(dbPath)

  try:
    # SQLite creates the file but not its folder, such as /var/lib/nginwho
    if isNewFile and dbPath.parentDir != "":
      createDir(dbPath.parentDir)
    let connection = open(dbPath, "", "", "")
    # WAL lets --report read while the service writes
    connection.exec(sql"PRAGMA journal_mode = WAL")
    # safe with WAL and much faster than the default FULL
    connection.exec(sql"PRAGMA synchronous = NORMAL")
    # wait for a lock instead of failing right away
    connection.exec(sql"PRAGMA busy_timeout = 5000")
    connection.exec(sql"PRAGMA foreign_keys = ON")

    # visitor IPs and URIs are private. SQLite gives the WAL files the same permissions
    if isNewFile:
      setFilePermissions(dbPath, {fpUserRead, fpUserWrite})

    return connection
  except CatchableError as e:
    raise newException(DbError, fmt"Could not open database {dbPath}: {e.msg}")


proc closeDbConnection*(db: DbConn) =
  info("Closing Database connection")

  try:
    db.close()
  except DbError as e:
    # nothing is lost, every write was committed already
    warn(fmt"Could not close database: {e.msg}")


proc topValues(db: DbConn, column: string, num: int, since: string): seq[Row] =
  ## Returns the most seen values of a column with their count, from `since` on.
  ## An empty `since` means all time
  if since == "":
    # the count column is updated on every insert, much faster than counting the nginwho table
    return db.getAllRows(sql(fmt"""
      SELECT {column}, count
      FROM {column}s
      ORDER BY count DESC, {column}
      LIMIT ?"""), num)

  return db.getAllRows(sql(fmt"""
    SELECT t.{column}, COUNT(*) AS occurrences
    FROM nginwho n
    JOIN {column}s t ON n.{column}_id = t.id
    WHERE n.date >= {toUnix}
    GROUP BY n.{column}_id
    ORDER BY occurrences DESC, t.{column}
    LIMIT ?"""), since, num)


proc getTopIPs*(db: DbConn, num: int, since = ""): seq[Row] =
  info(fmt"Getting top {num} visitor IPs")
  return topValues(db, "remote_ip", num, since)


proc getTopURIs*(db: DbConn, num: int, since = ""): seq[Row] =
  info(fmt"Getting top {num} URIs")
  return topValues(db, "request_uri", num, since)


proc getTopReferrers*(db: DbConn, num: int, since = ""): seq[Row] =
  info(fmt"Getting top {num} referrers")
  return topValues(db, "referrer", num, since)


proc getTopUserAgents*(db: DbConn, num: int, since = ""): seq[Row] =
  info(fmt"Getting top {num} user agents")
  return topValues(db, "user_agent", num, since)


proc getTopUnsuccessfulRequests*(db: DbConn, num: int, since = ""): seq[Row] =
  info(fmt"Getting top {num} unsuccessful requests")

  let statement = sql(fmt"""
  SELECT
    sc.status_code,
    ru.request_uri,
    ua.user_agent,
    COUNT(*) as occurrences
  FROM nginwho n
  JOIN status_codes sc ON n.status_code_id = sc.id
  JOIN request_uris ru ON n.request_uri_id = ru.id
  JOIN http_methods hm ON n.http_method_id = hm.id
  JOIN user_agents ua ON n.user_agent_id = ua.id
  WHERE
      n.date >= {toUnixOrAll}
      AND CAST(sc.status_code AS INTEGER) NOT BETWEEN 200 AND 399
      AND hm.http_method = 'GET'
  GROUP BY sc.status_code, ru.request_uri, ua.user_agent
  ORDER BY occurrences DESC, sc.status_code, ru.request_uri, ua.user_agent
  LIMIT ?
  """)

  return db.getAllRows(statement, since, num)


proc getNonDefaults*(db: DbConn, num: int, since = ""): seq[Row] =
  ## Non-default logs have no date, so `since` is ignored
  info(fmt"Getting top {num} non-default logs")
  return topValues(db, "non_default", num, "")


proc getTotalRequests*(db: DbConn, since = ""): int =
  ## Returns how many requests are saved from `since` on. An empty `since` means all time
  if since == "":
    return parseInt(db.getValue(sql"SELECT COUNT(*) FROM nginwho"))

  return parseInt(db.getValue(sql(fmt"SELECT COUNT(*) FROM nginwho WHERE date >= {toUnix}"), since))


proc getTotalNonDefaults*(db: DbConn): int =
  return parseInt(db.getValue(sql"SELECT IFNULL(SUM(count), 0) FROM non_defaults"))


proc getSpan*(db: DbConn, table: string): tuple[count: int, first, last: string] =
  ## How many rows the nginwho or trap_hits table has, and the dates of the first and last one.
  ## The dates are empty when the table is
  let row = db.getRow(sql(fmt"""
    SELECT COUNT(*), IFNULL(datetime(MIN(date), 'unixepoch'), ''), IFNULL(datetime(MAX(date), 'unixepoch'), '')
    FROM {table}"""))
  return (parseInt(row[0]), row[1], row[2])


proc hasOldSchema*(db: DbConn): bool =
  ## Databases from older versions keep dates in their own table
  return db.getValue(sql"SELECT 1 FROM pragma_table_info('nginwho') WHERE name = 'date_id'") == "1"


proc createTables*(db: DbConn) =
  info("Creating database tables")

  let upgrade = hasOldSchema(db)

  db.exec(sql"BEGIN TRANSACTION")

  for column in lookupColumns:
    db.exec(sql(fmt"""CREATE TABLE IF NOT EXISTS {column}s
        (
          id INTEGER PRIMARY KEY,
          {column} TEXT UNIQUE NOT NULL,
          count INTEGER NOT NULL DEFAULT 1
        )"""
      )
    )

  db.exec(sql("CREATE TABLE IF NOT EXISTS nginwho" & nginwhoTable))

  # older versions kept dates in their own table. Nearly every log has its own date,
  # so that table and its index were bigger than the nginwho table itself
  if upgrade:
    info("Moving dates into the nginwho table, this can take a while on big databases")
    db.exec(sql("CREATE TABLE nginwho_new" & nginwhoTable))
    db.exec(sql"""
      INSERT INTO nginwho_new
      SELECT n.id, CAST(strftime('%s', d.date) AS INTEGER), n.remote_ip_id, n.http_method_id,
             n.request_uri_id, n.status_code_id, n.response_size_id, n.referrer_id,
             n.user_agent_id, n.remote_user_id, n.authenticated_user_id
      FROM nginwho n
      JOIN dates d ON n.date_id = d.id""")
    db.exec(sql"DROP TABLE nginwho")
    db.exec(sql"DROP TABLE dates")
    db.exec(sql"ALTER TABLE nginwho_new RENAME TO nginwho")

  db.exec(sql(trapHitsTable))
  # older versions did not save POST bodies
  if db.getValue(sql"SELECT 1 FROM pragma_table_info('trap_hits') WHERE name = 'body'") != "1":
    db.exec(sql"ALTER TABLE trap_hits ADD COLUMN body TEXT")

  # time window reports look up logs by date
  db.exec(sql"CREATE INDEX IF NOT EXISTS idx_nginwho_date ON nginwho(date)")
  db.exec(sql"CREATE INDEX IF NOT EXISTS idx_trap_hits_date ON trap_hits(date)")

  db.exec(sql"COMMIT")

  if upgrade:
    # give the space of the dropped tables back to the disk
    db.exec(sql"VACUUM")
    db.exec(sql"PRAGMA wal_checkpoint(TRUNCATE)")


proc getLastRow*(db: DbConn): Log =
  info("Getting the last record from database")

  let selectStatement = sql(fmt"""
    SELECT
      {fromUnix},
      ri.remote_ip,
      hm.http_method,
      ru.request_uri
    FROM nginwho n
    JOIN remote_ips ri ON n.remote_ip_id = ri.id
    JOIN http_methods hm on n.http_method_id = hm.id
    JOIN request_uris ru ON n.request_uri_id = ru.id
    ORDER BY n.id DESC
    LIMIT 1
  """)

  let row = db.getRow(selectStatement)

  # every row has a date, so an empty one means there are no rows
  if row[0] == "":
    info("No rows in database yet")
    return

  return Log(
    date: row[0],
    remoteIP: row[1],
    httpMethod: row[2],
    requestURI: row[3],
  )


proc execPrepared(db: DbConn, statement: SqlPrepared, values: varargs[string]) =
  ## Runs a statement that was prepared once, so SQLite does not parse it again for every row.
  ## db_sqlite's own exec for prepared statements finalizes them on errors, which breaks a later finalize
  let stmt = PStmt(statement)
  discard reset(stmt)
  for i, value in values:
    if bind_text(stmt, int32(i + 1), value.cstring, int32(value.len),
        SQLITE_TRANSIENT) != SQLITE_OK:
      dbError(db)
  if step(stmt) != SQLITE_DONE:
    dbError(db)


proc upsert(db: DbConn, table, column: string, values: seq[string]) =
  info(fmt"Processing {table} table")

  if values.len < 1:
    info(fmt"No values to insert in {table} table")
    return

  let insertQuery = db.prepare(fmt"""
    INSERT INTO {table} ({column}, count)
    VALUES (?, ?)
    ON CONFLICT ({column})
    DO UPDATE SET
      count = count + excluded.count
  """)
  defer: discard finalize(PStmt(insertQuery))

  var valueCounts = initTable[string, int]()
  for value in values:
    valueCounts.mgetOrPut(value, 0).inc

  for value, count in valueCounts.pairs:
    execPrepared(db, insertQuery, value, $count)


proc normalizeNginwhoTable(db: DbConn, logs: seq[Log]) =
  info("Populating the nginwho table")

  let defaultQuery = db.prepare(fmt"""
    INSERT INTO nginwho (
      date,
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
      {toUnix},
      (SELECT id FROM remote_ips WHERE remote_ip = ?),
      (SELECT id FROM http_methods WHERE http_method = ?),
      (SELECT id FROM request_uris WHERE request_uri = ?),
      (SELECT id FROM status_codes WHERE status_code = ?),
      (SELECT id FROM response_sizes WHERE response_size = ?),
      (SELECT id FROM referrers WHERE referrer = ?),
      (SELECT id FROM user_agents WHERE user_agent = ?),
      (SELECT id FROM remote_users WHERE remote_user = ?),
      (SELECT id FROM authenticated_users WHERE authenticated_user = ?)
  """)
  defer: discard finalize(PStmt(defaultQuery))

  for log in logs:
    # TODO: handle non-default logs
    if log.nonDefault != "":
      continue
    execPrepared(db, defaultQuery,
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


proc insertLogs*(db: DbConn, logs: seq[Log]): bool =
  ## Returns false when the insert failed and nothing was saved
  let logsLen = logs.len
  if logsLen < 1:
    warn("No logs received")
    return true

  info(fmt"Inserting {logsLen} logs into database")

  var
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
    if log.remoteIP.len > 0: remoteIPs.add(log.remoteIP)
    if log.httpMethod.len > 0: httpMethods.add(log.httpMethod)
    if log.requestURI.len > 0: requestURIs.add(log.requestURI)
    if log.statusCode.len > 0: statusCodes.add(log.statusCode)
    if log.responseSize.len > 0: responseSizes.add(log.responseSize)
    if log.referrer.len > 0: referrers.add(log.referrer)
    if log.userAgent.len > 0: userAgents.add(log.userAgent)
    if log.nonDefault.len > 0: nonDefaults.add(log.nonDefault)
    if log.remoteUser.len > 0: remoteUsers.add(log.remoteUser)
    if log.authenticatedUser.len > 0: authenticatedUsers.add(
        log.authenticatedUser)

  try:
    # IMMEDIATE takes the write lock up front, so busy_timeout applies to the whole insert
    db.exec(sql"BEGIN IMMEDIATE")
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
    return true
  except DbError as e:
    # without a rollback the transaction stays open and every next insert fails
    # tryExec because there is no transaction to roll back when BEGIN itself failed
    discard db.tryExec(sql"ROLLBACK")
    error(fmt"Failed inserting {logsLen} logs, rolled back: {e.msg}")


proc insertTrapHit*(db: DbConn, hit: TrapHit): int64 =
  ## Saves a trapped request as soon as it starts, so we know who tried what even
  ## when the bot is still hanging on a slow drip. Returns the new row id, or -1 on
  ## failure, to update the byte count and duration once the trap ends
  try:
    return db.insertID(sql(fmt"""
      INSERT INTO trap_hits
        (date, remote_ip, http_method, request_uri, user_agent, trap, tactic, bytes_sent, seconds, detail, body)
      VALUES ({toUnix}, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"""),
      hit.date, hit.remoteIP, hit.httpMethod, hit.requestURI, hit.userAgent,
      hit.trap, hit.tactic, hit.bytesSent, hit.seconds, hit.detail, hit.body)
  except DbError as e:
    error(fmt"Could not save trap hit: {e.msg}")
    return -1


proc finishTrapHit*(db: DbConn, id: int64, bytesSent, seconds: int,
    detail: string) =
  ## Fills in what the trap ended up sending and how long it held the bot
  if id < 0:
    return
  try:
    db.exec(sql"""
      UPDATE trap_hits SET bytes_sent = ?, seconds = ?, detail = ?
      WHERE id = ?""", bytesSent, seconds, detail, id)
  except DbError as e:
    error(fmt"Could not update trap hit {id}: {e.msg}")


const
  # seconds as "3h 20m", "12m" or "45s", so the report reads at a glance
  humanSeconds = """
    CASE
      WHEN SUM(seconds) >= 3600 THEN printf('%dh %dm', SUM(seconds)/3600, (SUM(seconds)%3600)/60)
      WHEN SUM(seconds) >= 60 THEN printf('%dm', SUM(seconds)/60)
      ELSE printf('%ds', SUM(seconds))
    END"""


proc getTopTrappedIPs*(db: DbConn, num: int, since = ""): seq[Row] =
  ## The busiest bots, with how long they were held. Last column is the hit count
  info(fmt"Getting top {num} trapped IPs")
  return db.getAllRows(sql(fmt"""
    SELECT remote_ip, {humanSeconds}, COUNT(*) AS hits
    FROM trap_hits
    WHERE date >= {toUnixOrAll}
    GROUP BY remote_ip
    ORDER BY hits DESC, remote_ip
    LIMIT ?"""), since, num)


proc getTopTraps*(db: DbConn, num: int, since = ""): seq[Row] =
  ## What the bots were after and what we did about it
  info(fmt"Getting top {num} traps")
  return db.getAllRows(sql(fmt"""
    SELECT trap, tactic, {humanSeconds}, COUNT(*) AS hits
    FROM trap_hits
    WHERE date >= {toUnixOrAll}
    GROUP BY trap, tactic
    ORDER BY hits DESC, trap
    LIMIT ?"""), since, num)


proc getTopTrappedURIs*(db: DbConn, num: int, since = ""): seq[Row] =
  info(fmt"Getting top {num} trapped URIs")
  return db.getAllRows(sql(fmt"""
    SELECT request_uri, trap, COUNT(*) AS hits
    FROM trap_hits
    WHERE date >= {toUnixOrAll}
    GROUP BY request_uri, trap
    ORDER BY hits DESC, request_uri
    LIMIT ?"""), since, num)


proc getTrappedCredentials*(db: DbConn, num: int, since = ""): seq[Row] =
  ## Usernames and passwords bots sent to the trap, mostly to the fake login pages
  info(fmt"Getting top {num} trapped credentials")
  return db.getAllRows(sql(fmt"""
    SELECT remote_ip, detail, COUNT(*) AS hits
    FROM trap_hits
    WHERE date >= {toUnixOrAll} AND detail LIKE 'tried %'
    GROUP BY remote_ip, detail
    ORDER BY hits DESC, remote_ip
    LIMIT ?"""), since, num)


proc getTrapTotals*(db: DbConn, since = ""): tuple[hits, seconds, bytes: int] =
  ## Total hits, seconds wasted and bytes sent, for the report header
  let row = db.getRow(sql(fmt"""
    SELECT COUNT(*), IFNULL(SUM(seconds), 0), IFNULL(SUM(bytes_sent), 0)
    FROM trap_hits
    WHERE date >= {toUnixOrAll}"""), since)
  return (parseInt(row[0]), parseInt(row[1]), parseInt(row[2]))
