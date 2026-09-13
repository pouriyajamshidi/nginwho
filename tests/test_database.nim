import std/[unittest, times, strutils, os]
import db_connector/db_sqlite

from types import Log, Logs
from nginx import parseLogEntry, dropAlreadyInserted
from database import getDbConnection, closeDbConnection, createTables, insertLogs, getLastRow, getTopIPs, getTopURIs,
    getTopReferres, getTopUnsuccessfulRequests, getNonDefaults


proc newDb(): DbConn =
  result = getDbConnection(":memory:")
  createTables(result)


proc count(db: DbConn, table: string): int =
  db.getValue(sql("SELECT COUNT(*) FROM " & table)).parseInt


proc allLogs(db: DbConn): seq[Row] =
  ## Joins the nginwho table back into full logs, in insert order
  db.getAllRows(sql"""
    SELECT d.date, ri.remote_ip, hm.http_method, ru.request_uri, sc.status_code,
           rs.response_size, IFNULL(r.referrer, ''), ua.user_agent
    FROM nginwho n
    JOIN dates d ON n.date_id = d.id
    JOIN remote_ips ri ON n.remote_ip_id = ri.id
    JOIN http_methods hm ON n.http_method_id = hm.id
    JOIN request_uris ru ON n.request_uri_id = ru.id
    JOIN status_codes sc ON n.status_code_id = sc.id
    JOIN response_sizes rs ON n.response_size_id = rs.id
    LEFT JOIN referrers r ON n.referrer_id = r.id
    JOIN user_agents ua ON n.user_agent_id = ua.id
    ORDER BY n.id
  """)


proc log(ip = "1.1.1.1", uri = "/", status = "200", date = "2026-09-13 10:00:00",
    referrer = "", userAgent = "curl/8.0"): Log =
  Log(date: date, remoteIP: ip, httpMethod: "GET", requestURI: uri, statusCode: status,
      responseSize: "10", referrer: referrer, userAgent: userAgent)


suite "database":
  test "a saved log reads back with every field in the right column":
    let db = newDb()
    let line = """203.0.113.7 - - [13/Sep/2026:10:15:32 +0000] "GET /blog HTTP/1.1" 404 5120 "https://example.com" "Mozilla/5.0 Firefox/130.0""""
    insertLogs(db, @[parseLogEntry(line, "")])

    check db.allLogs() == @[@["2026-09-13 10:15:32", "203.0.113.7", "GET", "/blog", "404",
        "5120", "https://example.com", "Mozilla/5.0 Firefox/130.0"]]

  test "logs without a referrer are saved":
    let db = newDb()
    insertLogs(db, @[log(referrer = "")])
    check db.count("nginwho") == 1
    check db.count("referrers") == 0

  test "counts add up across inserts":
    let db = newDb()
    insertLogs(db, @[log(ip = "1.1.1.1"), log(ip = "1.1.1.1"), log(ip = "2.2.2.2")])
    insertLogs(db, @[log(ip = "1.1.1.1")])

    check db.count("nginwho") == 4
    check db.getTopIPs(10) == @[@["1.1.1.1", "3"], @["2.2.2.2", "1"]]

  test "createTables on an existing database keeps the data":
    let db = newDb()
    insertLogs(db, @[log()])
    createTables(db)
    check db.count("nginwho") == 1

  test "non-default logs are counted but not added to the nginwho table":
    let db = newDb()
    insertLogs(db, @[Log(nonDefault: "garbage"), Log(nonDefault: "garbage"), log()])
    check db.count("nginwho") == 1
    check db.getNonDefaults(10) == @[@["garbage", "2"]]

  test "getLastRow returns the last saved log":
    let db = newDb()
    check db.getLastRow() == Log()

    insertLogs(db, @[log(uri = "/first"), log(uri = "/last", date = "2026-09-13 10:00:05")])
    let last = db.getLastRow()
    check last.requestURI == "/last"
    check last.date == "2026-09-13 10:00:05"

  test "restarting on the same log file does not save logs twice":
    let db = newDb()
    let lines = @[
      """1.1.1.1 - - [13/Sep/2026:10:00:00 +0000] "GET /a HTTP/1.1" 200 1 "-" "curl/8.0"""",
      """1.1.1.1 - - [13/Sep/2026:10:00:00 +0000] "GET /a HTTP/1.1" 200 1 "-" "curl/8.0"""",
      """2.2.2.2 - - [13/Sep/2026:10:00:01 +0000] "GET /b HTTP/1.1" 200 1 "-" "curl/8.0"""",
    ]
    var logs: Logs
    for line in lines:
      logs.add(parseLogEntry(line, ""))

    insertLogs(db, logs[0..1])

    # nginwho restarts and reads the file from the start, now with one more line
    insertLogs(db, dropAlreadyInserted(logs, db.getLastRow()))
    check db.count("nginwho") == 3

    insertLogs(db, dropAlreadyInserted(logs, db.getLastRow()))
    check db.count("nginwho") == 3

  test "a failed insert rolls back and the database keeps working":
    let db = newDb()
    # a log without a status code breaks the NOT NULL constraint of the nginwho table
    check not insertLogs(db, @[log(uri = "/lost"), log(status = "")])
    check db.count("nginwho") == 0
    check db.count("request_uris") == 0

    check insertLogs(db, @[log(uri = "/ok")])
    check db.count("nginwho") == 1

  test "a request with an empty user agent does not lose the other logs":
    let db = newDb()
    insertLogs(db, @[
      parseLogEntry("""1.1.1.1 - - [13/Sep/2026:10:00:00 +0000] "GET /a HTTP/1.1" 200 1 "-" "curl/8.0"""", ""),
      parseLogEntry("""2.2.2.2 - - [13/Sep/2026:10:00:01 +0000] "GET /b HTTP/1.1" 200 1 "-" """"", ""),
    ])
    check db.count("nginwho") == 2

  test "top lists are ordered and limited":
    let db = newDb()
    insertLogs(db, @[log(uri = "/a"), log(uri = "/b"), log(uri = "/b"), log(uri = "/c"),
        log(uri = "/c"), log(uri = "/c")])
    check db.getTopURIs(2) == @[@["/c", "3"], @["/b", "2"]]

    insertLogs(db, @[log(referrer = "https://x.com"), log(referrer = "https://y.com"),
        log(referrer = "https://y.com")])
    check db.getTopReferres(1) == @[@["https://y.com", "2"]]

  test "top unsuccessful requests only has recent failed GET requests":
    let db = newDb()
    let today = now().utc.format("yyyy-MM-dd HH:mm:ss")
    insertLogs(db, @[
      log(uri = "/missing", status = "404", date = today),
      log(uri = "/missing", status = "404", date = today),
      log(uri = "/broken", status = "500", date = today),
      log(uri = "/fine", status = "200", date = today),
      log(uri = "/moved", status = "301", date = today),
      log(uri = "/old", status = "404", date = "2020-01-01 00:00:00"),
    ])
    check db.getTopUnsuccessfulRequests(10) == @[
      @["/missing with user agent curl/8.0", "2"],
      @["/broken with user agent curl/8.0", "1"],
    ]

  test "empty tables give empty results":
    let db = newDb()
    check db.getTopIPs(3).len == 0
    check db.getTopUnsuccessfulRequests(3).len == 0

  test "a database file uses WAL and enforces foreign keys":
    let path = getTempDir() / "nginwho_test_wal.db"
    removeFile(path)
    let db = getDbConnection(path)
    defer:
      closeDbConnection(db)
      removeFile(path)

    createTables(db)
    insertLogs(db, @[log()])
    check db.count("nginwho") == 1
    check db.getValue(sql"PRAGMA journal_mode") == "wal"
    check db.getValue(sql"PRAGMA foreign_keys") == "1"
    check getFilePermissions(path) == {fpUserRead, fpUserWrite}
