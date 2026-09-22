## Tests the trap: which bad path maps to which target, and that hits are saved
## and can be reported on

import std/unittest
from db_connector/db_sqlite import DbConn

from trap import classify
from types import TrapHit
from database import getDbConnection, createTables, insertTrapHit, finishTrapHit,
    getTopTrappedIPs, getTopTraps, getTopTrappedURIs, getTrappedCredentials, getTrapTotals


suite "classify":
  test "the paths from the offender list land in the right target":
    check $classify("/.env") == "env"
    check $classify("/api/.env") == "env"
    check $classify("/.env.production") == "env"
    check $classify("/.git/config") == "git"
    check $classify("/wp-login.php") == "wordpress"
    check $classify("//wp-includes/wlwmanifest.xml") == "wordpress"
    check $classify("/.aws/credentials") == "creds"
    check $classify("/.ssh/id_rsa") == "creds"
    check $classify("/backup.sql") == "backup"
    check $classify("/db.sql.gz") == "backup"
    check $classify("/config.json") == "config"
    check $classify("/phpinfo.php") == "php"
    check $classify("/actuator/env") == "api"
    check $classify("/api/v1/users") == "api"
    check $classify("/.well-known/gecko-litespeed.php") == "php"

  test "admin and login pages beat the plain php trap, so we can harvest logins":
    check $classify("/administrator/index.php") == "admin"
    check $classify("/phpmyadmin/") == "admin"
    check $classify("/login") == "admin"

  test "path traversal and shells are their own target":
    check $classify("/../../etc/passwd") == "rce"
    check $classify("/cgi-bin/test.cgi") == "rce"

  test "innocent paths are not trapped":
    check $classify("/") == "none"
    check $classify("/posts/hello") == "none"
    check $classify("/index.xml") == "none"


proc newDb(): DbConn =
  result = getDbConnection(":memory:")
  createTables(result)


suite "trap hits":
  test "a hit is saved at once and filled in when the trap ends":
    let db = newDb()
    let id = db.insertTrapHit(TrapHit(
      date: "2026-09-22 10:00:00", remoteIP: "45.9.1.10", httpMethod: "GET",
      requestURI: "/.env", userAgent: "curl/8", trap: "env", tactic: "drip"))
    check id > 0

    # before it ends, the row exists with nothing sent yet
    check getTrapTotals(db).hits == 1
    check getTrapTotals(db).bytes == 0

    db.finishTrapHit(id, 840, 120, "AKIAEXAMPLE")
    let totals = getTrapTotals(db)
    check totals.hits == 1
    check totals.bytes == 840
    check totals.seconds == 120

  test "the reports group and count the hits":
    let db = newDb()
    for i in 1 .. 3:
      let id = db.insertTrapHit(TrapHit(
        date: "2026-09-22 10:00:00", remoteIP: "45.9.1.10", httpMethod: "GET",
        requestURI: "/.env", userAgent: "x", trap: "env", tactic: "drip"))
      db.finishTrapHit(id, 100, 10, "")
    let id = db.insertTrapHit(TrapHit(
      date: "2026-09-22 10:00:00", remoteIP: "203.0.113.5", httpMethod: "GET",
      requestURI: "/.git/config", userAgent: "x", trap: "git", tactic: "drip"))
    db.finishTrapHit(id, 50, 5, "")

    let ips = getTopTrappedIPs(db, 10)
    check ips.len == 2
    check ips[0][0] == "45.9.1.10" # the busiest first
    check ips[0][^1] == "3"        # last column is the hit count

    let uris = getTopTrappedURIs(db, 10)
    check uris[0][0] == "/.env"
    check uris[0][^1] == "3"

    let traps = getTopTraps(db, 10)
    check traps[0][0] == "env"

  test "credentials typed into the fake login are reported":
    let db = newDb()
    let id = db.insertTrapHit(TrapHit(
      date: "2026-09-22 10:00:00", remoteIP: "66.66.66.66", httpMethod: "POST",
      requestURI: "/wp-login.php", userAgent: "x", trap: "wordpress", tactic: "login"))
    db.finishTrapHit(id, 1300, 25, "tried admin:hunter2")

    let creds = getTrappedCredentials(db, 10)
    check creds.len == 1
    check creds[0][0] == "66.66.66.66"
    check creds[0][1] == "tried admin:hunter2"

    # a drip hit has no credentials, so it is left out
    let id2 = db.insertTrapHit(TrapHit(
      date: "2026-09-22 10:00:00", remoteIP: "1.1.1.1", httpMethod: "GET",
      requestURI: "/.env", userAgent: "x", trap: "env", tactic: "drip"))
    db.finishTrapHit(id2, 10, 1, "")
    check getTrappedCredentials(db, 10).len == 1
