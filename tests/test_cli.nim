## Runs the real nginwho binary

import std/[unittest, os, osproc, strutils]
import db_connector/db_sqlite

from consts import VERSION

let tempDir = getTempDir() / "nginwho_test_cli"
let binary = tempDir / "nginwho"
removeDir(tempDir)
createDir(tempDir)

let build = execCmdEx("nim c --hints:off -o:" & quoteShell(binary) & " " &
    quoteShell(currentSourcePath.parentDir / ".." / "src" / "nginwho.nim"))
doAssert build.exitCode == 0, build.output


proc run(args: string): tuple[output: string, exitCode: int] =
  execCmdEx(quoteShell(binary) & " " & args)


suite "cli":
  test "version matches nginwho.nimble":
    const nimble = staticRead("../nginwho.nimble")
    check ("version       = \"" & VERSION & "\"") in nimble
    # log lines are printed before the version
    check run("--version").output.strip().splitLines()[^1] == VERSION

  test "exits with an error when told to do nothing":
    check run("--processNginxLogs=false").exitCode == 1

  test "report fails when the database is missing":
    let missing = tempDir / "missing_report.db"
    check run("--report --dbPath=" & quoteShell(missing)).exitCode == 1
    check not fileExists(missing)

  test "migration needs both database paths":
    check run("--migrateV1ToV2Db --v1DbPath=x.db").exitCode == 1

  test "migration fails when the v1 database is missing":
    check run("--migrateV1ToV2Db --v1DbPath=" & quoteShell(tempDir / "missing.db") &
        " --v2DbPath=" & quoteShell(tempDir / "out.db")).exitCode == 1


suite "migrate v1 to v2":
  let v1Path = tempDir / "v1.db"
  let v2Path = tempDir / "v2.db"

  proc createV1(rows: openArray[array[4, string]]) =
    removeFile(v1Path)
    let db = open(v1Path, "", "", "")
    defer: db.close()
    db.exec(sql"""CREATE TABLE nginwho (date TEXT, remoteIP TEXT, httpMethod TEXT,
        requestURI TEXT, statusCode TEXT, responseSize TEXT, referrer TEXT, userAgent TEXT,
        remoteUser TEXT, authenticatedUser TEXT)""")
    db.exec(sql"BEGIN")
    for r in rows:
      db.exec(sql"INSERT INTO nginwho VALUES (?, ?, ?, ?, '200', '10', '', 'curl/8.0', '', '')",
          r[0], r[1], r[2], r[3])
    db.exec(sql"COMMIT")

  proc migrate(): int =
    removeFile(v2Path)
    run("--migrateV1ToV2Db --v1DbPath=" & quoteShell(v1Path) & " --v2DbPath=" &
        quoteShell(v2Path)).exitCode

  proc query(statement: string): seq[Row] =
    let db = open(v2Path, "", "", "")
    defer: db.close()
    db.getAllRows(sql(statement))

  test "moves rows into the v2 schema and cleans them like live processing does":
    createV1([
      ["13-Sep-2026:10:00:00", "1.1.1.1", "GET", "/page"],
      ["13-Sep-2026:10:00:01", "1.1.1.1", "GET", "/sitemap.xml"],
      ["13-Sep-2026:10:00:02", "1.1.1.1", "GET", "/app.js"],
      ["13-Sep-2026:10:00:03", "1.1.1.1", "GET", "/style.css"],
      ["", "1.1.1.1", "GET", "/no-date"],
      ["13-Sep-2026:10:00:04", "2.2.2.2", "", "/no-method"],
      ["13-Sep-2026:10:00:05", "2.2.2.2", "\\x16\\x03", "/binary"],
    ])
    check migrate() == 0

    check query("""SELECT d.date, ri.remote_ip, hm.http_method, ru.request_uri FROM nginwho n
        JOIN dates d ON n.date_id = d.id
        JOIN remote_ips ri ON n.remote_ip_id = ri.id
        JOIN http_methods hm ON n.http_method_id = hm.id
        JOIN request_uris ru ON n.request_uri_id = ru.id
        ORDER BY n.id""") == @[
      @["2026-09-13 10:00:00", "1.1.1.1", "GET", "/page"],
      @["2026-09-13 10:00:01", "1.1.1.1", "GET", "/sitemap.xml"],
      @["2026-09-13 10:00:04", "2.2.2.2", "Invalid", "/no-method"],
    ]
    check query("SELECT COUNT(*) FROM non_defaults") == @[@["1"]]

  test "no rows are lost or duplicated around the batch size":
    # the migration inserts in batches of 100_000
    var rows: seq[array[4, string]]
    for i in 0 ..< 100_003:
      rows.add(["13-Sep-2026:10:00:00", "1.1.1.1", "GET", "/" & $i])
    createV1(rows)

    check migrate() == 0
    check query("SELECT COUNT(*), COUNT(DISTINCT request_uri_id) FROM nginwho") == @[@["100003", "100003"]]
    check query("SELECT count FROM remote_ips") == @[@["100003"]]
