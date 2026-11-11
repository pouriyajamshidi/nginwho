## Runs the real nginwho binary

import std/[unittest, os]
from std/osproc import execCmdEx, startProcess, terminate, waitForExit, close
from std/strutils import splitLines, strip, contains
from db_connector/db_sqlite import open, close, getValue, sql

from nginwho import version, maintainer

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
    check ("version       = \"" & version & "\"") in nimble
    # log lines are printed before the version and the maintainer
    let lines = run("--version").output.strip().splitLines()
    check lines[^2] == version
    check lines[^1] == maintainer

  test "exits with an error when told to do nothing":
    # every feature is off by default. a missing config file keeps the defaults
    check run("--config=" & quoteShell(tempDir / "none.conf")).exitCode == 1
    check run("--config=" & quoteShell(tempDir / "none.conf") & " --report=false").exitCode == 1

  test "report runs on its own":
    let path = tempDir / "report.db"
    open(path, "", "", "").close()
    # stdin is empty, which report mode reads as quitting
    check run("--config=" & quoteShell(tempDir / "none.conf") & " --report --dbPath=" &
        quoteShell(path)).exitCode == 0

  test "report fails when the database is missing":
    let missing = tempDir / "missing_report.db"
    check run("--report --dbPath=" & quoteShell(missing)).exitCode == 1
    check not fileExists(missing)

  test "bad flag values exit with an error instead of crashing":
    for args in ["--interval=abc", "--interval=0", "--showRealIps=maybe", "--cdn=akamai"]:
      let (output, exitCode) = run(args)
      check exitCode == 1
      check "Bad value" in output

  test "a flag value after a space is an error instead of being ignored":
    for args in ["--processNginxLogs --omitReferrer example.com", "--report --dbPath /tmp/x.db"]:
      let (output, exitCode) = run(args)
      check exitCode == 1
      check "Unexpected argument" in output

  test "a bad config value exits with an error":
    let conf = tempDir / "bad.conf"
    for (content, message) in [
        ("[logs]\ninterval = 0\n", "Bad value '0' for interval in [logs]: must be at least 1"),
        ("[server]\nport = 70000\n", "Bad value '70000' for port in [server]: must be between 1 and 65535"),
        ("[trap]\nport = abc\n", "Bad value 'abc' for port in [trap]"),
        ("[trap]\nmax_connections = 0\n", "Bad value '0' for max_connections in [trap]: must be at least 1"),
        ("[trap]\ndrip_min_ms = 900\ndrip_max_ms = 100\n", "drip_min_ms (900) is above drip_max_ms (100) in [trap]"),
        ("[cdn]\nname = akamai\n", "Bad value 'akamai' for name in [cdn]: must be cloudflare or fastly"),
        ("[firewall]\nlockdown = ture\n", "Bad value 'ture' for lockdown in [firewall]"),
        ("[trap.agents]\nDeepSeek = slow\n",
          "Bad value 'slow' for DeepSeek in [trap.agents]: must be drip, endless, maze, login or bomb")]:
      writeFile(conf, content)
      # the database must not be touched, as nginwho stops before it gets there
      let dbPath = tempDir / "bad_config.db"
      let (output, exitCode) = run("--config=" & quoteShell(conf) & " --report --dbPath=" & quoteShell(dbPath))
      check exitCode == 1
      check message in output
      check not fileExists(dbPath)

  test "a database that can't be opened ends the program with an error":
    # its folder can't be made since a file has that name, even for root, which may run the tests
    let notDir = tempDir / "not_a_dir"
    writeFile(notDir, "")
    let dbPath = notDir / "x.db"
    let (output, exitCode) = run("--processNginxLogs --serve --root=" & quoteShell(tempDir) & " --port=18557" &
        " --logPath=" & quoteShell(tempDir / "access.log") & " --dbPath=" & quoteShell(dbPath))
    check exitCode == 1
    check ("Could not open database " & dbPath) in output

  test "lines written to the log right before it is rotated are saved":
    let logPath = tempDir / "rotate.log"
    let dbPath = tempDir / "rotate.db"
    proc line(uri: string): string =
      "1.1.1.1 - - [13/Sep/2026:10:00:00 +0000] \"GET " & uri & " HTTP/1.1\" 200 1 \"-\" \"curl/8.0\"\n"

    writeFile(logPath, line("/a"))
    let p = startProcess(binary, args = ["--config=" & tempDir / "none.conf", "--processNginxLogs",
        "--interval=1", "--logPath=" & logPath, "--dbPath=" & dbPath])
    sleep(1500)

    # a line nginx writes between two reads, then logrotate moves the file
    let f = open(logPath, fmAppend)
    f.write(line("/b"))
    f.close()
    moveFile(logPath, logPath & ".1")
    writeFile(logPath, line("/c"))
    sleep(3000)
    p.terminate()
    discard p.waitForExit()
    p.close()

    let db = open(dbPath, "", "", "")
    check db.getValue(sql"SELECT COUNT(*) FROM nginwho") == "3"
    db.close()
