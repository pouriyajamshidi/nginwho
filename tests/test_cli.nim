## Runs the real nginwho binary

import std/[unittest, os]
from std/osproc import execCmdEx
from std/strutils import splitLines, strip, contains
from db_connector/db_sqlite import open, close

from nginwho import version

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
    # log lines are printed before the version
    check run("--version").output.strip().splitLines()[^1] == version

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

  test "bad config values are reported and the defaults are kept":
    let conf = tempDir / "bad.conf"
    writeFile(conf, "[nginx]\ninterval = 0\n[server]\nport = 70000\n[trap]\nport = abc\n" &
        "max_connections = 0\ndrip_min_ms = 900\ndrip_max_ms = 100\n" &
        "[nginx]\ncdn = akamai\n[trap.agents]\nDeepSeek = slow\n")
    # --report with a missing database reads the config and then stops
    let (output, _) = run("--config=" & quoteShell(conf) & " --report --dbPath=" &
        quoteShell(tempDir / "missing_config.db"))
    check "Bad value '0' for interval in [nginx]: must be at least 1" in output
    check "Bad value '70000' for port in [server]: must be between 1 and 65535" in output
    check "Bad value 'abc' for port in [trap]" in output
    check "Bad value '0' for max_connections in [trap]: must be at least 1" in output
    check "drip_min_ms (900) is above drip_max_ms (100) in [trap]" in output
    check "Bad value 'akamai' for cdn in [nginx]: must be cloudflare or fastly" in output
    check "Bad value 'slow' for DeepSeek in [trap.agents]: must be drip, endless, maze, login or bomb" in output

  test "a database that can't be opened ends the program with an error":
    # its folder can't be made since a file has that name, even for root, which may run the tests
    let notDir = tempDir / "not_a_dir"
    writeFile(notDir, "")
    let dbPath = notDir / "x.db"
    let (output, exitCode) = run("--processNginxLogs --serve --root=" & quoteShell(tempDir) & " --port=18557" &
        " --logPath=" & quoteShell(tempDir / "access.log") & " --dbPath=" & quoteShell(dbPath))
    check exitCode == 1
    check ("Could not open database " & dbPath) in output
