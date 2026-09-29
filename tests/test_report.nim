import std/unittest
from std/strutils import repeat, startsWith

from report import formatTable, formatTotals, formatSeconds


suite "report table":
  test "columns line up and counts get separators":
    let lines = formatTable(@["URI"], @[@["/a", "12000"], @["/longer", "3000"]], 20000)
    check lines == @[
      "#  URI      Requests       %",
      "1  /a         12,000   60.0%  ████████████████████",
      "2  /longer     3,000   15.0%  █████",
    ]

  test "long values are cut so the table stays readable":
    let lines = formatTable(@["User agent"], @[@["x".repeat(80), "1"]], 1)
    check lines[1] == "1  " & "x".repeat(49) & "…  " & "       1  100.0%  " & "█".repeat(20)

  test "non-ASCII values line up":
    let lines = formatTable(@["URI", "Status"], @[@["/café", "404", "2"], @["/ab", "500", "1"]], 3)
    check lines[1].startsWith("1  /café  404     ")
    check lines[2].startsWith("2  /ab    500     ")

  test "escape codes saved by bots do not reach the terminal":
    let lines = formatTable(@["Tried"], @[@["a\x1b[2Jb", "1"]], 1)
    check lines[1].startsWith("1  a\\x1B[2Jb")

  test "totals line up and only show dates when there are some":
    let lines = formatTotals(@[
      ("Requests", 12345, "2024-11-01 08:30:00", "2026-09-26 23:59:59"),
      ("Non-default logs", 2, "", ""),
      ("Trap hits", 0, "", ""),
    ])
    check lines == @[
      "Requests          12,345  2024-11-01 08:30:00 to 2026-09-26 23:59:59",
      "Non-default logs       2",
      "Trap hits              0",
    ]

  test "bot time reads like the trap reports":
    check formatSeconds(45) == "45s"
    check formatSeconds(720) == "12m"
    check formatSeconds(12_000) == "3h 20m"
