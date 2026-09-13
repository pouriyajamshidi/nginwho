import std/[unittest, strutils]

from report import formatTable


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
