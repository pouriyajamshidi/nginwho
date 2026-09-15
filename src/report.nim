from std/terminal import setForegroundColor, resetAttributes, styledWrite, styledWriteLine,
    styleBright, styleUnderscore, fgYellow, fgCyan, fgRed, fgGreen
from std/strformat import fmt
from std/strutils import parseInt, repeat, strip, insertSep, align, formatFloat, ffDecimal, rfind
from std/unicode import runeLen, runeSubStr
from std/os import fileExists
from std/times import Duration, initDuration, now, format, `-`, DurationZero, `==`
from db_connector/db_sqlite import DbConn, Row

from consts import DATE_FORMAT
from database import getDbConnection, closeDbConnection, createTables, hasDateIndex,
    getTopIPs, getTopURIs, getTopUnsuccessfulRequests, getTopReferres, getNonDefaults,
    getTotalRequests, getTotalNonDefaults


const
  # long URIs and user agents would break the table
  maxColumnWidth = 50
  barWidth = 20

type
  Report = object
    name: string
    columns: seq[string]
    query: proc (db: DbConn, num: uint, since: string): seq[Row] {.nimcall.}
    allTimeOnly: bool

  TimeWindow = tuple[name: string, duration: Duration]

let reports = [
  Report(name: "Top IP addresses", columns: @["IP address"], query: getTopIPs),
  Report(name: "Top URIs", columns: @["URI"], query: getTopURIs),
  Report(name: "Top unsuccessful requests", columns: @["Status", "URI", "User agent"],
      query: getTopUnsuccessfulRequests),
  Report(name: "Top referrers", columns: @["Referrer"], query: getTopReferres),
  # non-default logs are saved without a date
  Report(name: "Top non-defaults", columns: @["Log line"], query: getNonDefaults, allTimeOnly: true),
]

# a zero duration means all time
let timeWindows: array[4, TimeWindow] = [
  ("last 24 hours", initDuration(days = 1)),
  ("last 7 days", initDuration(days = 7)),
  ("last 30 days", initDuration(days = 30)),
  ("all time", DurationZero),
]


proc since(window: TimeWindow): string =
  ## Returns the date the time window starts at, in the same format and local time as the saved logs
  if window.duration == DurationZero:
    return ""
  return (now() - window.duration).format(DATE_FORMAT)


proc fit(text: string, width: int): string =
  ## Cuts `text` to `width` characters and pads it to exactly that width
  if runeLen(text) > width:
    return runeSubStr(text, 0, width - 1) & "…"
  return text & " ".repeat(width - runeLen(text))


proc formatTable*(columns: seq[string], rows: seq[Row], total: int): seq[string] =
  ## Returns the rows as table lines, starting with the header.
  ## Every row has one value per column and then its count
  var widths: seq[int]
  for i, column in columns:
    var width = runeLen(column)
    for row in rows:
      width = max(width, runeLen(row[i]))
    widths.add(min(width, maxColumnWidth))

  var counts: seq[int]
  for row in rows:
    counts.add(parseInt(row[^1]))

  let topCount = max(counts & @[1])
  let countWidth = max(len("Requests"), len(insertSep($topCount, ',')))
  let numberWidth = len($len(rows))

  var header = align("#", numberWidth)
  for i, column in columns:
    header &= "  " & fit(column, widths[i])
  result.add(header & "  " & align("Requests", countWidth) & "  " & align("%", 6))

  for n, row in rows:
    var line = align($(n + 1), numberWidth)
    for i in 0 ..< len(columns):
      line &= "  " & fit(row[i], widths[i])

    let percent = if total > 0: counts[n] / total * 100 else: 0.0
    let bar = "█".repeat(max(1, counts[n] * barWidth div topCount))
    result.add(line & "  " & align(insertSep($counts[n], ','), countWidth) & "  " &
        align(percent.formatFloat(ffDecimal, 1) & "%", 6) & "  " & bar)


proc warn(message: string) =
  stdout.styledWriteLine(fgRed, message)


proc ask(question: string): string =
  stdout.styledWrite(fgCyan, question)
  stdout.flushFile()
  # treat Ctrl+D the same as quitting
  try:
    return stdin.readLine().strip()
  except IOError:
    return "q"


proc askNumber(question: string, max: int): int =
  ## Returns a number from 1 to `max`, or 0 to go back
  while true:
    let answer = ask(question)
    if answer == "q":
      return 0

    try:
      let num = parseInt(answer)
      if num >= 1 and num <= max:
        return num
    except ValueError:
      discard

    warn(fmt"Pick a number from 1 to {max}, or q to go back")


proc printMenu(lines: seq[string]) =
  ## Prints menu lines in yellow so every menu looks the same
  setForegroundColor(fgYellow, true)
  echo()
  for line in lines:
    echo("  ", line)
  echo()
  stdout.resetAttributes()


proc showMenu(window: TimeWindow) =
  var lines: seq[string]
  for i, report in reports:
    let note = if report.allTimeOnly: " (all time)" else: ""
    lines.add(fmt"{i + 1}) {report.name}{note}")

  lines.add(fmt"w) Change time window (now: {window.name})")
  lines.add("q) Quit")
  printMenu(lines)


proc chooseTimeWindow(current: int): int =
  var lines: seq[string]
  for i, window in timeWindows:
    lines.add(fmt"{i + 1}) {window.name}")
  printMenu(lines)

  let choice = askNumber("Select a time window (q to keep the current one): ", len(timeWindows))
  if choice == 0:
    return current
  return choice - 1


proc showResults(db: DbConn, report: Report, num: uint, window: TimeWindow) =
  let rows = report.query(db, num, since(window))

  let windowName = if report.allTimeOnly: "all time" else: window.name
  let total = if report.allTimeOnly: getTotalNonDefaults(db) else: getTotalRequests(db, since(window))

  echo()
  stdout.styledWriteLine(fgGreen, styleBright, fmt"{report.name}, {windowName} ({insertSep($total, ',')} requests)")
  echo()

  if len(rows) == 0:
    warn("  No records found")
    return

  let lines = formatTable(report.columns, rows, total)
  stdout.styledWriteLine(styleBright, styleUnderscore, "  ", lines[0])
  for line in lines[1..^1]:
    # the bar is the last part of the line and has no spaces
    let barStart = line.rfind("  ") + 2
    stdout.styledWriteLine("  ", line[0 ..< barStart], fgGreen, line[barStart..^1])


proc report*(dbPath: string) =
  # opening a missing database creates an empty one and every query fails
  if not fileExists(dbPath):
    warn(fmt"Database not found at {dbPath}")
    quit(1)

  let db = getDbConnection(dbPath)

  # databases from older versions don't have the index yet
  if not hasDateIndex(db):
    echo("Creating the date index for time window reports, this can take a while on big databases...")
    createTables(db)

  var window = 2 # last 30 days

  while true:
    showMenu(timeWindows[window])

    let choice = ask("Select an option: ")

    if choice == "q":
      break

    if choice == "w":
      window = chooseTimeWindow(window)
      continue

    let option = try: parseInt(choice) except ValueError: 0
    if option < 1 or option > len(reports):
      warn("Pick an option from the menu")
      continue

    let num = askNumber("Number of records to show: ", high(int32))
    if num == 0:
      continue

    showResults(db, reports[option - 1], uint(num), timeWindows[window])

  stdout.resetAttributes()
  closeDbConnection(db)
  quit(0)
