from std/terminal import setForegroundColor, resetAttributes, styledWriteLine,
    styleUnderscore, fgYellow, fgRed, fgGreen, fgBlue
from std/strformat import fmt
from std/strutils import parseInt, repeat, strip
from std/rdstdin import readLineFromStdin
from std/os import fileExists
from std/times import Duration, initDuration, now, format, `-`, DurationZero, `==`
from db_connector/db_sqlite import DbConn, Row

from consts import DATE_FORMAT
from database import getDbConnection, closeDbConnection, createTables, hasDateIndex,
    getTopIPs, getTopURIs, getTopUnsuccessfulRequests, getTopReferres, getNonDefaults


const parenRepeatCount = 80

type
  Report = object
    name: string
    query: proc (db: DbConn, num: uint, since: string): seq[Row] {.nimcall.}
    allTimeOnly: bool

  TimeWindow = tuple[name: string, duration: Duration]

let reports = [
  Report(name: "Top IP addresses", query: getTopIPs),
  Report(name: "Top URIs", query: getTopURIs),
  Report(name: "Top unsuccessful requests", query: getTopUnsuccessfulRequests),
  Report(name: "Top referrers", query: getTopReferres),
  # non-default logs are saved without a date
  Report(name: "Top non-defaults", query: getNonDefaults, allTimeOnly: true),
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


proc echoSigns(letter: string = "=", count: int = parenRepeatCount) =
  echo(letter.repeat(count))


proc ask(question: string): string =
  # treat Ctrl+D the same as quitting
  try:
    return readLineFromStdin(question).strip()
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

    echo(fmt"Pick a number from 1 to {max}, or q to go back")


proc showMenu(window: TimeWindow) =
  stdout.resetAttributes()
  setForegroundColor(fgYellow, true)

  echo()
  echoSigns()

  for i, report in reports:
    let note = if report.allTimeOnly: " (all time)" else: ""
    echo(fmt"{i + 1}) {report.name}{note}")

  echo(fmt"w) Change time window (now: {window.name})")
  echo("q) Quit")

  echoSigns()
  stdout.resetAttributes()


proc chooseTimeWindow(current: int): int =
  echo()
  for i, window in timeWindows:
    echo(fmt"{i + 1}) {window.name}")

  let choice = askNumber("Select a time window (q to keep the current one): ", len(timeWindows))
  if choice == 0:
    return current
  return choice - 1


proc showResults(db: DbConn, report: Report, num: uint, window: TimeWindow) =
  let rows = report.query(db, num, since(window))

  stdout.resetAttributes()
  setForegroundColor(fgGreen, true)

  echo()
  echoSigns()

  if len(rows) == 0:
    echo("No records found")

  var count = 1
  for row in rows:
    stdout.styledWriteLine(fgGreen, fmt"{count}) {row[0]} is seen ",
        styleUnderscore, row[1], " times")
    count += 1

  setForegroundColor(fgGreen, true)
  echoSigns()

  setForegroundColor(fgRed, true)
  echoSigns("-")
  stdout.resetAttributes()


proc report*(dbPath: string) =
  # opening a missing database creates an empty one and every query fails
  if not fileExists(dbPath):
    echo(fmt"Database not found at {dbPath}")
    quit(1)

  let db = getDbConnection(dbPath)

  # databases from older versions don't have the index yet
  if not hasDateIndex(db):
    echo("Creating the date index for time window reports, this can take a while on big databases...")
    createTables(db)

  var window = 2 # last 30 days

  while true:
    showMenu(timeWindows[window])

    setForegroundColor(fgBlue, true)
    let choice = ask("Select an option: ")

    if choice == "q":
      break

    if choice == "w":
      window = chooseTimeWindow(window)
      continue

    let option = try: parseInt(choice) except ValueError: 0
    if option < 1 or option > len(reports):
      echo("Pick an option from the menu")
      continue

    let num = askNumber("Number of records to show: ", high(int32))
    if num == 0:
      continue

    showResults(db, reports[option - 1], uint(num), timeWindows[window])

  stdout.resetAttributes()
  closeDbConnection(db)
  quit(0)
