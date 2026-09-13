from std/terminal import setForegroundColor, resetAttributes, styledWriteLine,
    styleUnderscore, fgYellow, fgRed, fgGreen, fgBlue
from logging import info, warn, error
from std/strformat import fmt
from std/strutils import parseUInt, repeat
from std/rdstdin import readLineFromStdin
from db_connector/db_sqlite import DbConn, Row

from database import getDbConnection, closeDbConnection, getTopIPs,
    getTopURIs, getTopUnsuccessfulRequests, getTopReferres, getNonDefaults


const parenRepeatCount = 80

type OptionProc = proc (db: DbConn, num: uint): seq[Row]

# a seq keeps the menu in this order, a Table would not
let options: seq[(string, OptionProc)] = @[
  ("Show top IP addresses", getTopIPs),
  ("Show top URIs", getTopURIs),
  ("Show top unsuccessful requests", getTopUnsuccessfulRequests),
  ("Show top referrers", getTopReferres),
  ("Show top non-defaults", getNonDefaults),
]



proc echoSigns(letter: string = "=", count: int = parenRepeatCount) =
  echo(letter.repeat(count))


proc echoNewlines(count: int = 2) =
  echo("\n".repeat(count))


proc showAvailableOptions() =
  stdout.resetAttributes()
  setForegroundColor(fgYellow, true)

  echoNewlines()
  echoSigns()

  for i, (name, _) in options:
    stdout.write(i + 1, ")", " ", name, "\n")

  echoSigns()
  echoNewlines()

  stdout.resetAttributes()


proc ask(question: string): string =
  # treat Ctrl+D the same as quitting
  try:
    return readLineFromStdin(question)
  except IOError:
    return "q"


proc getUserChoice(): (uint, uint) =
  stdout.resetAttributes()
  setForegroundColor(fgBlue, true)

  echoNewlines()

  let option = ask("Select an option number (q to quit): ")
  if option == "q":
    return (0, 0)

  let num = ask("Select the number of records to query (q to quit): ")
  if num == "q":
    return (0, 0)

  echoNewlines(1)

  try:
    let parsedOption = parseUInt(option)
    let parsedNum = parseUInt(num)

    if parsedOption < 1 or parsedNum < 1:
      error("Option and number should be greater than 0")
      return getUserChoice()

    if parsedOption > uint(len(options)):
      error("Option number is too large... Try again")
      return getUserChoice()

    return (parsedOption, parsedNum)
  except ValueError:
    error("Bad number... Try again")
    return getUserChoice()


proc runQueryFunction(db: DbConn, optionProc: OptionProc, num: uint) =
  stdout.resetAttributes()

  let rows = optionProc(db, num)

  setForegroundColor(fgGreen, true)

  echoNewlines()
  echoSigns()

  var count = 1
  for row in rows:
    stdout.styledWriteLine(fgGreen, fmt"{count}) {row[0]} is seen ",
        styleUnderscore, row[1], " times")
    count += 1

  setForegroundColor(fgGreen, true)

  echoSigns()
  echoNewlines()

  setForegroundColor(fgRed, true)
  echoSigns("-")


proc report*(dbPath: string) =
  info("Entering report mode")

  let db = getDbConnection(dbPath)

  while true:
    showAvailableOptions()

    let (optionNumber, num) = getUserChoice()

    if optionNumber == 0 and num == 0:
      stdout.resetAttributes()
      break

    let option = options[optionNumber - 1][1]
    stdout.resetAttributes()

    runQueryFunction(db, option, num)

  stdout.resetAttributes()

  closeDbConnection(db)
  info("Exiting")

  quit(0)
