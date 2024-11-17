import std/tables

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

var optionMapping = newTable[string, OptionProc]()

optionMapping["Show top IP addresses"] = getTopIPs
optionMapping["Show top URIs"] = getTopURIs
optionMapping["Show top unsuccessful requests"] = getTopUnsuccessfulRequests
optionMapping["Show top referrers"] = getTopReferres
optionMapping["Show top non-defaults"] = getNonDefaults



proc echoSigns(letter: string = "=", count: int = parenRepeatCount) =
  echo(letter.repeat(count))


proc echoNewlines(count: int = 2) =
  echo("\n".repeat(count))


proc showAvailableOptions() =
  stdout.resetAttributes()
  setForegroundColor(fgYellow, true)

  echoNewlines()
  echoSigns()

  var counter = 1
  for option, _ in optionMapping:
    stdout.write(counter, ")", " ", option, "\n")
    counter += 1

  echoSigns()
  echoNewlines()

  stdout.resetAttributes()


proc getUserChoice(): (uint, uint) =
  stdout.resetAttributes()
  setForegroundColor(fgBlue, true)

  echoNewlines()

  let option = readLineFromStdin("Select an option number (q to quit): ")
  let num = readLineFromStdin("Select the number of records to query (q to quit): ")
  if option == "q" or num == "q":
    return (0, 0)

  echoNewlines(1)

  try:
    let parsedOption = parseUInt(option)
    let parsedNum = parseUInt(num)

    if parsedOption < 1 or parsedNum < 1:
      error("Option and number should be greater than 0")
      return getUserChoice()

    if parsedOption > uint(len(optionMapping)):
      error("Option number is too large... Try again")
      return getUserChoice()

    return (parsedOption, parsedNum)
  except ValueError:
    error("Bad number... Try again")
    return getUserChoice()


proc mapNumToKey(num: uint): OptionProc =
  var counter = 0
  for k, v in optionMapping:
    if num - 1 == uint(counter):
      return optionMapping[k]
    counter += 1


proc runQueryFunction(option: OptionProc, db: DbConn, num: uint) =
  stdout.resetAttributes()

  let rows = option(db, num)

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

    let option = mapNumToKey(optionNumber)
    stdout.resetAttributes()

    runQueryFunction(option, db, num)

  stdout.resetAttributes()
  info("Exiting")
  closeDbConnection(db)
  quit(0)
