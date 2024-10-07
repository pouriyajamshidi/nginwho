from std/times import parse, Datetime, format, epochTime
from std/strutils import formatFloat
from std/strformat import fmt

proc convertDateFormat*(nginxDate: string): string =
  let parsedDate: DateTime = parse(nginxDate, "d-MMM-yyyy:HH:mm:ss")
  return parsedDate.format("yyyy-MM-dd HH:mm:ss")


template benchmark*(benchmarkName: string, code: untyped) =
  block:
    let start = epochTime()
    code
    let elapsed = epochTime() - start
    let elapsedStr = elapsed.formatFloat(format = ffDecimal, precision = 3)
    echo(fmt"Elapsed time: [ {benchmarkName} ] {elapsedStr}s")

