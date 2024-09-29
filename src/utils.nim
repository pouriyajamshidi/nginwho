from times import parse, Datetime, format

proc convertDateFormat*(nginxDate: string): string =
  let parsedDate: DateTime = parse(nginxDate, "d-MMM-yyyy:HH:mm:ss")
  return parsedDate.format("yyyy-MM-dd HH:mm:ss")
