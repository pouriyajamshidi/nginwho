from std/times import parse, DateTime, format
from std/strutils import endsWith

proc convertDateFormat*(nginxDate: string): string =
  let parsedDate: DateTime = parse(nginxDate, "d-MMM-yyyy:HH:mm:ss")
  return parsedDate.format("yyyy-MM-dd HH:mm:ss")


proc isStaticAsset*(requestURI: string): bool =
  ## Fonts, scripts and styles are not stored, they only add noise
  # TODO: Decide whether to exclude these or not
  requestURI.endsWith(".woff2") or requestURI.endsWith(".js") or requestURI.endsWith(".css")
