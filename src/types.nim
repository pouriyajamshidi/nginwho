type Log* = object
  date*: string
  remoteIP*: string
  httpMethod*: string
  requestURI*: string
  statusCode*: string
  responseSize*: int
  referrer*: string
  userAgent*: string
  nonStandard*: string
  remoteUser*: string
  authenticatedUser*: string


type
  Logs* = seq[Log]

  Args* = tuple[
    logPath: string,
    dbPath: string,
    interval: int,
    omitReferrer: string,
    showRealIPs: bool,
    blockUntrustedCidrs: bool,
    processNginxLogs: bool,
    migrateV1ToV2Db: bool,
    v1DbPath: string,
    v2DbPath: string,
  ]
