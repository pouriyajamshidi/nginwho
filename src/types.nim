from std/json import JsonNode

type
  TrapConfig* = object
    enabled*: bool
    port*: int
    maxConnections*: int
    maxSeconds*: int
    dripMinMs*: int
    dripMaxMs*: int
    bombs*: bool
    bombAfter*: int # trapped hits from one IP in a day before it gets a bomb

  TrapHit* = object
    date*: string
    remoteIP*: string
    httpMethod*: string
    requestURI*: string
    userAgent*: string
    trap*: string   # what they were looking for
    tactic*: string # what we did to them
    bytesSent*: int
    seconds*: int
    detail*: string # the fake secret we handed out, or the credentials they tried


type Log* = object
  date*: string
  remoteIP*: string
  httpMethod*: string
  requestURI*: string
  statusCode*: string
  responseSize*: string
  referrer*: string
  userAgent*: string
  nonDefault*: string
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
    serve: bool,
    root: string,
    port: int,
    report: bool,
    migrateV1ToV2Db: bool,
    v1DbPath: string,
    v2DbPath: string,
    trap: TrapConfig,
  ]


type
  Cidrs* = object
    ipv4*: JsonNode
    ipv6*: JsonNode
    etag*: string


type
  SetType* = enum
    IPv4 = "ipv4_addr"
    IPv6 = "ipv6_addr"

  IPProtocol* = enum
    IPv4 = "ip"
    IPv6 = "ip6"


type
  NftSet* = object
    ipv4*: JsonNode
    ipv6*: JsonNode


type
  NftAttrs* = object
    withCloudflareV4Set*: bool
    withCloudflareV6Set*: bool
    withNginwhoChain*: bool
    withNginwhoIPv4Policy*: bool
    withNginwhoIPv6Policy*: bool
    withInputChain*: bool
    withInputPolicy*: bool
