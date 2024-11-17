from std/json import JsonNode

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
    report: bool,
    migrateV1ToV2Db: bool,
    v1DbPath: string,
    v2DbPath: string,
  ]


type
  Cidrs* = object
    ipv4*: JsonNode
    ipv6*: JsonNode
    etag*: string
    etagChanged*: bool


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
