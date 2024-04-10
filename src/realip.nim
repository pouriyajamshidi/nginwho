import std/[asyncdispatch, httpclient, json, strformat, options, strutils]
include consts, nginx, filter



type
  IPCidrs* = object
    ipv4: JsonNode
    ipv6: JsonNode
    etag: string
    etagChanged: bool


proc reloadNginxAt(hour: int = 3, minute: int = 0) {.async.} =
  while true:
    let now: DateTime = getTime().local()
    if now.hour == hour and now.minute == minute:
      let testResult: int = testNginxConfig()
      if testResult != 0:
        echo fmt"{now} - nginx configuration test failed"
        continue

      reloadNginx()

    await sleepAsync(ONE_MINUTE)


proc populateReverseProxyFile(filePath: string=DEFAULT_OUTPUT_PATH, ipCidr: IPCidrs): bool =
  let now: string = getTime().format("yyyy-MM-dd HH:mm:ss")
  echo fmt"{now} - Populating CIDRs file in {filePath}"

  if ipCidr.etagChanged:
    try:
      let file: File = open(filePath, fmWrite)
      defer: file.close()

      file.write("# Cloudflare ranges\n")
      file.write("# Last update: ", now, "\n")
      file.write("# Last etag: ", ipCidr.etag, "\n\n")
      file.write("# IPv4 CIDRs\n")

      for cidr in ipCidr.ipv4:
        file.write(CFG_SET_REAL_IP_FROM, " ", cidr.getStr(), ";", "\n")

      file.write("\n# IPv6 CIDRs\n")

      for cidr in ipCidr.ipv6:
        file.write(CFG_SET_REAL_IP_FROM, " ", cidr.getStr(), ";", "\n")

      file.write("\n\n", CFG_REAL_IP_HEADER, " ", CF_REAL_IP_HEADER, "\n")
      return true
    except:
      echo fmt"{now} - Could not open {filePath}"
      return false


proc getCloudflareCIDRs(): Option[IPCidrs] =
  let now: string = getTime().format("yyyy-MM-dd HH:mm:ss")
  echo fmt"{now} - Getting Cloudflare CIDRs"

  let client: HttpClient = newHttpClient()
  let response: Response = client.get(CF_IP_API)

  if response.code != Http200:
    echo fmt"{now} - API call to {CF_IP_API} failed"
    return none(IPCidrs)

  let jsonResponse: JsonNode = parseJson(response.body)

  let etag: string =  jsonResponse["result"]["etag"].getStr()
  
  let apiSuccess: bool =  jsonResponse["success"].getBool()
  if apiSuccess != true:
    echo fmt"{now} - API `success` is not true: {apiSuccess}"
    return none(IPCidrs)
  
  let ipv4Cidrs: JsonNode =  jsonResponse["result"]["ipv4_cidrs"]
  let ipv6Cidrs: JsonNode = jsonResponse["result"]["ipv6_cidrs"]

  if ipv4Cidrs.isNil or ipv6Cidrs.isNil:
    return none(IPCidrs)
  else:
    return some(IPCidrs(ipv4: ipv4Cidrs, ipv6: ipv6Cidrs, etag: etag, etagChanged: true))


proc getCurrentEtag(configFile: string=DEFAULT_OUTPUT_PATH): string = 
  let now: string = getTime().format("yyyy-MM-dd HH:mm:ss")

  if not fileExists(configFile):
    echo fmt"{now} - {configFile} does not exist"
    return

  for line in lines(configFile):
    if line.startsWith("# Last etag:"):
      let etagLine: seq[string] = line.split("# Last etag: ")
      if len(etagLine) > 1:
        return etagLine[1]


proc fetchAndProcessIPCidrs(blockUntrustedCidrs: bool=false) {.async.} =
  let now: string = getTime().format("yyyy-MM-dd HH:mm:ss")

  while true:
    let currentEtag: string = getCurrentEtag()
    let cfCIDRs: Option[IPCidrs] = getCloudflareCIDRs()

    case cfCIDRs.isSome:
    of true:
      let cidrs: IPCidrs = cfCIDRs.get()
      if currentEtag != cidrs.etag:
        if populateReverseProxyFile(ipCidr=cidrs):
          filter(cidrs)
          waitFor reloadNginxAt()
      else:
          echo fmt"{now} - etag has not changed {currentEtag}"
    of false:
      echo fmt"{now} - Failed fetching CIDRs"

    await sleepAsync(SIX_HOURS)

