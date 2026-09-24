import std/[asyncdispatch, httpcore, json]
from std/httpclient import AsyncHttpClient, AsyncResponse, newAsyncHttpClient, close, get, code, body
from std/strformat import fmt
from std/options import Option, none, some, isSome, get
from std/strutils import startsWith, split
from std/times import getTime, format

from std/os import fileExists
from std/logging import info, error, warn

from nginx import reloadNginx, dateFormat
from nftables import acceptOnly, NftSet


type
  Cidrs* = object
    ipv4*: JsonNode
    ipv6*: JsonNode
    etag*: string


const
  cidrFile* = "/etc/nginx/nginwho" # nginx includes this to trust Cloudflare's real IP header
  apiUrl = "https://api.cloudflare.com/client/v4/ips"
  timeoutMs = 10_000
  refreshMs = 6 * 60 * 60 * 1000


proc parseCidrsResponse*(jsonResponse: JsonNode): Option[Cidrs] =
  let etag: string = jsonResponse{"result", "etag"}.getStr()

  let apiSuccess: bool = jsonResponse{"success"}.getBool()
  if apiSuccess != true:
    warn(fmt"API `success` is not true: {apiSuccess}")
    return none(Cidrs)

  let ipv4Cidrs: JsonNode = jsonResponse{"result", "ipv4_cidrs"}
  let ipv6Cidrs: JsonNode = jsonResponse{"result", "ipv6_cidrs"}

  # an empty list would flush its nftables Set and block all Cloudflare traffic of that IP version
  if ipv4Cidrs.isNil or ipv6Cidrs.isNil or ipv4Cidrs.len == 0 or ipv6Cidrs.len == 0:
    warn("API response is missing IPv4 or IPv6 CIDRs")
    return none(Cidrs)
  else:
    return some(Cidrs(ipv4: ipv4Cidrs, ipv6: ipv6Cidrs, etag: etag))


proc getCloudflareCIDRs(): Future[Option[Cidrs]] {.async.} =
  info("Getting Cloudflare CIDRs")

  let client: AsyncHttpClient = newAsyncHttpClient()
  defer: client.close()

  var jsonResponse: JsonNode

  try:
    let request: Future[AsyncResponse] = client.get(apiUrl)

    if not await request.withTimeout(timeoutMs):
      error(fmt"Call to {apiUrl} timed out")
      return none(Cidrs)

    let response: AsyncResponse = request.read()

    if response.code != Http200:
      error(fmt"Call to {apiUrl} failed")
      return none(Cidrs)

    jsonResponse = parseJson(await response.body)
  except CatchableError as e:
    error(fmt"Call to {apiUrl} failed: {e.msg}")
    return none(Cidrs)

  return parseCidrsResponse(jsonResponse)


proc populateReverseProxyFile*(filePath: string, cidrs: Cidrs): bool =
  info(fmt"Populating CIDRs file in {filePath}")

  let now: string = getTime().format(dateFormat)

  try:
    let file: File = open(filePath, fmWrite)
    defer: file.close()

    file.write("# Cloudflare ranges\n")
    file.write("# Last update: ", now, "\n")
    file.write("# Last etag: ", cidrs.etag, "\n\n")
    file.write("# IPv4 CIDRs\n")

    for cidr in cidrs.ipv4:
      file.write("set_real_ip_from ", cidr.getStr(), ";\n")

    file.write("\n# IPv6 CIDRs\n")

    for cidr in cidrs.ipv6:
      file.write("set_real_ip_from ", cidr.getStr(), ";\n")

    file.write("\n\nreal_ip_header CF-Connecting-IP;\n")
    return true
  except:
    error(fmt"Could not open {filePath}")
    return false


proc getCurrentEtag*(configFile: string = cidrFile): string =
  info("Getting current Cloudflare CIDRs ETAG")

  if not fileExists(configFile):
    error(fmt"{configFile} does not exist")
    return

  for line in lines(configFile):
    if line.startsWith("# Last etag:"):
      let etagLine: seq[string] = line.split("# Last etag: ")
      if len(etagLine) > 1:
        return etagLine[1]


proc fetchAndProcessIPCidrs*(blockUntrustedCidrs: bool = false) {.async.} =
  info("Fetching and processing Cloudflare CIDRs")

  while true:
    let currentEtag: string = getCurrentEtag()
    let cfCIDRs: Option[Cidrs] = await getCloudflareCIDRs()

    case cfCIDRs.isSome:
    of true:
      let cidrs: Cidrs = cfCIDRs.get()

      if blockUntrustedCidrs:
        warn("will block untrusted CIDRs using nftables")
        acceptOnly(NftSet(ipv4: cidrs.ipv4, ipv6: cidrs.ipv6))

      if currentEtag != cidrs.etag:
        # nginx reload is graceful and does not drop open connections
        if populateReverseProxyFile(cidrFile, cidrs):
          reloadNginx()
      else:
        info(fmt"etag has not changed {currentEtag}")
    of false:
      error("Failed fetching CIDRs")

    await sleepAsync(refreshMs)
