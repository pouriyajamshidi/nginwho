import std/[asyncdispatch, httpcore, json]
from std/httpclient import newAsyncHttpClient, close, get, code, body
from std/strformat import fmt
from std/options import Option, none, some, isNone, get
from std/strutils import startsWith, split, join, toHex, capitalizeAscii, parseInt
from std/net import IpAddress, IpAddressFamily, parseIpAddress, isIpAddress
from std/algorithm import sorted
from std/hashes import hash
from std/times import getTime, format

from std/os import fileExists
from std/logging import info, error, warn

from nginx import reloadNginx, dateFormat
from nftables import acceptOnly, NftSet, NftError, validCidrs


type
  Cdn* = enum
    ## The CDN in front of the site. Only one at a time, nginx trusts a single real IP header
    Cloudflare = "cloudflare"
    Fastly = "fastly"

  Cidrs* = object
    cdn*: Cdn
    ipv4*: JsonNode
    ipv6*: JsonNode
    etag*: string


const
  cidrFile* = "/etc/nginx/nginwho" # nginx includes this to trust the CDN's real IP header
  apiUrls: array[Cdn, string] = [
    Cloudflare: "https://api.cloudflare.com/client/v4/ips",
    Fastly: "https://api.fastly.com/public-ip-list"]
  # the header the CDN puts the visitor's IP in
  realIpHeaders*: array[Cdn, string] = [
    Cloudflare: "CF-Connecting-IP",
    Fastly: "Fastly-Client-IP"]
  timeoutMs = 10_000
  refreshMs = 6 * 60 * 60 * 1000
  retryMs = 60 * 1000

# the ranges fetched last. --serve trusts the CDN's real IP header only from these,
# and does not limit how many connections they open
var trustedRanges: seq[tuple[network: IpAddress, bits: int]]


proc name*(cdn: Cdn): string =
  ## "Cloudflare" or "Fastly", for logs and nftables Set names
  capitalizeAscii($cdn)


proc makeEtag(cdn: Cdn, ipv4, ipv6: JsonNode): string =
  ## Fastly's API has no etag, so we make one from the ranges for every CDN.
  ## The order of the ranges does not matter
  var cidrs: seq[string]
  for cidr in ipv4:
    cidrs.add(cidr.getStr())
  for cidr in ipv6:
    cidrs.add(cidr.getStr())
  return toHex(hash($cdn & " " & sorted(cidrs).join(" ")))


proc parseCidrsResponse*(cdn: Cdn, jsonResponse: JsonNode): Option[Cidrs] =
  var ipv4Cidrs, ipv6Cidrs: JsonNode

  case cdn
  of Cloudflare:
    let apiSuccess = jsonResponse{"success"}.getBool()
    if not apiSuccess:
      warn(fmt"API `success` is not true: {apiSuccess}")
      return none(Cidrs)
    ipv4Cidrs = jsonResponse{"result", "ipv4_cidrs"}
    ipv6Cidrs = jsonResponse{"result", "ipv6_cidrs"}
  of Fastly:
    ipv4Cidrs = jsonResponse{"addresses"}
    ipv6Cidrs = jsonResponse{"ipv6_addresses"}

  # an empty list would flush its nftables Set and block all CDN traffic of that IP version
  if ipv4Cidrs.isNil or ipv6Cidrs.isNil or ipv4Cidrs.len == 0 or
      ipv6Cidrs.len == 0:
    warn("API response is missing IPv4 or IPv6 CIDRs")
    return none(Cidrs)
  else:
    return some(Cidrs(cdn: cdn, ipv4: ipv4Cidrs, ipv6: ipv6Cidrs,
        etag: makeEtag(cdn, ipv4Cidrs, ipv6Cidrs)))


proc getCdnCIDRs(cdn: Cdn): Future[Option[Cidrs]] {.async.} =
  info(fmt"Getting {cdn.name} CIDRs")

  let apiUrl = apiUrls[cdn]
  let client = newAsyncHttpClient()
  defer: client.close()

  var jsonResponse: JsonNode

  try:
    let request = client.get(apiUrl)

    if not await request.withTimeout(timeoutMs):
      error(fmt"Call to {apiUrl} timed out")
      return none(Cidrs)

    let response = request.read()

    if response.code != Http200:
      error(fmt"Call to {apiUrl} failed")
      return none(Cidrs)

    jsonResponse = parseJson(await response.body)
  except CatchableError as e:
    error(fmt"Call to {apiUrl} failed: {e.msg}")
    return none(Cidrs)

  return parseCidrsResponse(cdn, jsonResponse)


proc populateReverseProxyFile*(filePath: string, cidrs: Cidrs): bool =
  info(fmt"Populating CIDRs file in {filePath}")

  let now = getTime().format(dateFormat)

  try:
    let file = open(filePath, fmWrite)
    defer: file.close()

    file.write("# ", cidrs.cdn.name, " ranges\n")
    file.write("# Last update: ", now, "\n")
    file.write("# Last etag: ", cidrs.etag, "\n\n")
    file.write("# IPv4 CIDRs\n")

    for cidr in cidrs.ipv4:
      file.write("set_real_ip_from ", cidr.getStr(), ";\n")

    file.write("\n# IPv6 CIDRs\n")

    for cidr in cidrs.ipv6:
      file.write("set_real_ip_from ", cidr.getStr(), ";\n")

    file.write("\n\nreal_ip_header ", realIpHeaders[cidrs.cdn], ";\n")
    return true
  except IOError as e:
    error(fmt"Could not write {filePath}: {e.msg}")
    return false


proc trustRanges*(cidrs: Cidrs) =
  ## Replaces the ranges `visitorIP` trusts
  var ranges: seq[tuple[network: IpAddress, bits: int]]
  for list in [cidrs.ipv4, cidrs.ipv6]:
    # the same check as for nftables. a prefix length past the address would crash fromCdn
    for cidr in validCidrs(list):
      let parts = cidr.split('/')
      ranges.add((parseIpAddress(parts[0]), parseInt(parts[1])))
  trustedRanges = ranges


proc samePrefix(a, b: openArray[uint8], bits: int): bool =
  for i in 0 ..< bits:
    let mask = 0x80'u8 shr (i mod 8)
    if (a[i div 8] and mask) != (b[i div 8] and mask):
      return false
  return true


proc fromCdn*(ip: string): bool =
  ## Whether `ip` is in the CDN's ranges. False until the ranges are fetched
  if not isIpAddress(ip):
    return false
  let address = parseIpAddress(ip)
  for (network, bits) in trustedRanges:
    if address.family != network.family:
      continue
    if address.family == IpAddressFamily.IPv4:
      if samePrefix(address.address_v4, network.address_v4, bits): return true
    elif samePrefix(address.address_v6, network.address_v6, bits): return true


proc visitorIP*(peer, headerIP: string): string =
  ## The visitor's IP for a request from `peer` carrying `headerIP` in the CDN's real IP
  ## header. Anyone can send that header, so it only counts when the CDN sent the request
  if headerIP != "" and isIpAddress(headerIP) and fromCdn(peer):
    return headerIP
  return peer


proc getCurrentEtag*(configFile: string = cidrFile): string =
  info("Getting current CIDRs ETAG")

  if not fileExists(configFile):
    error(fmt"{configFile} does not exist")
    return

  for line in lines(configFile):
    if line.startsWith("# Last etag:"):
      let etagLine = line.split("# Last etag: ")
      if etagLine.len > 1:
        return etagLine[1]


proc fetchAndProcessIPCidrs*(cdn: Cdn, showRealIPs,
    blockUntrustedCidrs, serve: bool) {.async.} =
  ## Fetches the CDN's ranges every six hours. `showRealIPs` writes them for nginx.
  ## With `serve` our own server knows the CDN by them.
  ## `blockUntrustedCidrs` lets only them through nftables. Each works without the other
  info(fmt"Fetching and processing {cdn.name} CIDRs")

  while true:
    let fetched = await getCdnCIDRs(cdn)
    if fetched.isNone:
      # try again soon, a boot without network should not leave the firewall open for six hours
      error("Failed fetching CIDRs, trying again in a minute")
      await sleepAsync(retryMs)
      continue

    let cidrs = fetched.get()

    if blockUntrustedCidrs:
      try:
        acceptOnly(NftSet(name: cdn.name, ipv4: cidrs.ipv4, ipv6: cidrs.ipv6))
      except NftError as e:
        # a firewall problem must not stop the real IPs or anything else nginwho runs
        error(e.msg)

    if serve:
      trustRanges(cidrs)
    elif showRealIPs:
      let currentEtag = getCurrentEtag()
      if currentEtag != cidrs.etag:
        # nginx reload is graceful and does not drop open connections
        if populateReverseProxyFile(cidrFile, cidrs):
          reloadNginx()
      else:
        info(fmt"etag has not changed {currentEtag}")

    await sleepAsync(refreshMs)
