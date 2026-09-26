import std/[asyncdispatch, httpcore, json]
from std/httpclient import AsyncHttpClient, AsyncResponse, newAsyncHttpClient,
    close, get, code, body
from std/strformat import fmt
from std/options import Option, none, some, isNone, get
from std/strutils import startsWith, split, join, toHex, capitalizeAscii
from std/algorithm import sorted
from std/hashes import hash
from std/times import getTime, format

from std/os import fileExists
from std/logging import info, error, warn

from nginx import reloadNginx, dateFormat
from nftables import acceptOnly, NftSet, NftError


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
  realIpHeaders: array[Cdn, string] = [
    Cloudflare: "CF-Connecting-IP",
    Fastly: "Fastly-Client-IP"]
  timeoutMs = 10_000
  refreshMs = 6 * 60 * 60 * 1000
  retryMs = 60 * 1000


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
    let apiSuccess: bool = jsonResponse{"success"}.getBool()
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

  return parseCidrsResponse(cdn, jsonResponse)


proc populateReverseProxyFile*(filePath: string, cidrs: Cidrs): bool =
  info(fmt"Populating CIDRs file in {filePath}")

  let now: string = getTime().format(dateFormat)

  try:
    let file: File = open(filePath, fmWrite)
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


proc getCurrentEtag*(configFile: string = cidrFile): string =
  info("Getting current CIDRs ETAG")

  if not fileExists(configFile):
    error(fmt"{configFile} does not exist")
    return

  for line in lines(configFile):
    if line.startsWith("# Last etag:"):
      let etagLine: seq[string] = line.split("# Last etag: ")
      if len(etagLine) > 1:
        return etagLine[1]


proc fetchAndProcessIPCidrs*(cdn: Cdn, showRealIPs,
    blockUntrustedCidrs: bool) {.async.} =
  ## Fetches the CDN's ranges every six hours. `showRealIPs` writes them for nginx and
  ## `blockUntrustedCidrs` lets only them through nftables. Each works without the other
  info(fmt"Fetching and processing {cdn.name} CIDRs")

  while true:
    let fetched: Option[Cidrs] = await getCdnCIDRs(cdn)
    if fetched.isNone:
      # try again soon, a boot without network should not leave the firewall open for six hours
      error("Failed fetching CIDRs, trying again in a minute")
      await sleepAsync(retryMs)
      continue

    let cidrs: Cidrs = fetched.get()

    if blockUntrustedCidrs:
      try:
        acceptOnly(NftSet(name: cdn.name, ipv4: cidrs.ipv4, ipv6: cidrs.ipv6))
      except NftError as e:
        # a firewall problem must not stop the real IPs or anything else nginwho runs
        error(e.msg)

    if showRealIPs:
      let currentEtag: string = getCurrentEtag()
      if currentEtag != cidrs.etag:
        # nginx reload is graceful and does not drop open connections
        if populateReverseProxyFile(cidrFile, cidrs):
          reloadNginx()
      else:
        info(fmt"etag has not changed {currentEtag}")

    await sleepAsync(refreshMs)
