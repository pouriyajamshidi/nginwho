import std/[asyncdispatch, httpclient, json, strformat, options, strutils]

from os import fileExists
from logging import info, error, warn, fatal

import consts
from nginx import reloadNginxAt, populateReverseProxyFile
from nftables import acceptOnly
from types import Cidrs, NftSet



proc getCloudflareCIDRs(): Option[Cidrs] =
  info("Getting Cloudflare CIDRs")

  let client: HttpClient = newHttpClient()
  let response: Response = client.get(CLOUDFLARE_CIDR_API_URL)

  if response.code != Http200:
    error(fmt"Call to {CLOUDFLARE_CIDR_API_URL} failed")
    return none(Cidrs)

  let jsonResponse: JsonNode = parseJson(response.body)

  let etag: string = jsonResponse["result"]["etag"].getStr()

  let apiSuccess: bool = jsonResponse["success"].getBool()
  if apiSuccess != true:
    warn(fmt"API `success` is not true: {apiSuccess}")
    return none(Cidrs)

  let ipv4Cidrs: JsonNode = jsonResponse["result"]["ipv4_cidrs"]
  let ipv6Cidrs: JsonNode = jsonResponse["result"]["ipv6_cidrs"]

  if ipv4Cidrs.isNil or ipv6Cidrs.isNil:
    return none(Cidrs)
  else:
    return some(Cidrs(ipv4: ipv4Cidrs, ipv6: ipv6Cidrs, etag: etag,
        etagChanged: true))


proc getCurrentEtag(configFile: string = NGINX_CIDR_FILE): string =
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
    let cfCIDRs: Option[Cidrs] = getCloudflareCIDRs()

    case cfCIDRs.isSome:
    of true:
      let cidrs: Cidrs = cfCIDRs.get()

      if blockUntrustedCidrs:
        warn("will block untrusted CIDRs using nftables")
        acceptOnly(NftSet(ipv4: cidrs.ipv4, ipv6: cidrs.ipv6))

      if currentEtag != cidrs.etag:
        if populateReverseProxyFile(NGINX_CIDR_FILE, cidrs):
          waitFor reloadNginxAt(3, 0)
      else:
        info(fmt"etag has not changed {currentEtag}")
    of false:
      error("Failed fetching CIDRs")

    await sleepAsync(SIX_HOURS)
