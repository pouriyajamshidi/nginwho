import std/[asyncdispatch, httpclient, json, strformat, options, strutils, times]

from os import fileExists
from logging import info, error, warn, fatal

import consts
from nginx import reloadNginx
from nftables import acceptOnly


type
  Cidrs = object
    ipv4: JsonNode
    ipv6: JsonNode
    etag: string
    etagChanged: bool


proc reloadNginxAt(hour: int = 3, minute: int = 0) {.async.} =
  info(fmt"Preparing to soft-reload nginx at {hour}:{minute}")

  while true:
    let now: DateTime = getTime().local()
    if now.hour == hour and now.minute == minute:
      reloadNginx()

    await sleepAsync(ONE_MINUTE)


proc populateReverseProxyFile(filePath: string, cidrs: Cidrs): bool =
  info(fmt"Populating CIDRs file in {filePath}")

  let now: string = getTime().format(DATE_FORMAT)

  if cidrs.etagChanged:
    try:
      let file: File = open(filePath, fmWrite)
      defer: file.close()

      file.write("# Cloudflare ranges\n")
      file.write("# Last update: ", now, "\n")
      file.write("# Last etag: ", cidrs.etag, "\n\n")
      file.write("# IPv4 CIDRs\n")

      for cidr in cidrs.ipv4:
        file.write(NGINX_SET_REAL_IP_FROM, " ", cidr.getStr(), ";", "\n")

      file.write("\n# IPv6 CIDRs\n")

      for cidr in cidrs.ipv6:
        file.write(NGINX_SET_REAL_IP_FROM, " ", cidr.getStr(), ";", "\n")

      file.write("\n\n", NGINX_REAL_IP_HEADER, " ", NGINX_CF_REAL_IP_HEADER, "\n")
      return true
    except:
      error(fmt"Could not open {filePath}")
      return false


proc getCloudflareCIDRs(): Option[Cidrs] =
  info("Getting Cloudflare CIDRs")

  let client: HttpClient = newHttpClient()
  let response: Response = client.get(CLOUDFLARE_CIDR_API_URL)

  if response.code != Http200:
    error(fmt"Call to {CLOUDFLARE_CIDR_API_URL} failed")
    return none(Cidrs)

  let jsonResponse: JsonNode = parseJson(response.body)

  let etag: string =  jsonResponse["result"]["etag"].getStr()
  
  let apiSuccess: bool =  jsonResponse["success"].getBool()
  if apiSuccess != true:
    warn(fmt"API `success` is not true: {apiSuccess}")
    return none(Cidrs)
  
  let ipv4Cidrs: JsonNode =  jsonResponse["result"]["ipv4_cidrs"]
  let ipv6Cidrs: JsonNode = jsonResponse["result"]["ipv6_cidrs"]

  if ipv4Cidrs.isNil or ipv6Cidrs.isNil:
    return none(Cidrs)
  else:
    return some(Cidrs(ipv4: ipv4Cidrs, ipv6: ipv6Cidrs, etag: etag, etagChanged: true))


proc getCurrentEtag(configFile: string=NGINX_CIDR_FILE): string = 
  info("Getting current Cloudflare CIDRs ETAG")

  if not fileExists(configFile):
    error(fmt"{configFile} does not exist")
    return

  for line in lines(configFile):
    if line.startsWith("# Last etag:"):
      let etagLine: seq[string] = line.split("# Last etag: ")
      if len(etagLine) > 1:
        return etagLine[1]


proc fetchAndProcessIPCidrs*(blockUntrustedCidrs: bool=false) {.async.} =
  info("Fetching and processing Cloudflare CIDRs")

  if blockUntrustedCidrs:
    warn("will block untrusted CIDRs using nftables")

  while true:
    let currentEtag: string = getCurrentEtag()
    let cfCIDRs: Option[Cidrs] = getCloudflareCIDRs()

    case cfCIDRs.isSome:
    of true:
      let cidrs: Cidrs = cfCIDRs.get()
      
      if blockUntrustedCidrs:
        acceptOnly(cidrs.ipv4)
        
      if currentEtag != cidrs.etag:
        if populateReverseProxyFile(NGINX_CIDR_FILE, cidrs):
          waitFor reloadNginxAt()
      else:
          info(fmt"etag has not changed {currentEtag}")
    of false:
      error("Failed fetching CIDRs")

    await sleepAsync(SIX_HOURS)

