import std/[asyncdispatch, os, strformat, json]

from strutils import split, parseInt, isDigit, join, replace, repeat
from algorithm import sort, sorted
from json import parseFile
from logging import info, error, warn, fatal
from osproc import execProcess, execCmd
from net import parseIpAddress, IpAddressFamily

import consts


proc applyRules(fileName: string=NFT_CIDR_RULES_FILE) =
  info("Applying nftables rules")

  let res: int = execCmd(fmt"nft -j -f {filename}")
  if res != 0:
    error("Failed applying nftables rules - Are you root?")
    quit(1)
  else:
    info("Successfully applied nftables rules")


proc writeRules(fileName: string=NFT_CIDR_RULES_FILE, rules: JsonNode) =
  info(fmt"Writing nginwho rules to {fileName}")

  try:
    writeFile(fileName, rules.pretty())
    info(fmt"Successfully wrote nginwho rules to {fileName}")
  except Exception as e:
    error(fmt"Failed writing nginwho rules to {fileName}: {e.msg}")


proc createChain(): JsonNode =
  info("Creating nginwho chain")

  return %* {
    "add": {
      "chain": {
        "family": "inet",
        "table": "filter",
        "name": "nginwho",
        "handle": 4,
        "type": "filter",
        "hook": "prerouting",
        "prio": -10,
        "policy": "accept"
      }
    }
  }


proc createSet(cidrs: JsonNode): JsonNode =
  info("Creating IPv4 set")

  var ipSet: JsonNode = %* {
    "add": {
      "set": {
        "family": "inet",
        "name": NFT_SET_NAME_CF_IPv4,
        "table": "filter",
        "type": "ipv4_addr",
        "handle": 50,
        "flags": [
            "interval"
        ],
        "elem": []
      }
    }
  }

  for cidr in cidrs:
    let ipAndPrefixLen: seq[string] =  cidr.getStr().split("/")

    ipSet["add"]["set"]["elem"].add(%*{
      "prefix": {
        "addr": ipAndPrefixLen[0],
        "len": parseInt(ipAndPrefixLen[1])
        }
      }
    )

  return ipSet


proc createRules(family: string, cidrs: JsonNode): JsonNode =
  info(fmt"Creating nginwho rules for {family} family")

  var rules: JsonNode = %* {
    "nftables": [
      createChain(),
      createSet(cidrs),
      {
        "add": {
          "rule": {
            "family": family,
            "table": "filter",
            "chain": "nginwho",
            "handle": 1,
            "expr": [{ "log": { "prefix": "NGINWHO_DROPPED " } }]
          }
        }
      },
      {
        "add": {
          "rule": {
            "family": family,
            "table": "filter",
            "chain": "nginwho",
            "handle": 2,
            "expr": [
              {
                "match": {
                  "op": "!=",
                  "left": { "payload": { "protocol": "ip", "field": "saddr" } },
                  "right": fmt"@{NFT_SET_NAME_CF_IPv4}"
                }
              },
              {
                "match": {
                  "op": "==",
                  "left": { "payload": { "protocol": "tcp", "field": "dport" } },
                  "right": { "set": [80, 443] }
                }
              },
              { "counter": { "packets": 0, "bytes": 0 } },
              { "drop": newJNull() }
            ]
          }
        }
      },
      {
        "add": {
          "rule": {
            "family": family,
            "table": "filter",
            "chain": "input",
            "handle": 1,
            "expr": [
              {
                "match": {
                  "op": "==",
                  "left": { "payload": { "protocol": "tcp", "field": "dport" } },
                  "right": { "set": [80, 443] }
                }
              },
              { "counter": { "packets": 0, "bytes": 0 } },
              { "accept": newJNull() }
            ]
          }
        }
      }
    ]
  }

  return rules


proc nginwhoChainHasPolicy(nftOutput: JsonNode): bool =
  info("Checking nftables nginwho chain for existing policy")

  for element in 0..nftOutput.len() - 1:
    if not nftOutput[element].contains("rule"):
      continue
    
    let chainName = nftOutput[element]["rule"]["chain"].getStr()
    if chainName != NFT_CHAIN_NAME:
      continue

    let expression = nftOutput[element]["rule"]["expr"]
    if expression.len() < 4:
      continue

    let destination = expression[0]["match"]["right"].getStr()
    let service = expression[1]["match"]["right"]["set"].getElems()

    if destination == fmt"@{NFT_SET_NAME_CF_IPv4}" and
      service.len() == 2 and
      service[0].getInt() == 80 and
      service[1].getInt() == 443:
      info("nginwho chain already has the required policy")
      return true

  warn(fmt"{NFT_CHAIN_NAME} does not exist")


proc nginwhoChainExists(nftOutput: JsonNode): bool =
  info("Checking nftables nginwho chain existence")

  for element in 0..nftOutput.len() - 1:
    if nftOutput[element].contains("chain"):
      if nftOutput[element]["chain"]["name"].getStr() == NFT_CHAIN_NAME:
        info(fmt"Found {NFT_CHAIN_NAME} nftables chain")
        return true

  warn(fmt"{NFT_CHAIN_NAME} does not exist")


proc cloudflareSetChanged(nftOutput: JsonNode, newCidrs: JsonNode): bool =
  info("Checking nftables Cloudflare Set for changes")

  var currentSets = newSeq[string]()

  for element in 0..nftOutput.len() - 1:
    if not nftOutput[element].contains("set"):
      continue
    if nftOutput[element]["set"]["name"].getStr() == NFT_SET_NAME_CF_IPv4:
      for elem in nftOutput[element]["set"]["elem"]:
        var address = elem["prefix"]["addr"].getStr()
        var length = elem["prefix"]["len"].getInt()
        let addressAndLen = fmt"{address}/{length}"
        currentSets.add(addressAndLen)

  if sorted(currentSets) == sorted(newCidrs.to(seq[string])):
    info("Cloudflare Set has not changed")
    return false

  info("Cloudflare Set has changed")
  return true


proc cloudflareSetExists(nftOutput: JsonNode, tableName: string="inet"): bool =
  info("Checking Cloudflare nftables set existence")

  for element in 0..nftOutput.len() - 1:
    if nftOutput[element].contains("set"):
      if nftOutput[element]["set"]["family"].getStr() == tableName:
        info("Found Cloudflare's nftables set")
        return true

  warn(fmt"{NFT_SET_NAME_CF_IPv4} does not exist")


proc fetchCidrsFrom(fileName: string=NGINX_CIDR_FILE): JsonNode = 
  info(fmt"Fetching CIDRs from {fileName}")

  if not fileExists(fileName):
    error(fmt"{fileName} does not exist")
    quit(1)
  
  var cidrs: seq[string] = @[]

  for line in lines(fileName):
    if line.len() == 0:
      continue
    
    let splitLine = line.split(" ")
    if splitLine.len() < 2 or splitLine.len() > 2:
      continue

    if splitLine[1][0].isDigit():
      let ipAndMask = splitLine[1].replace(";", "")
      let ipAddr = parseIpAddress(ipAndMask.split("/")[0])
      # TODO: Add IPv6 support
      if ipAddr.family == IpAddressFamily.IPv6:
        continue
      cidrs.add($ipAndMask)
  
  if cidrs.len() == 0:
    error(fmt"No CIDRs found")
    quit(1)

  return %* cidrs


proc inetFilterExists(nftOutput: JsonNode): bool =
  info("Checking nftables inet filter table existence")

  try:
    for idx in 0..nftOutput.len() - 1:
      if nftOutput[idx].contains("table"):
        let tableFamily: string = nftOutput[idx]["table"]["family"].getStr()
        # if tableFamily notin ["inet", "ip"]:
        if tableFamily != "inet":
          continue
        info(fmt"Found table inet filter family: `{tableFamily}`")
        return true
  except Exception as e:
    error(fmt"Failed checking `inet` table existence: {e.msg}")


proc getCurrentRules(configFile: string=""): JsonNode = 
  # TODO: we do not need to get configFile or to parse files
  # we only care about the `else` part of this function - remove after tests
  if configFile == NFT_CONFIG_FILE_PATH or configFile == TEMP_NFT_FILE_PATH:
    info(fmt"Getting nftables rules from {configFile}")

    if not fileExists(configFile):
      warn(fmt"{configFile} does not exist")
      return

    try:
      return parseFile(configFile)
    except Exception as e:
      error(fmt"Failed parsing JSON: {e.msg}")
      return
  else:
    info(fmt"Getting nftables rules using `{NFT_GET_RULESET_CMD}`")
    try:
      return parseJson(execProcess(NFT_GET_RULESET_CMD))
    except Exception as e:
      error(fmt"Failed parsing JSON: {e.msg}")


proc writeRulesAndApply(rules: JsonNode) =
  writeRules(rules=rules)
  applyRules()


proc ensureNftExists() = 
  info("Checking existence of nftables")

  let result: string = findExe("nft")

  if result == "":
    fatal("nftables command not found")
    quit(1)
    

proc runPrechecks(cidrs: JsonNode) =
  info("Running nftables pre-checks")
  
  ensureNftExists()
  
  # let nftOutput: JsonNode = getCurrentRules(TEMP_NFT_FILE_PATH)[NFT_CMD]
  let nftOutput: JsonNode = getCurrentRules()[NFT_CMD]

  if not inetFilterExists(nftOutput):
    error("No `inet` nftables filter found - please create it manually like:\n\n",  fmt"{NFT_SAMPLE_POLICY}")
    quit(1)
  
  discard nginwhoChainExists(nftOutput)
  if cloudflareSetExists(nftOutput):
    discard cloudflareSetChanged(nftOutput, cidrs)
  discard nginwhoChainHasPolicy(nftOutput)

  quit(0)


proc acceptOnly*(cidrs: JsonNode) = 
  if cidrs.len() != 0:
    runPrechecks(cidrs)
    let rules: JsonNode = createRules("inet", cidrs)
    writeRulesAndApply(rules)
  else:
    warn("Received empty CIDRs")


proc acceptOnly*(path: string) {.async.} = 
  let cidrs: JsonNode = fetchCidrsFrom(path)
  runPrechecks(cidrs)

  let rules: JsonNode = createRules("inet", cidrs)
  writeRulesAndApply(rules)

  await sleepAsync(SIX_HOURS)