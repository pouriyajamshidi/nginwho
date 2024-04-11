import std/[asyncdispatch, os, strformat, json]

from strutils import split, parseInt, isDigit, join, replace
from json import parseFile
from logging import addHandler, newConsoleLogger, ConsoleLogger, info, error, warn, fatal
from osproc import execProcess, execCmd
from net import parseIpAddress, IpAddressFamily

import consts

from logging import addHandler, newConsoleLogger, ConsoleLogger, info, error, warn, fatal

var logger: ConsoleLogger = newConsoleLogger(fmtStr="[$date -- $time] - $levelname: ")
# addHandler(logger)


var cfElements: seq[string] = @[
  "103.21.244.0/22",
  "103.22.200.0/22",
  "103.31.4.0/22",
  "104.16.0.0/13",
  "104.24.0.0/14",
  "108.162.192.0/18",
  "131.0.72.0/22",
  "141.101.64.0/18",
  "162.158.0.0/15",
  "172.64.0.0/13",
  "173.245.48.0/20",
  "188.114.96.0/20",
  "190.93.240.0/20",
  "197.234.240.0/22",
  "198.41.128.0/17",
  "127.0.0.1/32",
]


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
        "name": "CF_CDN_EDGE",
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

  var rules = %* {
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
            "expr": [
              {
                "match": {
                  "op": "in",
                  "left": {
                    "ct": {
                      "key": "state"
                    }
                  },
                  "right": [
                    "established",
                    "related"
                  ]
                }
              },
              {
                "accept": newJNull()
              }
            ]
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
                  "op": "==",
                  "left": {
                    "payload": {
                      "protocol": "ip",
                      "field": "saddr"
                    }
                  },
                  "right": "@CF_CDN_EDGE"
                }
              },
              {
                "match": {
                  "op": "==",
                  "left": {
                    "payload": {
                      "protocol": "tcp",
                      "field": "dport"
                    }
                  },
                  "right": {
                    "set": [
                      80,
                      443
                    ]
                  }
                }
              },
              {
                "accept": newJNull()
              }
            ]
          }
        }
      },
      {
        "add": {
          "rule": {
            "family": family,
            "table": "filter",
            "chain": "nginwho",
            "handle": 3,
            "expr": [
              {
                "match": {
                  "op": "!=",
                  "left": {
                    "payload": {
                      "protocol": "ip",
                      "field": "saddr"
                    }
                  },
                  "right": "@CF_CDN_EDGE"
                }
              },
              {
                "match": {
                  "op": "==",
                  "left": {
                    "payload": {
                      "protocol": "tcp",
                      "field": "dport"
                    }
                  },
                  "right": {
                    "set": [
                      80,
                      443
                    ]
                  }
                }
              },
              {
                "drop": newJNull()
              }
            ]
          }
        }
      }
    ]
  }

  return rules


proc nginwhoChainExists(configOutput: JsonNode): bool =
  info("Checking nftables nginwho chain existence")

  for element in 0..configOutput.len() - 1:
    if configOutput[element].contains("chain"):
      if configOutput[element]["chain"]["name"].getStr() == NFT_CHAIN_NAME:
        info(fmt"Found {NFT_CHAIN_NAME} nftables chain")
        return true

  warn(fmt"{NFT_CHAIN_NAME} does not exist")


proc cloudflareSetExists(configOutput: JsonNode, tableName: string): bool =
  info("Checking Cloudflare nftables set existence")

  for element in 0..configOutput.len() - 1:
    if configOutput[element].contains("set"):
      if configOutput[element]["set"]["family"].getStr() == tableName:
        info("Found Cloudflare's nftables set")
        return true

  warn(fmt"{NFT_SET_NAME_CF} does not exist")


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


proc getFilterTableName(configOutput: JsonNode): string =
  info("Getting nftables filter table name")

  try:
    for idx in 0..configOutput.len() - 1:
      if configOutput[idx].contains("table"):
        let tableFamily = configOutput[idx]["table"]["family"].getStr()
        if tableFamily notin ["inet", "ip"]:
          continue
        info(fmt"Found table filter family with name: {tableFamily}")
        return tableFamily
  except Exception as e:
    error(fmt"Failed checking table existence: {e.msg}")


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


proc ensureNftExists() = 
  info("Checking existence of nftables")

  let result: string = findExe("nft")

  if result == "":
    fatal("nftables command not found")
    quit(1)
    

proc acceptOnly*(cidrs: JsonNode) = 
  ensureNftExists()
  
  let configOutput: JsonNode = getCurrentRules(TEMP_NFT_FILE_PATH)
  
  let filterTableName: string = getFilterTableName(configOutput[NFT])
  if filterTableName.len() == 0:
    error("No `inet` nftables filter found - please create it manually")
    quit(1)

  if cidrs.len() != 0:
    let rules: JsonNode = createRules(filterTableName, cidrs)
    writeRules(rules=rules)
    applyRules()
  else:
    warn("Received empty CIDRs")


proc acceptOnly*(path: string) {.async.} = 
  ensureNftExists()
  
  let configOutput: JsonNode = getCurrentRules(TEMP_NFT_FILE_PATH)
  
  let filterTableName: string = getFilterTableName(configOutput[NFT])
  if filterTableName.len() == 0:
    error("No `inet` nftables filter found - please create it manually")
    quit(1)

  let parsedCidrs: JsonNode = fetchCidrsFrom(path)
  let rules: JsonNode = createRules(filterTableName, parsedCidrs)
    
  writeRules(rules=rules)
  applyRules()

  await sleepAsync(SIX_HOURS)