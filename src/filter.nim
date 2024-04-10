import std/[json, os, strformat]

from strutils import split
from json import parseFile
from logging import addHandler, newConsoleLogger, ConsoleLogger, info, error, warn, fatal
from osproc import execProcess


const
    DEFAULT_NFT_CONFIG_FILE_PATH = "/etc/nftables.conf"
    TEMP_NFT_FILE_PATH = "nft_working_output.json"

    NFTABLES_MIN_RULE_LEN = 2

    NFT = "nftables"
    NFT_SET_NAME_CF = "Cloudflare"
    NFT_CHAIN_NAME = "nginwho"
    NFT_GET_RULESET_CMD = "nft -j list ruleset"

    # RULES_FILE = "/tmp/nginwho.nft"
    RULES_FILE = "nginwho.nft"


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

var logger: ConsoleLogger = newConsoleLogger(fmtStr="[$date -- $time] - $levelname: ")
addHandler(logger)


proc applyRules(fileName: string=RULES_FILE) =
  info("Applying nftables rules")

  let res: int = execCmd(fmt"nft -j -f {filename}")
  if res != 0:
    error("Failed applying nftables rules - Are you root?")
  else:
    info("Successfully applied nftables rules")


proc writeRules(fileName: string=RULES_FILE, rules: JsonNode) =
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


proc createSet(cidrs: seq[string]): JsonNode =
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
    let ipAndPrefixLen: seq[string] =  cidr.split("/")

    ipSet["add"]["set"]["elem"].add(%*{
      "prefix": {
        "addr": ipAndPrefixLen[0],
        "len": parseInt(ipAndPrefixLen[1])
        }
      }
    )

  return ipSet


proc createRules(family: string): JsonNode =
  info(fmt"Creating nginwho rules for {family} family")

  var rules = %* {
    "nftables": [
      createChain(),
      createSet(cfElements),
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
  if configFile == DEFAULT_NFT_CONFIG_FILE_PATH or configFile == TEMP_NFT_FILE_PATH:
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

  let result = findExe("nft")

  if result == "":
    fatal("nftables command not found")
    quit(1)
    

proc filter(ipCidr: IPCidrs) = 
  ensureNftExists()
  
  var configOutput: JsonNode = getCurrentRules(TEMP_NFT_FILE_PATH)
  
  let filterTableName: string = getFilterTableName(configOutput[NFT])
  if filterTableName.len() == 0:
    error("No `inet` nftables filter found - please create one of them manually")
    quit(1)

  let rules: JsonNode = createRules(filterTableName)
  writeRules(rules=rules)
  applyRules()
