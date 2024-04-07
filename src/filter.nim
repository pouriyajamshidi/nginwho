import std/[json, os, strformat, times]

const
    # DEFAULT_NFT_FILE_PATH = "/etc/nftables.conf"
    DEFAULT_NFT_FILE_PATH = "nft_working_output.json"
    NFTABLES_MIN_LEN = 2
    NFT = "nftables"
    NFT_SET_NAME_CF = "Cloudflare"
    NFT_CHAIN_NAME = "nginwho"

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

proc createSet(cidrs: seq[string]): JsonNode=
  let mamoosh = %*
  {
    "set": {
        "family": "inet",
        "name": "CF_CDN_EDGE",
        "table": "filter",
        "type": "ipv4_addr",
        "handle": 5,
        "flags": [
            "interval"
        ],
        "elem": [
            {
                "prefix": {
                    "addr": "103.21.244.0",
                    "len": 22
                }
            }
        ]
    }
  } 
  return mamoosh

proc nginwhoChainExists(configOutput: JsonNode): bool =
  let now: string = getTime().format("yyyy-MM-dd HH:mm:ss")

  echo fmt"{now} - Checking nftables nginwho chain existence"

  for element in 0..configOutput.len() - 1:
    if configOutput[element].contains("chain"):
      if configOutput[element]["chain"]["name"].getStr() == NFT_CHAIN_NAME:
        echo fmt"Found {NFT_CHAIN_NAME} nftables chain"
        return true

  echo fmt"{now} - {NFT_CHAIN_NAME} does not exist"

proc cloudflareSetExists(configOutput: JsonNode, tableName: string): bool =
  let now: string = getTime().format("yyyy-MM-dd HH:mm:ss")

  echo fmt"{now} - Checking Cloudflare nftables set existence"

  for element in 0..configOutput.len() - 1:
    if configOutput[element].contains("set"):
      if configOutput[element]["set"]["family"].getStr() == tableName:
        echo fmt"Found Cloudflare's nftables set"
        return true

  echo fmt"{now} - {NFT_SET_NAME_CF} does not exist"


proc getFilterTableName(configOutput: JsonNode): string =
  let now: string = getTime().format("yyyy-MM-dd HH:mm:ss")

  echo fmt"{now} - Getting nftables filter table name"

  try:
    for idx in 0..configOutput.len() - 1:
      if configOutput[idx].contains("table"):
        let tableFamily = configOutput[idx]["table"]["family"].getStr()
        if tableFamily notin ["inet", "ip"]:
          continue
        echo fmt"Found table filter family with name: {tableFamily}"
        return tableFamily
  except Exception as e:
    echo fmt"{now} - Failed checking table existence: {e.msg}"


proc getCurrentRules(configFile: string=DEFAULT_NFT_FILE_PATH): JsonNode = 
  let now: string = getTime().format("yyyy-MM-dd HH:mm:ss")

  echo fmt"{now} - Getting nftables rules from {configFile}"

  if not fileExists(configFile):
    echo fmt"{now} - {configFile} does not exist"
    return

  let file: File = open(configFile, fmRead)
  defer: file.close()

  var jsonData: JsonNode

  try:
    jsonData = parseJson(file.readAll())
    echo fmt"{now} - Successfully parsed JSON"
  except Exception as e:
    echo fmt"{now} - Failed parsing JSON: {e.msg}"
    return

  return jsonData


proc start() = 
  let now: string = getTime().format("yyyy-MM-dd HH:mm:ss")

  var configOutput: JsonNode = getCurrentRules()
  if configOutput[NFT].len() < NFTABLES_MIN_LEN:
    echo fmt"{now} - nftables output does not match the minimum length"
    quit(0)

  let filterTableName: string = getFilterTableName(configOutput[NFT])
  if filterTableName.len() == 0:
    echo fmt"{now} - No `inet` or `ip` filter found - please create one of them manually"
    quit(1)
  echo filterTableName

  if cloudflareSetExists(configOutput[NFT], filterTableName):
    echo "yes - CF set"
  else:
    echo "no - CF set"

  if nginwhoChainExists(configOutput[NFT]):
    echo "yes - nginwho chain"
  else:
    echo "no - nginwho chain"

  echo createSet(cfElements)