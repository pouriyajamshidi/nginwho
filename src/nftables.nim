import std/[asyncdispatch, os, strformat, json]

from strutils import split, parseInt, isDigit, join, replace, repeat
from algorithm import sorted
from logging import info, error, warn, fatal
from osproc import execProcess, execCmd
from net import parseIpAddress, IpAddressFamily
from types import SetType, IPProtocol, NftSet, NftAttrs

import consts



proc applyRules(fileName: string = NFT_CIDR_RULES_FILE) =
  info("Applying nftables rules")

  let res: int = execCmd(fmt"nft -j -f {filename}")
  if res != 0:
    error("Failed applying nftables rules - Are you root?")
    quit(1)
  else:
    info("Successfully applied nftables rules")


proc writeRules(fileName: string = NFT_CIDR_RULES_FILE, rules: JsonNode) =
  info(fmt"Writing nginwho rules to {fileName}")

  try:
    writeFile(fileName, rules.pretty())
    info(fmt"Successfully wrote nginwho rules to {fileName}")
  except Exception as e:
    error(fmt"Failed writing nginwho rules to {fileName}: {e.msg}")


proc createNginwhoChain(name: string = "nginwho"): JsonNode =
  info("Creating nginwho chain")

  return %* {
    "add": {
      "chain": {
        "family": "inet",
        "table": "filter",
        "name": name,
        "handle": 1,
        "type": "filter",
        "hook": "prerouting",
        "prio": -10,
        "policy": "accept"
    }
  }
  }


proc createNginwhoLogPolicy(): JsonNode =
  info("Creating nginwho log policy")

  return %* {
    "add": {
      "rule": {
        "family": "inet",
        "table": "filter",
        "chain": "nginwho",
        "handle": 1,
        "expr": [{"log": {"prefix": NFT_LOG_PREFIX}}]
    }
  }
  }


proc createNginwhoIPPolicy(protocol: IPProtocol, setName: string): JsonNode =
  info(fmt"Creating nginwho {protocol} policy for Set {setName}")

  return %* {
    "add": {
      "rule": {
        "family": "inet",
        "table": "filter",
        "chain": "nginwho",
        "handle": 3,
        "expr": [
          {
            "match": {
              "op": "!=",
              "left": {"payload": {"protocol": protocol, "field": "saddr"}},
              "right": fmt"@{setName}"
            }
          },
          {
            "match": {
              "op": "==",
              "left": {"payload": {"protocol": "tcp", "field": "dport"}},
              "right": {"set": [80, 443]}
            }
          },
          {"counter": {"packets": 0, "bytes": 0}},
          {"drop": newJNull()}
        ]
      }
    }
  }


proc createInputChain(name: string = "input"): JsonNode =
  info("Creating input chain")

  return %* {
    "add": {
      "chain": {
        "family": "inet",
        "table": "filter",
        "name": name,
        "handle": 1,
        "type": "filter",
        "hook": "input",
        "prio": 0,
        "policy": "accept"
    }
  }
  }


proc createInputChainPolicy(): JsonNode =
  info("Creating input chain policy")

  return %* {
    "add": {
      "rule": {
        "family": "inet",
        "table": "filter",
        "chain": "input",
        "handle": 2,
        "expr": [
          {
            "match": {
              "op": "==",
              "left": {"payload": {"protocol": "tcp", "field": "dport"}},
              "right": {"set": [80, 443]}
            }
          },
          {"counter": {"packets": 0, "bytes": 0}},
          {"accept": newJNull()}
        ]
      }
    }
  }


proc createSet(cidrs: JsonNode, setName: string, setType: SetType): JsonNode =
  info(fmt"Creating {setType} Set")

  var ipSet: JsonNode = %* {
    "add": {
      "set": {
        "family": "inet",
        "name": setName,
        "table": "filter",
        "type": setType,
        "handle": 50,
        "flags": [
            "interval"
    ],
    "elem": []
  }
    }
  }

  for cidr in cidrs:
    let ipAndPrefixLen: seq[string] = cidr.getStr().split("/")

    ipSet["add"]["set"]["elem"].add(%*{
      "prefix": {
        "addr": ipAndPrefixLen[0],
        "len": parseInt(ipAndPrefixLen[1])
      }
    }
    )

  return ipSet


proc createRules(nftSet: NftSet, nftAttrs: NftAttrs): JsonNode =
  info(fmt"Creating nftables rules")

  var rules: JsonNode = %* {"nftables": []}

  if nftAttrs.withCloudflareV4Set:
    rules[NFT_KEY_NAME].add(createSet(nftSet.ipv4, NFT_SET_NAME_CF_IPv4, SetType.IPv4))

  if nftAttrs.withCloudflareV6Set:
    rules[NFT_KEY_NAME].add(createSet(nftSet.ipv6, NFT_SET_NAME_CF_IPv6, SetType.IPv6))

  if nftAttrs.withNginwhoChain:
    rules[NFT_KEY_NAME].add(createNginwhoChain())

  if nftAttrs.withNginwhoIPv4Policy:
    rules[NFT_KEY_NAME].add(createNginwhoLogPolicy())
    rules[NFT_KEY_NAME].add(createNginwhoIPPolicy(IPProtocol.IPv4,
        NFT_SET_NAME_CF_IPv4))

  if nftAttrs.withNginwhoIPv6Policy:
    rules[NFT_KEY_NAME].add(createNginwhoIPPolicy(IPProtocol.IPv6,
        NFT_SET_NAME_CF_IPv6))

  if nftAttrs.withInputChain:
    rules[NFT_KEY_NAME].add(createInputChain())

  if nftAttrs.withInputPolicy:
    rules[NFT_KEY_NAME].add(createInputChainPolicy())

  info(fmt"Successfully created nftables rules")

  return rules


proc inputChainHasPolicy(nftOutput: JsonNode): bool =
  info("Checking nftables input chain for existing policy")

  for element in 0..nftOutput.len() - 1:
    if not nftOutput[element].contains("rule"):
      continue

    let chainName = nftOutput[element]["rule"]["chain"].getStr()
    if chainName != NFT_CHAIN_INPUT_NAME:
      continue

    let expression = nftOutput[element]["rule"]["expr"]
    if expression.len() < 3:
      continue

    try:
      let rightNode = expression[0]["match"]["right"]
      if rightNode.kind == JObject and rightNode.contains("set"):
        let service = expression[0]["match"]["right"]["set"].getElems()
        if service.len() == 2 and
          service[0].getInt() == 80 and
          service[1].getInt() == 443:
          info("input chain already has the required policy")
          return true
    except:
      continue

  warn(fmt"{NFT_CHAIN_INPUT_NAME} chain does not have the required policy")


proc inputChainExists(nftOutput: JsonNode): bool =
  info("Checking nftables input chain existence")

  for element in 0..nftOutput.len() - 1:
    if nftOutput[element].contains("chain"):
      if nftOutput[element]["chain"]["name"].getStr() == NFT_CHAIN_INPUT_NAME:
        info(fmt"Found nftables {NFT_CHAIN_INPUT_NAME} chain")
        return true

  warn(fmt"{NFT_CHAIN_INPUT_NAME} does not exist")


proc nginwhoChainHasPolicy(nftOutput: JsonNode, setName: string): bool =
  info(fmt"Checking nftables nginwho chain for existing policy on Set `{setName}`")

  for element in 0..nftOutput.len() - 1:
    if not nftOutput[element].contains("rule"):
      continue

    let chainName = nftOutput[element]["rule"]["chain"].getStr()
    if chainName != NFT_CHAIN_NGINWHO_NAME:
      continue

    let expression = nftOutput[element]["rule"]["expr"]
    if expression.len() < 4:
      continue

    let destination = expression[0]["match"]["right"].getStr()
    let service = expression[1]["match"]["right"]["set"].getElems()

    if destination == fmt"@{setName}" and
      service.len() == 2 and
      service[0].getInt() == 80 and
      service[1].getInt() == 443:
      info(fmt"nginwho chain already has the required policy for Set {setName}")
      return true

  warn(fmt"{NFT_CHAIN_NGINWHO_NAME} chain does not have the required policy for Set {setName}")


proc nginwhoChainExists(nftOutput: JsonNode): bool =
  info("Checking nftables nginwho chain existence")

  for element in 0..nftOutput.len() - 1:
    if nftOutput[element].contains("chain"):
      if nftOutput[element]["chain"]["name"].getStr() == NFT_CHAIN_NGINWHO_NAME:
        info(fmt"Found nftables {NFT_CHAIN_NGINWHO_NAME} chain")
        return true

  warn(fmt"Chain {NFT_CHAIN_NGINWHO_NAME} does not exist")


proc setChanged(nftOutput: JsonNode, newCidrs: JsonNode,
    setName: string): bool =
  info(fmt"Checking nftables {setName} Set for changes")

  var currentSets = newSeq[string]()

  for element in 0..nftOutput.len() - 1:
    if not nftOutput[element].contains("set"):
      continue
    if nftOutput[element]["set"]["name"].getStr() == setName:
      for elem in nftOutput[element]["set"]["elem"]:
        let address = elem["prefix"]["addr"].getStr()
        let length = elem["prefix"]["len"].getInt()
        let addressAndLen = fmt"{address}/{length}"
        currentSets.add(addressAndLen)

  if sorted(currentSets) == sorted(newCidrs.to(seq[string])):
    info(fmt"Set {setName} Set has not changed")
    return false

  info(fmt"Set {setName} Set has changed")
  return true


proc setExists(nftOutput: JsonNode, setName: string): bool =
  info(fmt"Checking nftables {setName} Set existence")

  for element in 0..nftOutput.len() - 1:
    if nftOutput[element].contains("set"):
      if nftOutput[element]["set"]["family"].getStr() == "inet" and
      nftOutput[element]["set"]["name"].getStr() == setName:
        info(fmt"Found nftables {setName} Set")
        return true

  warn(fmt"Set {setName} does not exist")


proc createNftSetsFrom(fileName: string = NGINX_CIDR_FILE): NftSet =
  info(fmt"Fetching NFT Sets from {fileName}")

  if not fileExists(fileName):
    error(fmt"{fileName} does not exist")
    quit(1)

  var ipv4Cidrs: seq[string] = @[]
  var ipv6Cidrs: seq[string] = @[]

  for line in lines(fileName):
    if line.len() == 0:
      continue

    let splitLine = line.split(" ")
    if splitLine.len() < 2 or splitLine.len() > 2:
      continue

    if splitLine[1][0].isDigit():
      let ipAndMask = splitLine[1].replace(";", "")
      let ipAddr = parseIpAddress(ipAndMask.split("/")[0])

      if ipAddr.family == IpAddressFamily.IPv4:
        ipv4Cidrs.add($ipAndMask)

      if ipAddr.family == IpAddressFamily.IPv6:
        ipv6Cidrs.add($ipAndMask)

  return NftSet(ipv4: %*ipv4Cidrs, ipv6: %*ipv6Cidrs)


proc inetFilterExists(nftOutput: JsonNode): bool =
  info("Checking nftables `inet filter` table existence")

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


proc getCurrentRules(): JsonNode =
  info(fmt"Getting current nftables rules using `{NFT_GET_RULESET_CMD}`")

  try:
    return parseJson(execProcess(NFT_GET_RULESET_CMD))
  except Exception as e:
    error(fmt"Failed parsing JSON: {e.msg}")


proc writeRulesAndApply(rules: JsonNode) =
  writeRules(rules = rules)
  applyRules()


proc ensureNftExists*() =
  info("Checking existence of nftables")

  let result: string = findExe("nft")

  if result == "":
    fatal("nftables command not found")
    quit(1)


proc changesRequired(nftAttrs: NftAttrs): bool =
  info("Checking if there are any nftables changes required")

  for _, value in nftAttrs.fieldPairs():
    if value == true:
      info("nftables requires changes")
      return true

  info("No changes to nftables are required")

  return false


proc runPrechecks(nftSet: NftSet): NftAttrs =
  info("Running nftables pre-checks")

  let nftOutput: JsonNode = getCurrentRules()[NFT_KEY_NAME]

  if not inetFilterExists(nftOutput):
    error("nftables `inet` filter not found")
    info("Please create one manually using this sample:\n\n",
        fmt"{NFT_SAMPLE_POLICY}")
    quit(1)

  var nftAttrs: NftAttrs

  if setExists(nftOutput, NFT_SET_NAME_CF_IPv4):
    nftAttrs.withCloudflareV4Set = if setChanged(nftOutput, nftSet.ipv4,
        NFT_SET_NAME_CF_IPv4): true else: false
  else:
    nftAttrs.withCloudflareV4Set = true

  if setExists(nftOutput, NFT_SET_NAME_CF_IPv6):
    nftAttrs.withCloudflareV6Set = if setChanged(nftOutput, nftSet.ipv6,
        NFT_SET_NAME_CF_IPv6): true else: false
  else:
    nftAttrs.withCloudflareV6Set = true

  nftAttrs.withNginwhoChain = if nginwhoChainExists(nftOutput): false else: true
  nftAttrs.withNginwhoIPv4Policy = if nginwhoChainHasPolicy(nftOutput,
      NFT_SET_NAME_CF_IPv4): false else: true
  nftAttrs.withNginwhoIPv6Policy = if nginwhoChainHasPolicy(nftOutput,
      NFT_SET_NAME_CF_IPv6): false else: true

  nftAttrs.withInputChain = if inputChainExists(nftOutput): false else: true
  nftAttrs.withInputPolicy = if inputChainHasPolicy(nftOutput): false else: true

  return nftAttrs


proc acceptOnly*(nftSet: NftSet) =
  info(fmt"Using `{NFT_GET_RULESET_CMD}` to construct nftables rules ")

  if nftSet.ipv4.len() == 0 and nftSet.ipv6.len() == 0:
    warn("Received empty NFT Sets")
    return

  let nftAttrs: NftAttrs = runPrechecks(nftSet)

  if changesRequired(nftAttrs):
    let rules: JsonNode = createRules(nftSet, nftAttrs)
    writeRulesAndApply(rules)


proc acceptOnly*(path: string) {.async.} =
  info(fmt"Using {path} to construct nftables rules ")

  let nftSet: NftSet = createNftSetsFrom(path)

  if nftSet.ipv4.len() == 0:
    warn("Received empty CIDRs")
    return

  let nftAttrs: NftAttrs = runPrechecks(nftSet)

  if changesRequired(nftAttrs):
    let rules: JsonNode = createRules(nftSet, nftAttrs)
    writeRulesAndApply(rules)

  await sleepAsync(SIX_HOURS)
