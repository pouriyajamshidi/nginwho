import std/json
from std/os import findExe
from std/strformat import fmt
from std/strutils import split, parseInt
from std/algorithm import sorted
from std/logging import info, error, warn
from std/osproc import execProcess, execCmd
from std/net import parseIpAddress, IpAddress, IpAddressFamily


type
  NftError* = object of CatchableError
    ## nftables could not be read or changed. Only the blocking stops, the rest of nginwho keeps going

  NftSet* = object
    name*: string # the CDN, its Sets are <name>_IPv4 and <name>_IPv6
    ipv4*: JsonNode
    ipv6*: JsonNode

  NftAttrs* = object
    ## The parts of the ruleset nginwho still has to add
    withV4Set*: bool
    withV6Set*: bool
    withNginwhoChain*: bool
    withNginwhoPolicies*: bool
    withInputChain*: bool
    withInputPolicy*: bool


const
  getRulesetCmd = "nft -j list ruleset"
  rulesFile = "/run/nginwho.nft"
  nginwhoChain = "nginwho"
  inputChain = "input"
  logPrefixV4 = "NGINWHO_DROPPED_v4 "
  logPrefixV6 = "NGINWHO_DROPPED_v6 "


proc setNameV4(nftSet: NftSet): string = nftSet.name & "_IPv4"
proc setNameV6(nftSet: NftSet): string = nftSet.name & "_IPv6"


proc withMask(cidr: string): string =
  ## Returns the CIDR with a prefix length, "1.2.3.4" becomes "1.2.3.4/32".
  ## Returns "" when it is not a valid IP or prefix length
  let parts = cidr.split("/")
  if parts.len > 2:
    return ""

  var ipAddr: IpAddress
  try:
    ipAddr = parseIpAddress(parts[0])
  except ValueError:
    return ""

  let maxLen = if ipAddr.family == IpAddressFamily.IPv4: 32 else: 128
  if parts.len == 1:
    return fmt"{parts[0]}/{maxLen}"

  try:
    let prefixLen = parseInt(parts[1])
    if prefixLen < 0 or prefixLen > maxLen:
      return ""
  except ValueError:
    return ""

  return cidr


proc validCidrs*(cidrs: JsonNode): seq[string] =
  ## Returns the CIDRs with a prefix length and skips the invalid ones
  for cidr in cidrs:
    let withPrefix = withMask(cidr.getStr())
    if withPrefix == "":
      warn(fmt"Skipping invalid CIDR: {cidr}")
      continue
    result.add(withPrefix)


proc applyRules() =
  info("Applying nftables rules")

  let res = execCmd(fmt"nft -j -f {rulesFile}")
  if res != 0:
    # nft prints why just before this
    raise newException(NftError, fmt"nft could not apply the rules in {rulesFile}")
  else:
    info("Successfully applied nftables rules")


proc writeRules(rules: JsonNode): bool =
  info(fmt"Writing nginwho rules to {rulesFile}")

  try:
    writeFile(rulesFile, rules.pretty())
    info(fmt"Successfully wrote nginwho rules to {rulesFile}")
    return true
  except IOError as e:
    error(fmt"Failed writing nginwho rules to {rulesFile}: {e.msg}")
    return false


proc createNginwhoChain(): JsonNode =
  info("Creating nginwho chain")

  return %* {
    "add": {
      "chain": {
        "family": "inet",
        "table": "filter",
        "name": nginwhoChain,
        "handle": 1,
        "type": "filter",
        "hook": "prerouting",
        "prio": -10,
        "policy": "accept"
    }
  }
  }


proc createNginwhoIPPolicy(protocol, setName, logPrefix: string): JsonNode =
  ## `protocol` is "ip" or "ip6", as nft names them
  info(fmt"Creating nginwho {protocol} policy for Set {setName}")

  return %* {
    "add": {
      "rule": {
        "family": "inet",
        "table": "filter",
        "chain": nginwhoChain,
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
          {"log": {"prefix": logPrefix}},
          {"drop": newJNull()}
        ]
      }
    }
  }


proc createInputChain(): JsonNode =
  info("Creating input chain")

  return %* {
    "add": {
      "chain": {
        "family": "inet",
        "table": "filter",
        "name": inputChain,
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
        "chain": inputChain,
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


proc createSet(cidrs: JsonNode, setName, setType: string): seq[JsonNode] =
  ## Returns the commands that create the Set or replace the elements of an existing one.
  ## `setType` is "ipv4_addr" or "ipv6_addr", as nft names them.
  ## Adding to an existing Set keeps its old elements, so it is flushed first
  info(fmt"Creating {setType} Set")

  let setId = %* {"family": "inet", "table": "filter", "name": setName}

  var ipSet = %* {
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

  for cidr in validCidrs(cidrs):
    let ipAndPrefixLen = cidr.split("/")

    ipSet["add"]["set"]["elem"].add(%*{
      "prefix": {
        "addr": ipAndPrefixLen[0],
        "len": parseInt(ipAndPrefixLen[1])
      }
    }
    )

  # adding a Set that exists does nothing, so this makes sure there is one to flush.
  # nft applies the file at once, so the Set is never empty in between
  var emptySet = ipSet.copy()
  emptySet["add"]["set"].delete("elem")

  return @[emptySet, %*{"flush": {"set": setId}}, ipSet]


proc createRules*(nftSet: NftSet, nftAttrs: NftAttrs): JsonNode =
  info("Creating nftables rules")

  # adding a table that exists does nothing, so this makes `inet filter` only when there is none
  var rules = %* {"nftables": [{"add": {"table": {"family": "inet", "name": "filter"}}}]}

  if nftAttrs.withV4Set:
    for command in createSet(nftSet.ipv4, nftSet.setNameV4, "ipv4_addr"):
      rules["nftables"].add(command)

  if nftAttrs.withV6Set:
    for command in createSet(nftSet.ipv6, nftSet.setNameV6, "ipv6_addr"):
      rules["nftables"].add(command)

  if nftAttrs.withNginwhoChain:
    rules["nftables"].add(createNginwhoChain())

  if nftAttrs.withNginwhoPolicies:
    # the rules of another CDN would drop this one's traffic, so the chain is emptied first.
    # nft applies the file at once, so nothing gets through in between
    rules["nftables"].add(%*{"flush": {"chain": {"family": "inet",
        "table": "filter", "name": nginwhoChain}}})
    rules["nftables"].add(createNginwhoIPPolicy("ip",
        nftSet.setNameV4, logPrefixV4))
    rules["nftables"].add(createNginwhoIPPolicy("ip6",
        nftSet.setNameV6, logPrefixV6))

  if nftAttrs.withInputChain:
    rules["nftables"].add(createInputChain())

  if nftAttrs.withInputPolicy:
    rules["nftables"].add(createInputChainPolicy())

  info("Successfully created nftables rules")

  return rules


proc inputChainHasPolicy(nftOutput: JsonNode): bool =
  info("Checking nftables input chain for existing policy")

  for node in nftOutput:
    if not node.contains("rule"):
      continue

    let chainName = node["rule"]["chain"].getStr()
    if chainName != inputChain:
      continue

    let expression = node["rule"]["expr"]
    if expression.len < 3:
      continue

    # {} gives nil instead of raising when a rule has another shape
    let service = expression[0]{"match", "right", "set"}.getElems()
    if service.len == 2 and
      service[0].getInt() == 80 and
      service[1].getInt() == 443:
      info("input chain already has the required policy")
      return true

  warn(fmt"{inputChain} chain does not have the required policy")


proc inputChainExists(nftOutput: JsonNode): bool =
  info("Checking nftables input chain existence")

  for node in nftOutput:
    if node.contains("chain"):
      if node["chain"]["name"].getStr() == inputChain:
        info(fmt"Found nftables {inputChain} chain")
        return true

  warn(fmt"{inputChain} does not exist")


proc nginwhoChainHasPolicy(nftOutput: JsonNode, setName: string): bool =
  info(fmt"Checking nftables nginwho chain for existing policy on Set `{setName}`")

  for node in nftOutput:
    if not node.contains("rule"):
      continue

    let chainName = node["rule"]["chain"].getStr()
    if chainName != nginwhoChain:
      continue

    let expression = node["rule"]["expr"]
    if expression.len < 4:
      continue

    let destination = expression[0]{"match", "right"}.getStr()
    let service = expression[1]{"match", "right", "set"}.getElems()

    if destination == fmt"@{setName}" and
      service.len == 2 and
      service[0].getInt() == 80 and
      service[1].getInt() == 443:
      info(fmt"nginwho chain already has the required policy for Set {setName}")
      return true

  warn(fmt"{nginwhoChain} chain does not have the required policy for Set {setName}")


proc nginwhoChainIsCurrent(nftOutput: JsonNode, nftSet: NftSet): bool =
  ## True when the chain only has the drop rules for this CDN's Sets
  var rules = 0
  for node in nftOutput:
    if node.contains("rule") and node["rule"]["chain"].getStr() == nginwhoChain:
      rules += 1

  return rules == 2 and
    nginwhoChainHasPolicy(nftOutput, nftSet.setNameV4) and
    nginwhoChainHasPolicy(nftOutput, nftSet.setNameV6)


proc nginwhoChainExists(nftOutput: JsonNode): bool =
  info("Checking nftables nginwho chain existence")

  for node in nftOutput:
    if node.contains("chain"):
      if node["chain"]["name"].getStr() == nginwhoChain:
        info(fmt"Found nftables {nginwhoChain} chain")
        return true

  warn(fmt"Chain {nginwhoChain} does not exist")


proc setChanged(nftOutput: JsonNode, newCidrs: JsonNode,
    setName: string): bool =
  info(fmt"Checking nftables {setName} Set for changes")

  var currentSets = newSeq[string]()

  for node in nftOutput:
    if not node.contains("set"):
      continue
    if node["set"]["name"].getStr() == setName:
      # an empty Set has no elem at all
      for elem in node["set"]{"elem"}.getElems():
        # nft lists single addresses like 1.2.3.4/32 as a plain string
        if elem.kind == JString:
          currentSets.add(withMask(elem.getStr()))
          continue
        let address = elem["prefix"]["addr"].getStr()
        let length = elem["prefix"]["len"].getInt()
        let addressAndLen = fmt"{address}/{length}"
        currentSets.add(addressAndLen)

  let wantedSets = validCidrs(newCidrs)

  if sorted(currentSets) == sorted(wantedSets):
    info(fmt"Set {setName} Set has not changed")
    return false

  info(fmt"Set {setName} Set has changed")
  return true


proc setExists(nftOutput: JsonNode, setName: string): bool =
  info(fmt"Checking nftables {setName} Set existence")

  for node in nftOutput:
    if node.contains("set"):
      if node["set"]["name"].getStr() == setName:
        info(fmt"Found nftables {setName} Set")
        return true

  warn(fmt"Set {setName} does not exist")


proc getCurrentRules(): JsonNode =
  info(fmt"Getting current nftables rules using `{getRulesetCmd}`")

  try:
    result = parseJson(execProcess(getRulesetCmd)){"nftables"}
  except CatchableError as e:
    error(fmt"Failed parsing JSON: {e.msg}")

  # we can't decide which rules to add without the current ones
  if result.isNil:
    raise newException(NftError, "Could not get current nftables rules - Are you root?")


proc writeRulesAndApply(rules: JsonNode) =
  # don't apply an old or unknown rules file if writing failed
  if writeRules(rules):
    applyRules()


proc ensureNftExists*() =
  ## Raises OSError when nftables is not installed
  info("Checking existence of nftables")

  if findExe("nft") == "":
    raise newException(OSError, "nftables command not found")


proc changesRequired(nftAttrs: NftAttrs): bool =
  info("Checking if there are any nftables changes required")

  for _, value in nftAttrs.fieldPairs():
    if value:
      info("nftables requires changes")
      return true

  info("No changes to nftables are required")

  return false


proc inetFilterOnly(nftOutput: JsonNode): JsonNode =
  ## The part of the ruleset in `inet filter`. A chain or Set with the same name in
  ## another table, like an `input` chain in `ip filter`, is not nginwho's
  result = newJArray()
  for node in nftOutput:
    for kind, item in node:
      let table = if kind == "table": item{"name"} else: item{"table"}
      if item{"family"}.getStr() == "inet" and table.getStr() == "filter":
        result.add(node)


proc requiredChanges*(nftOutput: JsonNode, nftSet: NftSet): NftAttrs =
  ## Compares the current ruleset with what nginwho needs and returns the missing parts
  let nftOutput = inetFilterOnly(nftOutput)
  return NftAttrs(
    withV4Set: not setExists(nftOutput, nftSet.setNameV4) or setChanged(
        nftOutput, nftSet.ipv4, nftSet.setNameV4),
    withV6Set: not setExists(nftOutput, nftSet.setNameV6) or setChanged(
        nftOutput, nftSet.ipv6, nftSet.setNameV6),
    withNginwhoChain: not nginwhoChainExists(nftOutput),
    withNginwhoPolicies: not nginwhoChainIsCurrent(nftOutput, nftSet),
    withInputChain: not inputChainExists(nftOutput),
    withInputPolicy: not inputChainHasPolicy(nftOutput),
  )


proc acceptOnly*(nftSet: NftSet) =
  ## Raises NftError when the rules can't be checked or applied
  info(fmt"Using `{getRulesetCmd}` to construct nftables rules ")

  if nftSet.ipv4.len == 0 and nftSet.ipv6.len == 0:
    warn("Received empty NFT Sets")
    return

  let nftAttrs = requiredChanges(getCurrentRules(), nftSet)

  if changesRequired(nftAttrs):
    let rules = createRules(nftSet, nftAttrs)
    writeRulesAndApply(rules)

