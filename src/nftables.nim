import std/json
from std/os import findExe
from std/strformat import fmt
from std/strutils import split, rsplit, parseInt, splitLines, splitWhitespace, contains
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
    withInputChain*: bool
    withInputPolicy*: bool


const
  getRulesetCmd = "nft -j list ruleset"
  rulesFile = "/run/nginwho.nft"
  nginwhoChain = "nginwho"
  nginwhoHook = "prerouting"
  # raw, before conntrack (-200), so a dropped packet costs no connection tracking lookup
  nginwhoPrio = -300
  inputChain = "input"
  logPrefixV4 = "NGINWHO_DROPPED_v4 "
  logPrefixV6 = "NGINWHO_DROPPED_v6 "
  lockdownChain = "nginwho_input"
  logPrefixLockdown = "NGINWHO_INPUT_DROPPED "


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


proc baseChain(name, hook: string, prio: int, policy: string): JsonNode =
  ## A chain in `inet filter` that packets pass through at `hook`
  %*{"family": "inet", "table": "filter", "name": name, "type": "filter", "hook": hook,
      "prio": prio, "policy": policy}


proc nginwhoBaseChain(): JsonNode = baseChain(nginwhoChain, nginwhoHook, nginwhoPrio, "accept")


proc replaceChain(chain: JsonNode): seq[JsonNode] =
  ## Returns the commands that make the chain from scratch. A chain's hook and priority can't
  ## be changed in place, and old rules, like the ones for another CDN, must not stay, so the
  ## old chain is deleted first. Adding a chain that exists does nothing, so this makes sure
  ## there is one to delete. nft applies the file at once, so nothing gets through in between
  info("Creating " & chain["name"].getStr() & " chain")

  let chainId = %* {"family": "inet", "table": "filter", "name": chain["name"]}

  return @[
    %*{"add": {"chain": chainId}},
    %*{"flush": {"chain": chainId}},
    %*{"delete": {"chain": chainId}},
    %*{"add": {"chain": chain}}
  ]


proc webTraffic(): seq[JsonNode] =
  ## Matches TCP and UDP to ports 80 and 443. UDP 443 is HTTP/3
  @[
    %*{"match": {"op": "==", "left": {"meta": {"key": "l4proto"}}, "right": {"set": ["tcp", "udp"]}}},
    %*{"match": {"op": "==", "left": {"payload": {"protocol": "th", "field": "dport"}},
        "right": {"set": [80, 443]}}}
  ]


proc limitedLog(prefix: string): seq[JsonNode] =
  ## Logs at most 10 packets a minute, so a flood can't fill the system log.
  ## A packet over the limit does not match, so this must be its own rule and never
  ## part of a drop rule, or the packet would get through
  @[%*{"limit": {"rate": 10, "burst": 5, "per": "minute"}}, %*{"log": {"prefix": prefix}}]


proc addRule(chain: string, expr: seq[JsonNode]): JsonNode =
  %*{"add": {"rule": {"family": "inet", "table": "filter", "chain": chain, "expr": expr}}}


proc createNginwhoIPPolicy(protocol, setName, logPrefix: string): seq[JsonNode] =
  ## A rule that logs and a rule that drops web traffic from outside the Set.
  ## `protocol` is "ip" or "ip6", as nft names them.
  ## The port comes first, so traffic to other ports, like SSH, skips the Set lookup
  let notFromCdn = webTraffic() & @[
    %*{"match": {"op": "!=", "left": {"payload": {"protocol": protocol, "field": "saddr"}},
        "right": fmt"@{setName}"}}
  ]

  return @[
    addRule(nginwhoChain, notFromCdn & limitedLog(logPrefix)),
    addRule(nginwhoChain, notFromCdn & @[%*{"counter": {"packets": 0, "bytes": 0}}, %*{"drop": nil}])
  ]


proc nginwhoRules(nftSet: NftSet): seq[JsonNode] =
  createNginwhoIPPolicy("ip", nftSet.setNameV4, logPrefixV4) &
    createNginwhoIPPolicy("ip6", nftSet.setNameV6, logPrefixV6)


proc lockdownBaseChain(): JsonNode = baseChain(lockdownChain, "input", 0, "drop")


proc lockdownRules(sshPorts: seq[int]): seq[JsonNode] =
  ## What a web server lets in. The rest is logged and dropped
  let accept = %*{"accept": nil}

  result = @[
    addRule(lockdownChain, @[%*{"match": {"op": "==", "left": {"meta": {"key": "iif"}},
        "right": "lo"}}, accept]),
    # replies to connections the server made, like DNS lookups and updates
    addRule(lockdownChain, @[%*{"match": {"op": "in", "left": {"ct": {"key": "state"}},
        "right": ["established", "related"]}}, accept]),
    # IPv6 can't find the router or its neighbours without these. ICMP errors about a
    # connection are let in as related. in the order nft lists them
    addRule(lockdownChain, @[%*{"match": {"op": "==",
        "left": {"payload": {"protocol": "icmpv6", "field": "type"}},
        "right": {"set": ["nd-router-advert", "nd-neighbor-solicit", "nd-neighbor-advert"]}}},
        accept]),
    # DHCPv6 answers from another address than it was asked on, so it is not seen as a reply
    addRule(lockdownChain, @[
      %*{"match": {"op": "==", "left": {"meta": {"key": "nfproto"}}, "right": "ipv6"}},
      %*{"match": {"op": "==", "left": {"payload": {"protocol": "udp", "field": "dport"}},
          "right": 546}},
      accept])
  ]

  for port in sshPorts:
    result.add(addRule(lockdownChain, @[%*{"match": {"op": "==",
        "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": port}}, accept]))

  result.add(addRule(lockdownChain, webTraffic() & @[accept]))
  result.add(addRule(lockdownChain, @[%*{"counter": {"packets": 0, "bytes": 0}}] &
      limitedLog(logPrefixLockdown)))


proc createLockdown*(sshPorts: seq[int]): JsonNode =
  result = %* {"nftables": [{"add": {"table": {"family": "inet", "name": "filter"}}}]}
  for command in replaceChain(lockdownBaseChain()) & lockdownRules(sshPorts):
    result["nftables"].add(command)


proc parseSshPorts*(ssOutput: string): seq[int] =
  ## The ports sshd listens on, from the output of `ss -Htlnp`
  for line in ssOutput.splitLines():
    if not line.contains("((\"sshd\","):
      continue
    let fields = line.splitWhitespace()
    if fields.len < 4:
      continue
    # 0.0.0.0:22 or [::]:22
    try:
      let port = parseInt(fields[3].rsplit(':', 1)[^1])
      if port notin result:
        result.add(port)
    except ValueError:
      discard


proc findSshPorts*(): seq[int] =
  ## Empty when sshd is not running, not found, or started by systemd's ssh.socket
  info("Looking for the ports sshd listens on")
  parseSshPorts(execProcess("ss -Htlnp"))


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

  let expr = webTraffic() & @[%*{"counter": {"packets": 0, "bytes": 0}}, %*{"accept": nil}]

  return %* {"add": {"rule": {"family": "inet", "table": "filter", "chain": inputChain,
      "expr": expr}}}


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
    for command in replaceChain(nginwhoBaseChain()) & nginwhoRules(nftSet):
      rules["nftables"].add(command)

  if nftAttrs.withInputChain:
    rules["nftables"].add(createInputChain())

  if nftAttrs.withInputPolicy:
    rules["nftables"].add(createInputChainPolicy())

  info("Successfully created nftables rules")

  return rules


proc inputChainHasPolicy(nftOutput: JsonNode): bool =
  ## Any rule in the input chain for ports 80 and 443 counts, like `tcp dport { 80, 443 } accept`
  ## from older versions or the user's own
  info("Checking nftables input chain for existing policy")

  for node in nftOutput:
    if node{"rule", "chain"}.getStr() != inputChain:
      continue

    for item in node["rule"]["expr"]:
      # {} gives nil instead of raising when a rule has another shape
      if item{"match", "right", "set"} == %*[80, 443]:
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


proc withoutCounters(expr: JsonNode): JsonNode =
  ## The rule without its counters, which grow as packets pass
  result = newJArray()
  for item in expr:
    if not item.hasKey("counter"):
      result.add(item)


proc chainIsCurrent(nftOutput: JsonNode, chain: JsonNode, rules: seq[JsonNode]): bool =
  ## True when the chain is hooked as `chain` says and has only `rules`, in the same order
  let name = chain["name"].getStr()
  info(fmt"Checking nftables {name} chain")

  var hooked = false
  var current, wanted: seq[JsonNode]
  for node in nftOutput:
    if node{"chain", "name"}.getStr() == name:
      hooked = node["chain"]{"hook"} == chain["hook"] and
          node["chain"]{"prio"} == chain["prio"] and
          node["chain"]{"policy"} == chain["policy"]
    elif node{"rule", "chain"}.getStr() == name:
      current.add(withoutCounters(node["rule"]["expr"]))

  for rule in rules:
    wanted.add(withoutCounters(rule["add"]["rule"]["expr"]))

  if hooked and current == wanted:
    info(fmt"{name} chain is up to date")
    return true

  warn(fmt"{name} chain is missing or not up to date")


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
    withNginwhoChain: not chainIsCurrent(nftOutput, nginwhoBaseChain(), nginwhoRules(nftSet)),
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


proc lockdownIsCurrent*(nftOutput: JsonNode, sshPorts: seq[int]): bool =
  chainIsCurrent(inetFilterOnly(nftOutput), lockdownBaseChain(), lockdownRules(sshPorts))


proc lockDown*(sshPorts: seq[int]) =
  ## Drops everything coming in but SSH on `sshPorts`, the web ports and what a server needs.
  ## Raises NftError when the rules can't be checked or applied, or when no SSH port is given
  if sshPorts.len == 0:
    # a wrong guess would lock the user out of their own server
    raise newException(NftError, "Not locking down, the SSH port is not known. " &
        "Set ssh_port under [firewall] or --sshPort")

  if not lockdownIsCurrent(getCurrentRules(), sshPorts):
    writeRulesAndApply(createLockdown(sshPorts))
