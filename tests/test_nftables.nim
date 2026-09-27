import std/[unittest, json, os]
from std/osproc import execCmdEx
from std/strutils import splitLines, startsWith, join, find

from nftables import NftSet, NftAttrs, samplePolicy, createRules, requiredChanges, inetFilterExists, validCidrs

const allChanges = NftAttrs(withV4Set: true, withV6Set: true,
    withNginwhoChain: true, withNginwhoPolicies: true,
    withInputChain: true, withInputPolicy: true)

let tempDir = getTempDir() / "nginwho_test_nftables"
createDir(tempDir)

let cidrs = NftSet(name: "Cloudflare", ipv4: %*["173.245.48.0/20", "103.21.244.0/22"],
    ipv6: %*["2400:cb00::/32", "2606:4700::/32"])


proc canRunNft(): bool =
  execCmdEx("unshare -rn nft list ruleset").exitCode == 0


proc applyInNamespace(rulesFiles: seq[JsonNode], setup = "nft add table inet filter"): JsonNode =
  ## Applies the rules with the real nft in a throwaway network namespace and
  ## returns what `nft -j list ruleset` shows afterwards
  var script = setup
  for i, rules in rulesFiles:
    let path = tempDir / $i & ".json"
    writeFile(path, rules.pretty())
    script &= " && nft -j -f " & quoteShell(path)
  script &= " && nft -j list ruleset"

  let (output, exitCode) = execCmdEx("unshare -rn sh -c " & quoteShell(script))
  doAssert exitCode == 0, output
  return parseJson(output)["nftables"]


suite "nftables":
  test "an empty inet filter table needs everything":
    let ruleset = %*[{"table": {"family": "inet", "name": "filter", "handle": 1}}]
    check inetFilterExists(ruleset)
    check requiredChanges(ruleset, cidrs) == allChanges

  test "no inet table":
    let ruleset = %*[{"table": {"family": "ip", "name": "filter", "handle": 1}}]
    check not inetFilterExists(ruleset)

  test "an inet table with another name is not inet filter":
    let ruleset = %*[{"table": {"family": "inet", "name": "firewalld", "handle": 1}}]
    check not inetFilterExists(ruleset)

  test "only the requested parts are created":
    let rules = createRules(cidrs, NftAttrs(withV6Set: true))["nftables"]
    for command in rules:
      let body = if command.hasKey("add"): command["add"] else: command["flush"]
      check body.hasKey("set")
      check body["set"]["name"].getStr() == "Cloudflare_IPv6"

  test "invalid CIDRs are skipped instead of crashing":
    let withJunk = NftSet(name: "Cloudflare", ipv4: %*["173.245.48.0/20", "junk", 42], ipv6: %*["2400:cb00::/32"])
    let elems = createRules(withJunk, NftAttrs(withV4Set: true))["nftables"][^1]["add"]["set"]["elem"]
    check elems == %*[{"prefix": {"addr": "173.245.48.0", "len": 20}}]

  test "junk CIDRs are dropped":
    check validCidrs(%*["1.2.3.0/24", "not-an-ip/8", "1.2.3.0/33", "1.2.3.0/abc", "1.2.3.0/24/1",
        "2001:db8::/32"]) == @["1.2.3.0/24", "2001:db8::/32"]

  test "single IPs without a prefix length get one":
    check validCidrs(%*["1.2.3.4", "2001:db8::1"]) == @["1.2.3.4/32", "2001:db8::1/128"]

  test "real nft accepts the rules and the next run sees nothing to change":
    # without this nginwho adds the same rules again every six hours
    if not canRunNft():
      skip()
    else:
      let ruleset = applyInNamespace(@[createRules(cidrs, allChanges)])
      check requiredChanges(ruleset, cidrs) == NftAttrs()

  test "changed Cloudflare CIDRs only update the sets":
    if not canRunNft():
      skip()
    else:
      let ruleset = applyInNamespace(@[createRules(cidrs, allChanges)])
      let newCidrs = NftSet(name: "Cloudflare", ipv4: %*["173.245.48.0/20", "103.21.244.0/22", "141.101.64.0/18"],
          ipv6: cidrs.ipv6)
      check requiredChanges(ruleset, newCidrs) == NftAttrs(withV4Set: true)

  test "single IPs are applied and the next run sees nothing to change":
    # nft lists 1.2.3.4/32 back as a plain "1.2.3.4" instead of a prefix
    if not canRunNft():
      skip()
    else:
      let single = NftSet(name: "Cloudflare", ipv4: %*["1.2.3.4", "5.6.7.8/32", "173.245.48.0/20"],
          ipv6: %*["2001:db8::1", "2400:cb00::/32"])
      let ruleset = applyInNamespace(@[createRules(single, allChanges)])
      check requiredChanges(ruleset, single) == NftAttrs()

  test "removed Cloudflare CIDRs are removed from the sets":
    # otherwise they stay allowed and the sets are applied again every six hours
    if not canRunNft():
      skip()
    else:
      let first = applyInNamespace(@[createRules(cidrs, allChanges)])
      let newCidrs = NftSet(name: "Cloudflare", ipv4: %*["173.245.48.0/20"], ipv6: %*["2606:4700::/32"])
      let changes = requiredChanges(first, newCidrs)

      let after = applyInNamespace(@[createRules(cidrs, allChanges), createRules(newCidrs, changes)])
      check requiredChanges(after, newCidrs) == NftAttrs()

  test "switching CDN replaces the old CDN's rules":
    # the old drop rules would block all traffic from the new CDN
    if not canRunNft():
      skip()
    else:
      let fastly = NftSet(name: "Fastly", ipv4: %*["151.101.0.0/16"], ipv6: %*["2a04:4e42::/32"])
      let first = applyInNamespace(@[createRules(cidrs, allChanges)])
      let changes = requiredChanges(first, fastly)
      check changes == NftAttrs(withV4Set: true, withV6Set: true, withNginwhoPolicies: true)

      let after = applyInNamespace(@[createRules(cidrs, allChanges), createRules(fastly, changes)])
      check requiredChanges(after, fastly) == NftAttrs()

      var rules: seq[string]
      for node in after:
        if node.contains("rule") and node["rule"]["chain"].getStr() == "nginwho":
          rules.add(node["rule"]["expr"][0]["match"]["right"].getStr())
      check rules == @["@Fastly_IPv4", "@Fastly_IPv6"]

  test "option 1 of the sample policy nginwho suggests to users works":
    if not canRunNft():
      skip()
    else:
      let start = samplePolicy.find("#!/usr/sbin/nft -f")
      let conf = samplePolicy[start ..< samplePolicy.find("####", start)]
      writeFile(tempDir / "nftables.conf", conf)

      let setup = "nft -f " & quoteShell(tempDir / "nftables.conf")
      let before = applyInNamespace(@[], setup)
      var expected = allChanges
      expected.withInputChain = false
      check requiredChanges(before, cidrs) == expected

      let after = applyInNamespace(@[createRules(cidrs, expected)], setup)
      check requiredChanges(after, cidrs) == NftAttrs()

  test "option 2 of the sample policy nginwho suggests to users works":
    if not canRunNft():
      skip()
    else:
      var commands: seq[string]
      for line in samplePolicy[samplePolicy.find("2) Using") .. ^1].splitLines():
        if line.startsWith("nft "):
          commands.add(line)
      check commands.len > 0

      let setup = commands.join(" && ")
      let before = applyInNamespace(@[], setup)
      var expected = allChanges
      expected.withInputChain = false
      expected.withInputPolicy = false
      check requiredChanges(before, cidrs) == expected

      let after = applyInNamespace(@[createRules(cidrs, expected)], setup)
      check requiredChanges(after, cidrs) == NftAttrs()
