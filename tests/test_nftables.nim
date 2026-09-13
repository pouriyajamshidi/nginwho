import std/[unittest, json, os, osproc, strutils]

from types import NftSet, NftAttrs
from consts import NFT_SAMPLE_POLICY
from nftables import createRules, requiredChanges, inetFilterExists

const allChanges = NftAttrs(withCloudflareV4Set: true, withCloudflareV6Set: true,
    withNginwhoChain: true, withNginwhoIPv4Policy: true, withNginwhoIPv6Policy: true,
    withInputChain: true, withInputPolicy: true)

let tempDir = getTempDir() / "nginwho_test_nftables"
createDir(tempDir)

let cidrs = NftSet(ipv4: %*["173.245.48.0/20", "103.21.244.0/22"],
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

  test "only the requested parts are created":
    let rules = createRules(cidrs, NftAttrs(withCloudflareV6Set: true))["nftables"]
    for command in rules:
      let body = if command.hasKey("add"): command["add"] else: command["flush"]
      check body.hasKey("set")
      check body["set"]["name"].getStr() == "Cloudflare_IPv6"

  test "invalid CIDRs are skipped instead of crashing":
    let withJunk = NftSet(ipv4: %*["173.245.48.0/20", "junk", 42], ipv6: %*["2400:cb00::/32"])
    let elems = createRules(withJunk, NftAttrs(withCloudflareV4Set: true))["nftables"][^1]["add"]["set"]["elem"]
    check elems == %*[{"prefix": {"addr": "173.245.48.0", "len": 20}}]

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
      let newCidrs = NftSet(ipv4: %*["173.245.48.0/20", "103.21.244.0/22", "141.101.64.0/18"],
          ipv6: cidrs.ipv6)
      check requiredChanges(ruleset, newCidrs) == NftAttrs(withCloudflareV4Set: true)

  test "single IPs are applied and the next run sees nothing to change":
    # nft lists 1.2.3.4/32 back as a plain "1.2.3.4" instead of a prefix
    if not canRunNft():
      skip()
    else:
      let single = NftSet(ipv4: %*["1.2.3.4", "5.6.7.8/32", "173.245.48.0/20"],
          ipv6: %*["2001:db8::1", "2400:cb00::/32"])
      let ruleset = applyInNamespace(@[createRules(single, allChanges)])
      check requiredChanges(ruleset, single) == NftAttrs()

  test "removed Cloudflare CIDRs are removed from the sets":
    # otherwise they stay allowed and the sets are applied again every six hours
    if not canRunNft():
      skip()
    else:
      let first = applyInNamespace(@[createRules(cidrs, allChanges)])
      let newCidrs = NftSet(ipv4: %*["173.245.48.0/20"], ipv6: %*["2606:4700::/32"])
      let changes = requiredChanges(first, newCidrs)

      let after = applyInNamespace(@[createRules(cidrs, allChanges), createRules(newCidrs, changes)])
      check requiredChanges(after, newCidrs) == NftAttrs()

  test "option 1 of the sample policy nginwho suggests to users works":
    if not canRunNft():
      skip()
    else:
      let start = NFT_SAMPLE_POLICY.find("#!/usr/sbin/nft -f")
      let conf = NFT_SAMPLE_POLICY[start ..< NFT_SAMPLE_POLICY.find("####", start)]
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
      for line in NFT_SAMPLE_POLICY[NFT_SAMPLE_POLICY.find("2) Using") .. ^1].splitLines():
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
