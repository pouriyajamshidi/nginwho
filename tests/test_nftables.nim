import std/[unittest, json, os]
from std/osproc import execCmdEx
from std/strutils import contains

from nftables import NftSet, NftAttrs, NftError, createRules, requiredChanges, validCidrs,
    createLockdown, lockdownIsCurrent, parseSshPorts, lockDown

const allChanges = NftAttrs(withV4Set: true, withV6Set: true,
    withNginwhoChain: true,
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
    check requiredChanges(ruleset, cidrs) == allChanges

  test "only the requested parts are created":
    let rules = createRules(cidrs, NftAttrs(withV6Set: true))["nftables"]
    # the table always comes first, adding it does nothing when it exists
    check rules[0] == %*{"add": {"table": {"family": "inet", "name": "filter"}}}
    for command in rules[1 .. ^1]:
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
      check changes == NftAttrs(withV4Set: true, withV6Set: true, withNginwhoChain: true)

      let after = applyInNamespace(@[createRules(cidrs, allChanges), createRules(fastly, changes)])
      check requiredChanges(after, fastly) == NftAttrs()

      var rules: seq[string]
      for node in after:
        # the loopback rule has no Set
        if node.contains("rule") and node["rule"]["chain"].getStr() == "nginwho" and
            node["rule"]["expr"].len > 2:
          # the ports come first, then the Set
          rules.add(node["rule"]["expr"][2]["match"]["right"].getStr())
      # a rule that logs and a rule that drops for each
      check rules == @["@Fastly_IPv4", "@Fastly_IPv4", "@Fastly_IPv6", "@Fastly_IPv6"]

  test "the server can still reach its own web ports":
    # like a health check on localhost. Nothing listens, so a packet that gets through is
    # refused at once, and a dropped one waits for the timeout
    if not canRunNft():
      skip()
    else:
      let path = tempDir / "loopback.json"
      writeFile(path, createRules(cidrs, allChanges).pretty())
      let script = "ip link set lo up && nft add table inet filter && nft -j -f " &
          quoteShell(path) & " && timeout 2 bash -c 'echo > /dev/tcp/127.0.0.1/80'"
      let (output, _) = execCmdEx("unshare -rn sh -c " & quoteShell(script))
      check "refused" in output

  test "a missing inet filter table is created":
    if not canRunNft():
      skip()
    else:
      # no table at all, or only tables nginwho does not use
      for setup in ["true", "nft add table inet firewalld && nft add table ip filter"]:
        let before = applyInNamespace(@[], setup)
        check requiredChanges(before, cidrs) == allChanges

        let after = applyInNamespace(@[createRules(cidrs, allChanges)], setup)
        check requiredChanges(after, cidrs) == NftAttrs()

  test "chains and sets with the same names in other tables are not taken for nginwho's":
    if not canRunNft():
      skip()
    else:
      let setup = "nft add table ip filter && " &
          "nft 'add chain ip filter input { type filter hook input priority filter; policy accept; }' && " &
          "nft add rule ip filter input tcp dport '{ 80, 443 }' counter accept && " &
          "nft add table inet other && nft add chain inet other nginwho && " &
          "nft 'add set inet other Cloudflare_IPv4 { type ipv4_addr; flags interval; }'"
      let before = applyInNamespace(@[], setup)
      check requiredChanges(before, cidrs) == allChanges

      let after = applyInNamespace(@[createRules(cidrs, allChanges)], setup)
      check requiredChanges(after, cidrs) == NftAttrs()

  test "an empty Set is filled instead of crashing the check":
    if not canRunNft():
      skip()
    else:
      let setup = "nft add table inet filter && " &
          "nft 'add set inet filter Cloudflare_IPv4 { type ipv4_addr; flags interval; }'"
      let before = applyInNamespace(@[], setup)
      check requiredChanges(before, cidrs) == allChanges

      let after = applyInNamespace(@[createRules(cidrs, allChanges)], setup)
      check requiredChanges(after, cidrs) == NftAttrs()

  test "an input chain that drops by default is kept and gets the web ports":
    if not canRunNft():
      skip()
    else:
      let setup = "nft add table inet filter && " &
          "nft 'add chain inet filter input { type filter hook input priority filter; policy drop; }' && " &
          "nft add rule inet filter input tcp dport 22 accept"
      let before = applyInNamespace(@[], setup)
      var expected = allChanges
      expected.withInputChain = false
      check requiredChanges(before, cidrs) == expected

      let after = applyInNamespace(@[createRules(cidrs, expected)], setup)
      check requiredChanges(after, cidrs) == NftAttrs()
      var policy = ""
      for node in after:
        if node{"chain", "name"}.getStr() == "input":
          policy = node["chain"]["policy"].getStr()
      check policy == "drop"

  test "a rule put in the nginwho chain by hand is removed":
    if not canRunNft():
      skip()
    else:
      var ruleset = applyInNamespace(@[createRules(cidrs, allChanges)])
      ruleset.add(%*{"rule": {"family": "inet", "table": "filter", "chain": "nginwho",
          "expr": [{"drop": nil}]}})
      check requiredChanges(ruleset, cidrs) == NftAttrs(withNginwhoChain: true)

  test "the nginwho chain of older versions is moved to the raw priority":
    if not canRunNft():
      skip()
    else:
      let setup = "nft add table inet filter && " &
          "nft 'add set inet filter Cloudflare_IPv4 { type ipv4_addr; flags interval; }' && " &
          "nft 'add chain inet filter nginwho { type filter hook prerouting priority -10; policy accept; }' && " &
          "nft add rule inet filter nginwho ip saddr != @Cloudflare_IPv4 tcp dport '{ 80, 443 }' counter log prefix NGINWHO_DROPPED_v4 drop"
      let before = applyInNamespace(@[], setup)
      check requiredChanges(before, cidrs).withNginwhoChain

      let after = applyInNamespace(@[createRules(cidrs, requiredChanges(before, cidrs))], setup)
      check requiredChanges(after, cidrs) == NftAttrs()
      for node in after:
        if node{"chain", "name"}.getStr() == "nginwho":
          check node["chain"]["prio"].getInt() == -300

  test "the tcp only web rule of older versions in the input chain is kept":
    if not canRunNft():
      skip()
    else:
      let setup = "nft add table inet filter && " &
          "nft 'add chain inet filter input { type filter hook input priority filter; policy drop; }' && " &
          "nft add rule inet filter input tcp dport '{ 80, 443 }' counter accept"
      let before = applyInNamespace(@[], setup)
      check not requiredChanges(before, cidrs).withInputPolicy

  test "the ports sshd listens on are read from ss":
    let ss = """
LISTEN 0      128    0.0.0.0:65222 0.0.0.0:* users:(("sshd",pid=1118,fd=5))
LISTEN 0      128    0.0.0.0:2222  0.0.0.0:* users:(("sshd",pid=1118,fd=3))
LISTEN 0      128       [::]:65222    [::]:* users:(("sshd",pid=1118,fd=6))
LISTEN 0      511    0.0.0.0:80    0.0.0.0:* users:(("nginx",pid=900,fd=6))
LISTEN 0      4096         *:22          *:* users:(("systemd",pid=1,fd=86))
"""
    check parseSshPorts(ss) == @[65222, 2222]
    # ss without root shows no processes
    check parseSshPorts("LISTEN 0 128 0.0.0.0:22 0.0.0.0:*") == newSeq[int]()

  test "no lockdown without an SSH port":
    expect NftError:
      lockDown(@[], @[80, 443], @[])

  test "real nft accepts the lockdown and the next run sees nothing to change":
    if not canRunNft():
      skip()
    else:
      let ruleset = applyInNamespace(@[createLockdown(@[65222], @[80, 443], @[])])
      check lockdownIsCurrent(ruleset, @[65222], @[80, 443], @[])
      check not lockdownIsCurrent(ruleset, @[22], @[80, 443], @[])

  test "other web ports, and only one, are seen as current too":
    if not canRunNft():
      skip()
    else:
      var ruleset = applyInNamespace(@[createLockdown(@[65222], @[8080, 8443], @[])])
      check lockdownIsCurrent(ruleset, @[65222], @[8080, 8443], @[])
      check not lockdownIsCurrent(ruleset, @[65222], @[80, 443], @[])
      ruleset = applyInNamespace(@[createLockdown(@[65222], @[8080], @[])])
      check lockdownIsCurrent(ruleset, @[65222], @[8080], @[])

  test "quic ports are opened over UDP, and seen as current":
    if not canRunNft():
      skip()
    else:
      let ruleset = applyInNamespace(@[createLockdown(@[65222], @[80, 443], @[443])])
      check lockdownIsCurrent(ruleset, @[65222], @[80, 443], @[443])
      check not lockdownIsCurrent(ruleset, @[65222], @[80, 443], @[])

  test "a new SSH port replaces the old one":
    if not canRunNft():
      skip()
    else:
      let ruleset = applyInNamespace(@[createLockdown(@[22], @[80, 443], @[]), createLockdown(@[65222], @[80, 443], @[])])
      check lockdownIsCurrent(ruleset, @[65222], @[80, 443], @[])

  test "the lockdown leaves the user's input chain and the nginwho chain alone":
    if not canRunNft():
      skip()
    else:
      let setup = "nft add table inet filter && " &
          "nft 'add chain inet filter input { type filter hook input priority filter; policy accept; }' && " &
          "nft add rule inet filter input udp dport 51820 accept"
      let ruleset = applyInNamespace(@[createRules(cidrs, allChanges), createLockdown(@[65222], @[80, 443], @[])], setup)
      check requiredChanges(ruleset, cidrs) == NftAttrs()
      check lockdownIsCurrent(ruleset, @[65222], @[80, 443], @[])
      var userRule = false
      for node in ruleset:
        if node{"rule", "chain"}.getStr() == "input" and
            node["rule"]["expr"][0]{"match", "right"} == %51820:
          userRule = true
      check userRule
