import std/[unittest, os, options]

from config import Args, readConfigFile
from cdn import Cdn
from trap import Tactic

let tempDir = getTempDir() / "nginwho_test_config"
removeDir(tempDir)
createDir(tempDir)


proc read(content: string): Args =
  ## Writes `content` to a config file and reads it over the defaults
  let path = tempDir / "nginwho.conf"
  writeFile(path, content)
  result = Args()
  readConfigFile(path, result)


suite "config file":
  test "every setting is read":
    let args = read("""
[database]
path = /tmp/visits.db

[nginx]
process_logs = true
log_path = /tmp/access.log
interval = 30
omit_referrer = example.com
cdn = fastly
show_real_ips = true
block_untrusted_cidrs = true

[server]
enabled = true
root = /srv/site
port = 8080
cert = /etc/ssl/site.pem
key = /etc/ssl/site.key

[firewall]
lockdown = true
ssh_port = 65222

[trap]
enabled = true
port = 7000
max_connections = 50
max_seconds = 60
drip_min_ms = 100
drip_max_ms = 200
bombs = false
bomb_after = 5
max_saved_hits_a_day = 0
files = /etc/nginwho/traps
""")
    check args.dbPath == "/tmp/visits.db"
    check args.processNginxLogs
    check args.logPath == "/tmp/access.log"
    check args.interval == 30_000
    check args.omitReferrer == "example.com"
    check args.cdn == Fastly
    check args.showRealIPs
    check args.blockUntrustedCidrs
    check args.serve
    check args.root == "/srv/site"
    check args.port == 8080
    check args.cert == "/etc/ssl/site.pem"
    check args.key == "/etc/ssl/site.key"
    check args.lockdown
    check args.sshPort == 65222
    check args.trap.enabled
    check args.trap.port == 7000
    check args.trap.maxConnections == 50
    check args.trap.maxSeconds == 60
    check args.trap.dripMinMs == 100
    check args.trap.dripMaxMs == 200
    check not args.trap.bombs
    check args.trap.bombAfter == 5
    check args.trap.maxSavedHitsADay == 0
    check args.trap.files == "/etc/nginwho/traps"

  test "a missing file keeps every default":
    var args = Args()
    readConfigFile(tempDir / "missing.conf", args)
    check args == Args()

  test "agents are saved lowercase, with or without a tactic":
    let args = read("""
[trap.agents]
DeepSeek = drip
gptbot = maze
bytespider
""")
    check args.trap.agents == @[
      ("deepseek", some(Tactic.drip)),
      ("gptbot", some(Tactic.maze)),
      ("bytespider", none(Tactic)),
    ]

  test "a drip minimum above the maximum keeps both defaults":
    let args = read("[trap]\ndrip_min_ms = 900\ndrip_max_ms = 100\n")
    check args.trap.dripMinMs == Args().trap.dripMinMs
    check args.trap.dripMaxMs == Args().trap.dripMaxMs
