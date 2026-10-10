# Package

version       = "3.0.0"
author        = "Pouriya Jamshidi"
description   = "A small and fast tool that looks after your website: saves your nginx logs, shows real visitor IPs behind Cloudflare or Fastly, blocks everyone but your CDN, traps bots and serves static sites"
license       = "MIT"
srcDir        = "src"
bin           = @["nginwho"]


# Dependencies

requires "nim >= 2.2.0"
requires "db_connector >= 0.1.0"
