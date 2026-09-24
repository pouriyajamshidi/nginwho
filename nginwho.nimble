# Package

version       = "2.5.0"
author        = "Pouriya Jamshidi"
description   = "nginwho is a lightweight and extremely fast nginx log parser, Cloudflare and Fastly origin IP resolver and non-CDN CIDRs blocker"
license       = "MIT"
srcDir        = "src"
bin           = @["nginwho"]


# Dependencies

requires "nim >= 2.2.0"
requires "db_connector >= 0.1.0"
