# Package

version       = "2.0.0"
author        = "pouriya jamshidi"
description   = "nginwho is a lightweight and extremely fast nginx log parser, Cloudflare origin IP resolver and non-Cloudflare CIDRs blocker"
license       = "MIT"
srcDir        = "src"
bin           = @["nginwho"]


# Dependencies

requires "nim >= 2.2.0"
