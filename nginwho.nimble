# Package

version       = "1.0.0"
author        = "pouriya jamshidi"
description   = "nginwho is a lightweight and extremely fast nginx log parser that stores the result into a sqlite3 database for further analysis and actions"
license       = "MIT"
srcDir        = "src"
bin           = @["nginwho"]


# Dependencies

requires "nim >= 2.0.2"
