# begin Nimble config (version 2)
when withDir(thisDir(), system.fileExists("nimble.paths")):
  include "nimble.paths"
# end Nimble config

# fetching the CDN ranges needs https, and so does the server with a certificate.
# here so that nimble install and the tests get it too, not only the release build
switch("define", "ssl")
