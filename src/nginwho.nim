import std/asyncdispatch
from std/strformat import fmt
from std/strutils import parseBool, splitLines, startsWith, split, strip
from db_connector/db_common import DbError
from std/os import getFileInfo, FileInfo, FileId, dirExists, fileExists,
    createDir, parentDir
from std/net import Port
from std/posix import RLimit, getrlimit, setrlimit, RLIMIT_NOFILE
from std/parseopt import CmdLineKind, initOptParser, next
from std/logging import addHandler, newConsoleLogger, info, error, warn,
    setLogFilter, lvlError

from nginx import Log, isStaticAsset, readChunkBytes, ensureNginxExists,
    ensureNginxLogExists, parseLogEntry, readNewLines, offsetAfterLastInserted
from cdn import Cdn, fetchAndProcessIPCidrs, visitorIP, realIpHeaders, fromCdn,
    firewallCheckMs
from nftables import ensureNftExists, NftError, lockDown, findSshPorts
from database import getDbConnection, closeDbConnection,
    createTables, insertLogs, getLastRow
from report import report
from server import serve, RealIP, Request, header
from trap import trap, trapHook
from config import Args, readConfigFile, parsePort, parseInterval, parseCdn,
    defaultConfigFile, defaultDbPath, oldDbPath, nginxLogPath, serveLogPath


proc nimbleVersion(): string =
  ## Reads the version from nginwho.nimble at compile time
  for line in staticRead("../nginwho.nimble").splitLines:
    if line.startsWith("version"):
      return line.split('=')[1].strip.strip(chars = {'"'})

const
  version* = nimbleVersion()
  maintainer* = "Pouriya Jamshidi"
  maxInsertAttempts = 3

addHandler(newConsoleLogger(fmtStr = "[$date -- $time] - $levelname: "))



proc usage(errorCode: int = 0) =
  echo """

  --help, -h              : Show help
  --version, -v           : Display version and quit
  --dbPath                : Path to SQLite database to log reports (default: /var/lib/nginwho/nginwho.db)
  --logPath               : Path to nginx access logs (default: /var/log/nginx/access.log,
                            or /var/log/nginwho/access.log with '--serve')
  --interval              : Refresh interval in seconds (default: 10)
  --omitReferrer          : Don't save referrers from this domain and its subdomains (default: none)
  --showRealIps           : Show real IP of visitors by getting the CDN's CIDRs to include in nginx config,
                            or with '--serve' to trust the CDN's header. Self-updates every six hours (default: false)
  --blockUntrustedCidrs   : Block untrusted IP addresses using nftables. Only allows the CDN's CIDRs (default: false)
  --lockdown              : Drop everything coming in but SSH, ports 80 and 443 and replies
                            to the server's own connections, using nftables (default: false)
  --sshPort               : SSH port to keep open with '--lockdown' (default: the port sshd listens on)
  --cdn                   : The CDN in front of your site, cloudflare or fastly (default: cloudflare)
  --processNginxLogs      : Process nginx logs (default: false)
  --serve                 : Serve static files and write nginx style logs to '--logPath' (default: false)
  --root                  : Directory to serve files from (default: /var/www/html)
  --port                  : Port to serve on, IPv4 and IPv6 (default: 80)
  --cert                  : Certificate file to serve HTTPS with, like nginx's ssl_certificate.
                            Loaded again when it changes, so renewals need no restart
  --key                   : Key file for '--cert', like nginx's ssl_certificate_key
  --report               : Enter report mode and query the database for statistics
  --config                : Path to the config file (default: /etc/nginwho/nginwho.conf).
                            Command line flags win over it
  --trap                  : Play with bots that probe for files we do not have.
                            nginx forwards its 403s and 404s to us, or with '--serve'
                            the server hands them over itself (default: false)
  --trapPort              : Port the trap listens on for nginx, on localhost only (default: 7777)

  """
  quit(errorCode)


proc validateArgs(args: Args) =
  if not args.processNginxLogs and
  not args.report and
  not args.showRealIPs and
  not args.blockUntrustedCidrs and
  not args.lockdown and
  not args.serve and
  not args.trap.enabled:
    error("Provided flags say do nothing... Exiting")
    usage(1)

  if (args.cert == "") != (args.key == ""):
    error("HTTPS needs both --cert and --key")
    usage(1)


proc isOn(value: string): bool =
  ## A flag on its own is on, and `--serve=false` turns it off
  value == "" or parseBool(value)


proc getArgs(): Args =
  # Args() and not `var args: Args`, only the constructor fills in the defaults
  var args = Args()

  # the config file comes first so that command line flags can win over it
  var configPath = defaultConfigFile
  var configParser = initOptParser()
  while true:
    configParser.next()
    case configParser.kind
    of cmdEnd: break
    of cmdShortOption, cmdLongOption:
      if configParser.key == "config": configPath = configParser.val
    of cmdArgument: discard
  readConfigFile(configPath, args)

  var p = initOptParser()

  while true:
    p.next()
    case p.kind
    of cmdEnd: break
    of cmdShortOption, cmdLongOption:
      try:
        case p.key
        of "report": args.report = isOn(p.val)
        of "config": discard # already read
        of "trap": args.trap.enabled = isOn(p.val)
        of "trapPort": args.trap.port = parsePort(p.val)
        of "help", "h": usage()
        of "version", "v":
          echo version
          echo maintainer
          quit(0)

        of "logPath": args.logPath = p.val
        of "dbPath": args.dbPath = p.val
        of "interval": args.interval = parseInterval(p.val)
        of "omitReferrer": args.omitReferrer = p.val
        of "cdn": args.cdn = parseCdn(p.val)
        of "showRealIps": args.showRealIPs = isOn(p.val)
        of "blockUntrustedCidrs": args.blockUntrustedCidrs = isOn(p.val)
        of "lockdown": args.lockdown = isOn(p.val)
        of "sshPort": args.sshPort = parsePort(p.val)
        of "processNginxLogs": args.processNginxLogs = isOn(p.val)
        of "serve": args.serve = isOn(p.val)
        of "root": args.root = p.val
        of "port": args.port = parsePort(p.val)
        of "cert": args.cert = p.val
        of "key": args.key = p.val
      except ValueError as e:
        error(fmt"Bad value '{p.val}' for --{p.key}: {e.msg}")
        usage(1)
    of cmdArgument:
      # "--omitReferrer example.com" gives the flag no value, so the value must not be ignored
      error(fmt"Unexpected argument '{p.key}'. Give flag values with = or :, like --omitReferrer=example.com")
      usage(1)

  # the server writes its own log, the nginx one belongs to nginx
  if args.logPath == "":
    args.logPath = if args.serve: serveLogPath else: nginxLogPath

  # older versions kept the database in /var/log. keep using it until it is moved
  if args.dbPath == defaultDbPath and not fileExists(defaultDbPath) and
      fileExists(oldDbPath):
    warn(fmt"Using the old database at {oldDbPath}. Stop nginwho and move it to {defaultDbPath}")
    args.dbPath = oldDbPath

  validateArgs(args)

  return args


proc processAndRecordLogs(args: Args) {.async.} =
  info("Processing log entries")

  let db = getDbConnection(args.dbPath)
  defer: closeDbConnection(db)

  createTables(db)

  var
    offset: int64 = 0
    fileId: FileId
    failedInserts = 0

  while true:
    var fileInfo: FileInfo
    try:
      fileInfo = getFileInfo(args.logPath)
    except OSError as e:
      warn(fmt"Could not read {args.logPath}: {e.msg}")
      await sleepAsync(args.interval)
      continue

    var
      logs: seq[Log]
      lines: seq[string]
      previousOffset: int64

    try:
      # first run, rotated or truncated log. skip the lines saved before a restart,
      # a new log has none of them so this starts from the beginning
      if fileInfo.id.file != fileId or fileInfo.size < offset:
        fileId = fileInfo.id.file
        offset = offsetAfterLastInserted(args.logPath, getLastRow(db))

      if fileInfo.size == offset:
        info(fmt"{args.logPath} has no new logs... sleeping")
        await sleepAsync(args.interval)
        continue

      previousOffset = offset
      lines = readNewLines(args.logPath, offset)
    except IOError as e:
      warn(fmt"Could not read {args.logPath}: {e.msg}")
      await sleepAsync(args.interval)
      continue

    for line in lines:
      if line.len == 0:
        continue

      let log = parseLogEntry(line, args.omitReferrer)

      if isStaticAsset(log.requestURI):
        continue

      logs.add(log)

    info(fmt"Got {logs.len} logs to process")

    if logs.len == 0:
      info("Database is up to date with the latest logs")
    elif insertLogs(db, logs):
      failedInserts = 0
    else:
      failedInserts += 1
      # read the same lines again next time, but don't get stuck on logs that can never be saved
      if failedInserts < maxInsertAttempts:
        warn(fmt"Will retry these logs in {args.interval div 1000} seconds")
        offset = previousOffset
      else:
        error(fmt"Dropping {logs.len} logs after {maxInsertAttempts} failed inserts")
        failedInserts = 0

    # a big log is read in chunks, keep going without waiting until it is caught up
    let moreToRead = failedInserts == 0 and fileInfo.size - previousOffset > readChunkBytes
    await sleepAsync(if moreToRead: 0 else: args.interval)


proc keepLockedDown(sshPort: int) {.async.} =
  ## Checks the lockdown every few minutes, so it is back soon after a firewall reload
  ## wipes it, and follows sshd when it moves to another port
  while true:
    let sshPorts = if sshPort != 0: @[sshPort] else: findSshPorts()
    try:
      lockDown(sshPorts)
    except NftError as e:
      # a firewall problem must not stop anything else nginwho runs
      error(e.msg)
    await sleepAsync(firewallCheckMs)


proc raiseOpenFileLimit() =
  ## The usual limit of 1024 open files is low for a web server and a trap together.
  ## Must run before anything async, the event loop reads the limit once
  var limit: RLimit
  if getrlimit(RLIMIT_NOFILE, limit) == 0 and limit.rlim_cur < limit.rlim_max:
    limit.rlim_cur = limit.rlim_max
    discard setrlimit(RLIMIT_NOFILE, limit)


proc runPreChecks(args: Args) =
  info("Running pre-checks based on provided user arguments")

  if args.serve:
    if not dirExists(args.root):
      error(fmt"Directory to serve not found at: {args.root}")
      quit(1)
    # the server creates the log, nginx is not needed
    if not fileExists(args.logPath):
      createDir(args.logPath.parentDir)
      writeFile(args.logPath, "")
  elif args.processNginxLogs:
    ensureNginxLogExists(args.logPath)

  # only --showRealIps runs nginx, to test and reload its config. reading its log needs no nginx.
  # with --serve there is no nginx, the server reads the real IP itself
  if args.showRealIPs and not args.serve:
    ensureNginxExists()

  if args.blockUntrustedCidrs or args.lockdown:
    ensureNftExists()


proc main() =
  # parse args first so --help and --version print nothing else
  let args = getArgs()

  if args.report:
    # info logs would get mixed with the report output
    setLogFilter(lvlError)
    report(args.dbPath)
    return

  info("Starting nginwho")

  raiseOpenFileLimit()
  runPreChecks(args)

  if args.serve:
    # nginwho is the web server here, so it hands probes to the trap itself instead of nginx
    let hook = if args.trap.enabled: trapHook(args.trap, args.dbPath) else: nil
    # behind a CDN, the visitor's IP is in the CDN's header instead of the connection
    let cdn = args.cdn
    let realIP: RealIP =
      if args.showRealIPs:
        proc (peer: string, req: Request): string =
          visitorIP(peer, req.header(realIpHeaders[cdn]))
      else: nil
    asyncCheck serve(args.root, args.logPath, Port(args.port), trapHook = hook,
        realIP = realIP, fromCdn = fromCdn, cert = args.cert, key = args.key)

  if args.trap.enabled and not args.serve:
    asyncCheck trap(args.trap, args.dbPath)

  if args.processNginxLogs:
    asyncCheck processAndRecordLogs(args)

  if args.showRealIPs:
    if not args.serve:
      warn("Do not forget to add `include /etc/nginx/nginwho;` in your nginx config file")
    if args.cdn == Fastly:
      warn("Fastly keeps a Fastly-Client-IP header sent by visitors, so they can fake their IP. " &
          "Set it to client.ip in your Fastly VCL, see the README")

  if args.lockdown:
    asyncCheck keepLockedDown(args.sshPort)

  if args.showRealIPs or args.blockUntrustedCidrs:
    asyncCheck fetchAndProcessIPCidrs(args.cdn, args.showRealIPs,
        args.blockUntrustedCidrs, args.serve)

  runForever()

when isMainModule:
  try:
    main()
  except DbError, IOError, OSError:
    # these end the program when they happen at start, or in an async task
    error(getCurrentExceptionMsg())
    quit(1)
