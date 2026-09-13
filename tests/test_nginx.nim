import std/[unittest, os, json, options, strutils]

from types import Log, Logs, Cidrs
from nginx import parseLogEntry, readNewLines, dropAlreadyInserted, populateReverseProxyFile
from cloudflare import getCurrentEtag, parseCidrsResponse
from nftables import createNftSetsFrom

let tempDir = getTempDir() / "nginwho_test_nginx"
createDir(tempDir)


suite "parseLogEntry":
  # nginx default "combined" format
  const line = """203.0.113.7 - - [13/Sep/2026:10:15:32 +0000] "GET /blog/post/ HTTP/1.1" 200 5120 "https://example.com/" "Mozilla/5.0 (X11; Linux x86_64) Firefox/130.0""""

  test "parses every field of a combined log line":
    let log = parseLogEntry(line, "")
    check log.remoteIP == "203.0.113.7"
    check log.date == "2026-09-13 10:15:32"
    check log.httpMethod == "GET"
    check log.requestURI == "/blog/post"
    check log.statusCode == "200"
    check log.responseSize == "5120"
    check log.referrer == "https://example.com"
    check log.userAgent == "Mozilla/5.0 (X11; Linux x86_64) Firefox/130.0"
    check log.nonDefault == ""

  test "keeps the root URI":
    let log = parseLogEntry("""203.0.113.7 - - [13/Sep/2026:10:15:32 +0000] "GET / HTTP/1.1" 200 1 "-" "curl/8.0"""", "")
    check log.requestURI == "/"

  test "a missing referrer is stored as empty":
    let log = parseLogEntry("""203.0.113.7 - - [13/Sep/2026:10:15:32 +0000] "GET / HTTP/1.1" 200 1 "-" "curl/8.0"""", "")
    check log.referrer == ""
    check log.userAgent == "curl/8.0"

  test "an empty user agent is stored like a missing one":
    let log = parseLogEntry("""203.0.113.7 - - [13/Sep/2026:10:15:32 +0000] "GET / HTTP/1.1" 200 1 "-" """"", "")
    check log.userAgent == "-"
    check log.nonDefault == ""

  test "omitted referrer is dropped":
    check parseLogEntry(line, "example.com").referrer == ""
    check parseLogEntry(line, "other.org").referrer == "https://example.com"

  test "IPv6 clients":
    let log = parseLogEntry("""2001:db8::1 - - [01/Jan/2026:00:00:00 +0000] "POST /api HTTP/2.0" 201 0 "-" "curl/8.0"""", "")
    check log.remoteIP == "2001:db8::1"
    check log.httpMethod == "POST"
    check log.date == "2026-01-01 00:00:00"

  test "short lines become non-default instead of crashing":
    # what nginx writes when a client sends garbage, e.g. TLS on port 80
    let junk = """198.51.100.1 - - [13/Sep/2026:10:15:32 +0000] "\x16\x03\x01\x00\xF7\x01" 400 157 "-" "-""""
    let log = parseLogEntry(junk, "")
    check log.nonDefault == junk
    check log.date == ""

  test "a bad date becomes non-default instead of crashing":
    let bad = """203.0.113.7 - - [99/Foo/2026:10:15:32 +0000] "GET / HTTP/1.1" 200 1 "-" "curl/8.0""""
    let log = parseLogEntry(bad, "")
    check log.nonDefault == bad

  test "empty line":
    check parseLogEntry("", "").nonDefault == ""


suite "readNewLines":
  let path = tempDir / "access.log"

  setup:
    writeFile(path, "")

  test "reads only what was added since the last read":
    var offset: int64 = 0
    writeFile(path, "one\ntwo\n")
    check readNewLines(path, offset) == @["one", "two"]
    check offset == 8

    check readNewLines(path, offset).len == 0

    let f = open(path, fmAppend)
    f.write("three\n")
    f.close()
    check readNewLines(path, offset) == @["three"]

  test "leaves a half written last line for the next read":
    var offset: int64 = 0
    writeFile(path, "one\ntw")
    check readNewLines(path, offset) == @["one"]
    check offset == 4

    let f = open(path, fmAppend)
    f.write("o\n")
    f.close()
    check readNewLines(path, offset) == @["two"]

  test "no complete line yet":
    var offset: int64 = 0
    writeFile(path, "partial")
    check readNewLines(path, offset).len == 0
    check offset == 0


suite "dropAlreadyInserted":
  proc log(date, uri: string): Log =
    Log(date: date, remoteIP: "1.1.1.1", httpMethod: "GET", requestURI: uri)

  test "keeps everything when the database is empty":
    let logs = @[log("2026-09-13 10:00:00", "/a"), log("2026-09-13 10:00:01", "/b")]
    check dropAlreadyInserted(logs, Log()) == logs

  test "keeps only the logs after the last saved one":
    let logs = @[log("2026-09-13 10:00:00", "/a"), log("2026-09-13 10:00:01", "/b"),
        log("2026-09-13 10:00:02", "/c")]
    check dropAlreadyInserted(logs, logs[1]) == @[logs[2]]

  test "same request repeated in one second is matched from the end":
    let same = log("2026-09-13 10:00:00", "/a")
    let logs = @[same, same, same, log("2026-09-13 10:00:01", "/b")]
    check dropAlreadyInserted(logs, same) == @[logs[3]]

  test "nothing new":
    let logs = @[log("2026-09-13 10:00:00", "/a")]
    check dropAlreadyInserted(logs, logs[0]).len == 0

  test "keeps everything when the last saved log is not in the file (rotated log)":
    let logs = @[log("2026-09-14 00:00:00", "/a")]
    check dropAlreadyInserted(logs, log("2026-09-13 23:59:59", "/z")) == logs


suite "cloudflare CIDRs file":
  # shape of https://api.cloudflare.com/client/v4/ips
  let apiResponse = parseJson("""{
    "result": {
      "ipv4_cidrs": ["173.245.48.0/20", "103.21.244.0/22"],
      "ipv6_cidrs": ["2400:cb00::/32", "2606:4700::/32"],
      "etag": "38f79d050aa027e3be3865e495dcc9bc"
    },
    "success": true, "errors": [], "messages": []
  }""")

  test "parses the API response":
    let cidrs = parseCidrsResponse(apiResponse)
    check cidrs.isSome
    check cidrs.get.etag == "38f79d050aa027e3be3865e495dcc9bc"
    check cidrs.get.ipv4.len == 2
    check cidrs.get.ipv6.len == 2

  test "rejects failed or incomplete responses":
    check parseCidrsResponse(parseJson("""{"success": false, "result": {"ipv4_cidrs": [], "ipv6_cidrs": []}}""")).isNone
    check parseCidrsResponse(parseJson("""{"success": true, "result": {"ipv4_cidrs": []}}""")).isNone
    check parseCidrsResponse(parseJson("{}")).isNone
    check parseCidrsResponse(parseJson("""{"success": true, "result": {"ipv4_cidrs": ["1.1.1.0/24"], "ipv6_cidrs": []}}""")).isNone

  test "written file gives back the same etag and CIDRs":
    # the etag decides if nginx gets reloaded, the CIDRs feed nftables
    let path = tempDir / "nginwho"
    let cidrs = parseCidrsResponse(apiResponse).get
    check populateReverseProxyFile(path, cidrs)

    check getCurrentEtag(path) == cidrs.etag

    let sets = createNftSetsFrom(path)
    check sets.ipv4 == cidrs.ipv4
    check sets.ipv6 == cidrs.ipv6

    let content = readFile(path)
    check "set_real_ip_from 173.245.48.0/20;" in content
    check "real_ip_header CF-Connecting-IP;" in content

  test "file is not rewritten when the etag did not change":
    let path = tempDir / "nginwho_unchanged"
    writeFile(path, "old")
    var cidrs = parseCidrsResponse(apiResponse).get
    cidrs.etagChanged = false
    check not populateReverseProxyFile(path, cidrs)
    check readFile(path) == "old"

  test "no etag when the file does not exist":
    check getCurrentEtag(tempDir / "missing") == ""

  test "reading CIDRs skips junk, comments and trailing spaces":
    let path = tempDir / "nginwho_hand_edited"
    writeFile(path, "# comment\n\nset_real_ip_from 1.2.3.0/24;   \nset_real_ip_from not-an-ip/8;\n" &
      "set_real_ip_from 1.2.3.0/33;\nset_real_ip_from 1.2.3.0/abc;\nset_real_ip_from 1.2.3.0/24/1;\n" &
      "set_real_ip_from 2001:db8::/32;\nreal_ip_header CF-Connecting-IP;\n")
    let sets = createNftSetsFrom(path)
    check sets.ipv4 == %*["1.2.3.0/24"]
    check sets.ipv6 == %*["2001:db8::/32"]

  test "single IPs without a prefix length get one":
    let path = tempDir / "nginwho_single_ips"
    writeFile(path, "set_real_ip_from 1.2.3.4;\nset_real_ip_from 2001:db8::1;\n")
    let sets = createNftSetsFrom(path)
    check sets.ipv4 == %*["1.2.3.4/32"]
    check sets.ipv6 == %*["2001:db8::1/128"]
