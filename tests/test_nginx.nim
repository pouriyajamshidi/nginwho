import std/[unittest, os, json]
from std/options import isSome, isNone, get
from std/strutils import contains

from nginx import Log, parseLogEntry, isFromDomain, readNewLines, offsetAfterLastInserted
from cdn import Cdn, Cidrs, getCurrentEtag, parseCidrsResponse, populateReverseProxyFile,
    trustRanges, visitorIP

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

  test "only the referrer's domain and its subdomains are omitted":
    check isFromDomain("https://example.com/posts/x/", "example.com")
    check isFromDomain("https://www.Example.com", "example.com")
    check isFromDomain("http://blog.example.com:8080/", "example.com")
    check not isFromDomain("https://google.com/search?q=example.com", "example.com")
    check not isFromDomain("https://notexample.com", "example.com")
    check not isFromDomain("https://example.com.evil.org", "example.com")
    check not isFromDomain("-", "example.com")

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

  test "reads a big file in chunks":
    var offset: int64 = 0
    writeFile(path, "one\ntwo\nthree\n")
    check readNewLines(path, offset, maxBytes = 9) == @["one", "two"]
    check readNewLines(path, offset, maxBytes = 9) == @["three"]
    check offset == 14

  test "a line longer than a chunk is skipped instead of getting stuck":
    var offset: int64 = 0
    writeFile(path, "0123456789")
    check readNewLines(path, offset, maxBytes = 4).len == 0
    check offset == 4

  test "no complete line yet":
    var offset: int64 = 0
    writeFile(path, "partial")
    check readNewLines(path, offset).len == 0
    check offset == 0


suite "offsetAfterLastInserted":
  let path = tempDir / "resume.log"
  const
    a = """1.1.1.1 - - [13/Sep/2026:10:00:00 +0000] "GET /a HTTP/1.1" 200 1 "-" "curl/8.0""""
    b = """2.2.2.2 - - [13/Sep/2026:10:00:01 +0000] "GET /b HTTP/1.1" 200 1 "-" "curl/8.0""""

  test "starts from the beginning when the database is empty":
    writeFile(path, a & "\n" & b & "\n")
    check offsetAfterLastInserted(path, Log()) == 0

  test "starts right after the last saved log":
    writeFile(path, a & "\n" & b & "\n")
    check offsetAfterLastInserted(path, parseLogEntry(a, "")) == a.len + 1

  test "same request repeated in one second is matched from the end":
    writeFile(path, a & "\n" & a & "\n" & b & "\n")
    check offsetAfterLastInserted(path, parseLogEntry(a, "")) == 2 * (a.len + 1)

  test "nothing new":
    writeFile(path, a & "\n")
    check offsetAfterLastInserted(path, parseLogEntry(a, "")) == a.len + 1

  test "starts from the beginning when the last saved log is not in the file (rotated log)":
    writeFile(path, b & "\n")
    check offsetAfterLastInserted(path, parseLogEntry(a, "")) == 0


suite "CDN CIDRs file":
  # shape of https://api.cloudflare.com/client/v4/ips
  let apiResponse = parseJson("""{
    "result": {
      "ipv4_cidrs": ["173.245.48.0/20", "103.21.244.0/22"],
      "ipv6_cidrs": ["2400:cb00::/32", "2606:4700::/32"],
      "etag": "38f79d050aa027e3be3865e495dcc9bc"
    },
    "success": true, "errors": [], "messages": []
  }""")

  # shape of https://api.fastly.com/public-ip-list
  let fastlyResponse = parseJson("""{
    "addresses": ["23.235.32.0/20", "151.101.0.0/16"],
    "ipv6_addresses": ["2a04:4e40::/32", "2a04:4e42::/32"]
  }""")

  test "parses the API response":
    let cidrs = parseCidrsResponse(Cloudflare, apiResponse)
    check cidrs.isSome
    check cidrs.get.etag != ""
    check cidrs.get.ipv4.len == 2
    check cidrs.get.ipv6.len == 2

  test "parses the Fastly API response":
    let cidrs = parseCidrsResponse(Fastly, fastlyResponse)
    check cidrs.isSome
    check cidrs.get.ipv4 == %*["23.235.32.0/20", "151.101.0.0/16"]
    check cidrs.get.ipv6.len == 2

  test "the etag only changes when the ranges or the CDN change":
    # Fastly has no etag, so we make one. a new order alone must not reload nginx
    let etag = parseCidrsResponse(Fastly, fastlyResponse).get.etag
    let reordered = parseJson("""{
      "addresses": ["151.101.0.0/16", "23.235.32.0/20"],
      "ipv6_addresses": ["2a04:4e42::/32", "2a04:4e40::/32"]
    }""")
    let added = parseJson("""{
      "addresses": ["23.235.32.0/20", "151.101.0.0/16", "199.232.0.0/16"],
      "ipv6_addresses": ["2a04:4e40::/32", "2a04:4e42::/32"]
    }""")
    check parseCidrsResponse(Fastly, reordered).get.etag == etag
    check parseCidrsResponse(Fastly, added).get.etag != etag

    let sameRanges = parseJson("""{"success": true, "result": {
      "ipv4_cidrs": ["23.235.32.0/20", "151.101.0.0/16"],
      "ipv6_cidrs": ["2a04:4e40::/32", "2a04:4e42::/32"]}}""")
    check parseCidrsResponse(Cloudflare, sameRanges).get.etag != etag

  test "rejects failed or incomplete responses":
    check parseCidrsResponse(Cloudflare, parseJson("""{"success": false, "result": {"ipv4_cidrs": [], "ipv6_cidrs": []}}""")).isNone
    check parseCidrsResponse(Cloudflare, parseJson("""{"success": true, "result": {"ipv4_cidrs": []}}""")).isNone
    check parseCidrsResponse(Cloudflare, parseJson("{}")).isNone
    check parseCidrsResponse(Cloudflare, parseJson("""{"success": true, "result": {"ipv4_cidrs": ["1.1.1.0/24"], "ipv6_cidrs": []}}""")).isNone
    check parseCidrsResponse(Fastly, parseJson("{}")).isNone
    check parseCidrsResponse(Fastly, parseJson("""{"addresses": ["1.1.1.0/24"], "ipv6_addresses": []}""")).isNone

  test "the real IP header only counts when the CDN sent the request":
    # nothing is trusted before the ranges are fetched
    check visitorIP("23.235.32.9", "203.0.113.7") == "23.235.32.9"

    trustRanges(parseCidrsResponse(Fastly, fastlyResponse).get)
    check visitorIP("23.235.32.9", "203.0.113.7") == "203.0.113.7"
    check visitorIP("23.235.47.255", "203.0.113.7") == "203.0.113.7"
    check visitorIP("2a04:4e42:10::5", "2001:db8::1") == "2001:db8::1"
    # a visitor talking to us directly can't pick their own IP
    check visitorIP("23.235.48.0", "203.0.113.7") == "23.235.48.0"
    check visitorIP("198.51.100.4", "203.0.113.7") == "198.51.100.4"
    check visitorIP("2a04:4e41::5", "2001:db8::1") == "2a04:4e41::5"
    # no header, or not an IP
    check visitorIP("23.235.32.9", "") == "23.235.32.9"
    check visitorIP("23.235.32.9", "evil\"quote") == "23.235.32.9"
    # a Cloudflare response is not a Fastly one
    check parseCidrsResponse(Fastly, apiResponse).isNone

  test "a bad range from the CDN is skipped instead of crashing the check":
    trustRanges(Cidrs(cdn: Fastly, ipv4: %*["23.235.32.0/40", "nope/20", "23.235.32.9"],
        ipv6: %*["2a04:4e42::/200"]))
    check visitorIP("23.235.32.9", "203.0.113.7") == "203.0.113.7"
    check visitorIP("23.235.32.10", "203.0.113.7") == "23.235.32.10"
    check visitorIP("2a04:4e42::5", "2001:db8::1") == "2a04:4e42::5"

  test "written file gives back the same etag and CIDRs":
    # the etag decides if nginx gets reloaded, the CIDRs feed nftables
    let path = tempDir / "nginwho"
    let cidrs = parseCidrsResponse(Cloudflare, apiResponse).get
    check populateReverseProxyFile(path, cidrs)

    check getCurrentEtag(path) == cidrs.etag

    let content = readFile(path)
    check "set_real_ip_from 173.245.48.0/20;" in content
    check "real_ip_header CF-Connecting-IP;" in content

  test "the Fastly file trusts Fastly's header":
    let path = tempDir / "nginwho_fastly"
    let cidrs = parseCidrsResponse(Fastly, fastlyResponse).get
    check populateReverseProxyFile(path, cidrs)

    check getCurrentEtag(path) == cidrs.etag

    let content = readFile(path)
    check "# Fastly ranges" in content
    check "set_real_ip_from 151.101.0.0/16;" in content
    check "set_real_ip_from 2a04:4e42::/32;" in content
    check "real_ip_header Fastly-Client-IP;" in content

  test "no etag when the file does not exist":
    check getCurrentEtag(tempDir / "missing") == ""

