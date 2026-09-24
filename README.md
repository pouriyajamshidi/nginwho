# nginwho

<div align="center" style="width: 100%;">
 <img alt="nginwho" src="https://github.com/pouriyajamshidi/nginwho/blob/master/artwork/nginwho.jpeg?raw=true" width="700">
</div>

---

**nginwho** is a lightweight, efficient and extremely fast program offering:

1. [nginx log parser](#nginx-log-parser): Stores nginx logs into a **sqlite3** database for further analysis and actions
2. [Restore original visitor IP](#restore-original-visitor-ip) behind a CDN: Continuously parses **Cloudflare** or **Fastly CIDRs** (`IPv4` and `IPv6`) through their **API**s so that nginx can leverage it to restore the original IP address of visitors
3. [Block untrusted](#block-untrusted-requests) requests using **nftables** to prevent HTTP and HTTPS requests coming from unknown IP addresses
4. [Reporting](#reporting) on gathered data such as top visited URLs through an interactive menu

Table of contents:

- [nginwho](#nginwho)
  - [Installation](#installation)
    - [Binary release (Linux x86_64)](#binary-release-linux-x86_64)
    - [Nimble](#nimble)
    - [Build from source](#build-from-source)
    - [Run as a service](#run-as-a-service)
  - [Usage](#usage)
  - [Flags](#flags)
  - [How it works](#how-it-works)
    - [nginx Log Parser](#nginx-log-parser)
    - [Restore Original Visitor IP](#restore-original-visitor-ip)
    - [Block Untrusted Requests](#block-untrusted-requests)
    - [Reporting](#reporting)
    - [Migrating v1 database to v2](#migrating-v1-database-to-v2)

## Installation

### Binary release (Linux x86_64)

```bash
curl -Lo nginwho https://github.com/pouriyajamshidi/nginwho/releases/latest/download/nginwho
sudo install nginwho -D -t /usr/local/bin/
```

### Nimble

```bash
nimble install nginwho
```

### Build from source

Requires [Nimble](https://github.com/nim-lang/nimble). It downloads the latest stable Nim if needed:

```bash
git clone https://github.com/pouriyajamshidi/nginwho.git
cd nginwho
nimble install -y --depsOnly
nimble c -d:release --opt:speed -d:ssl -o:nginwho src/nginwho.nim
sudo install nginwho -D -t /usr/local/bin/
```

To run the tests, use `nimble test`. The nftables tests run the real `nft` in a throwaway network namespace, so they don't need root or touch your firewall. They are skipped if that is not possible.

### Run as a service

Use the [accompanying systemd service](https://github.com/pouriyajamshidi/nginwho/blob/master/nginwho.service) to run **nginwho** in the background and survive reboots. The service reads everything from `/etc/nginwho/nginwho.conf`, so put the [sample config](https://github.com/pouriyajamshidi/nginwho/blob/master/nginwho.conf) there and edit it before enabling the service:

```bash
curl -Lo nginwho.conf https://raw.githubusercontent.com/pouriyajamshidi/nginwho/master/nginwho.conf
sudo install -m 644 nginwho.conf -D -t /etc/nginwho/
# edit /etc/nginwho/nginwho.conf to fit your setup

curl -Lo nginwho.service https://raw.githubusercontent.com/pouriyajamshidi/nginwho/master/nginwho.service
sudo install -m 644 nginwho.service -D -t /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now nginwho.service
```

## Usage

> [!IMPORTANT]
> If you have been a user since version 1, please check out [this section](#migrating-v1-database-to-v2) to migrate your database scheme to version 2.

```bash
nginwho --processNginxLogs --logPath:/var/log/nginx/access.log --dbPath:/var/lib/nginwho/nginwho.db

# If you want to omit a certain referrer from being logged (replace thegraynode.io with your domain):
nginwho --processNginxLogs \
        --logPath:/var/log/nginx/access.log \
        --dbPath:/var/lib/nginwho/nginwho.db \
        --omitReferrer:thegraynode.io

# If you only want to get real IP addresses of the visitors coming from Cloudflare:
nginwho --showRealIps:true

# The same behind Fastly:
nginwho --showRealIps:true --cdn:fastly
```

> Please note that you can mix these flags. They operate independently.

## Flags

Here are the available flags:

```text
  --help, -h              : Show help
  --version, -v           : Display version and quit
  --dbPath                : Path to SQLite database to log reports (default: /var/lib/nginwho/nginwho.db)
  --logPath               : Path to nginx access logs (default: /var/log/nginx/access.log,
                            or /var/log/nginwho/access.log with '--serve')
  --interval              : Refresh interval in seconds (default: 10)
  --omitReferrer          : Omit a specific referrer from being logged (default: none)
  --showRealIps           : Show real IP of visitors by getting the CDN's CIDRs to include in nginx config.
                            Self-updates every six hours (default: false)
  --blockUntrustedCidrs   : Block untrusted IP addresses using nftables. Only allows the CDN's CIDRs (default: false)
  --cdn                   : The CDN in front of your site, cloudflare or fastly (default: cloudflare)
  --processNginxLogs      : Process nginx logs (default: false)
  --serve                 : Serve static files and write nginx style logs to '--logPath' (default: false)
  --root                  : Directory to serve files from (default: /var/www/html)
  --port                  : Port to serve on, IPv4 and IPv6 (default: 80)
  --report                : Enter report mode and query the database for statistics
  --config                : Path to the config file (default: /etc/nginwho/nginwho.conf).
                            Command line flags win over it
  --trap                  : Play with bots that probe for files we do not have.
                            nginx forwards its 403s and 404s to us, or with '--serve'
                            the server hands them over itself (default: false)
  --trapPort              : Port the trap listens on for nginx, on localhost only (default: 7777)

  --migrateV1ToV2Db       : Migrate V1 database to V2 and exit (default: false).
                            Use with '--v1DbPath' and '--v2DbPath' flags
  --v1DbPath              : Path and name of the V1 database (e.g: /var/log/nginwho_v1.db)
  --v2DbPath              : Path and name of the V2 database (e.g: /var/lib/nginwho/nginwho.db)

```

## How it works

Let's see how nginwho works in a somewhat detailed yet short fashion.

### nginx Log Parser

**nginwho** by default reads `nginx` logs from `/var/log/nginx/access.log` and stores the parsed results in a **sqlite3** database located in `/var/lib/nginwho/nginwho.db` unless overridden by the [available flags](#flags).

It only reads the lines added since the last read, picks up where it left off after a restart and handles log rotation. Requests for static files (`.js`, `.css` and `.woff2`) are not stored, so reports show fewer requests than the raw log.

> [!WARNING]
> nginwho only supports the default nginx log format or any application that logs in the same format for now

### Restore Original Visitor IP

The second feature, `--showRealIps` flag fetches the CDN's CIDRs (`IPv4` and `IPv6`) every _six hours_ through their **API**s and writes the result to a file named `nginwho` located in `/etc/nginx/`. The CDN is **Cloudflare** by default. Use `--cdn:fastly` (or `cdn = fastly` under `[nginx]` in the config file) for **Fastly**. Only one CDN can be used at a time.

**nginwho** keeps a hash of the fetched CIDRs as an `etag` in the file, so if the CIDRs have not changed, the `/etc/nginx/nginwho` file will not be overwritten.

If the `/etc/nginx/nginwho` file has changed or this is a fresh run, **nginwho** tests the **nginx** config (`nginx -t`) and if it passes, soft reloads **nginx** (`nginx -s reload`) right away. A soft reload does not drop open connections.

> [!IMPORTANT]
> The `--showRealIps` flag requires **root privileges**.

For the `--showRealIps` flag to work, add this line to your **nginx** configuration to include the generated `/etc/nginx/nginwho` file:

```text
include /etc/nginx/nginwho;
```

So that nginx knows how to restore original visitor IP addresses.

> [!WARNING]
> nginx takes the visitor IP from the `Fastly-Client-IP` header. Fastly keeps this header when a visitor sends it, so a visitor can fake their IP. To stop that, set it yourself in your Fastly VCL (`vcl_recv`):
>
> ```text
> if (fastly.ff.visits_this_service == 0 && req.restarts == 0) {
>   set req.http.Fastly-Client-IP = client.ip;
> }
> ```

### Block Untrusted Requests

The third feature, `--blockUntrustedCidrs` flag gets the CDN's CIDRs from its API every _six hours_, with or without the `--showRealIps` flag. If the API can't be reached, for example right after a boot without network, it tries again every minute.

The fetched CIDRs will be checked against your existing **nftables** rules and if necessary, the required rules will be created and added through _nftable's JSON API_.

There will be a bunch of tests and pre-checks done before applying any policies. These checks include:

1. Existence of the CDN's IPv4 CIDRs nftables _Set_ (`Cloudflare_IPv4` or `Fastly_IPv4`)
1. Existence of the CDN's IPv6 CIDRs nftables _Set_ (`Cloudflare_IPv6` or `Fastly_IPv6`)
1. Existence of nftables `nginwho` chain (`prerouting` hook)
1. Existence of nftables `input` chain
1. Existence of **drop** policy inside `nginwho` chain for untrusted IP addresses on port **80** and **443**
1. Existence of **accept** policy inside `input` chain for trusted IP addresses on port **80** and **443**

The `nginwho` chain belongs to **nginwho**. When you switch CDN, the old CDN's rules in it are replaced so they do not block the new one.

**nginwho** only creates the necessary changes. Otherwise, no actions will be taken. For instance, if a CIDR gets added or removed, only that part of **nftables** configuration will be changed and the rest remain unchanged.

> [!IMPORTANT]
> The `--blockUntrustedCidrs` flag requires **root privileges**.

> [!IMPORTANT]
> Since playing with **nftables** could result in blocking yourself out, **nginwho** requires you to have some basic policies in place, in specific, having an `inet filter` table. If you do not have it, **nginwho** will detect that and shows you how to create one.

### Reporting

Running **nginwho** with the `--report` flag will launch an interactive menu, providing some options (top visited URLs, top visiting IP addresses, etc.) that you can select and specify how many records to be queried. Reports cover the last 30 days by default. Press `w` to switch to the last 24 hours, 7 days or all time.

The database file is only readable by the user that created it, so if nginwho runs as a service (root), use `sudo`:

```bash
sudo nginwho --report --dbPath:/var/lib/nginwho/nginwho.db
```

### Trap mode

Instead of returning a plain `403` or `404` to bots that probe for `.env` files, `.git`
directories, WordPress logins and the like, nginwho can play with them. Turn it on with
`--trap` (or `enabled = true` under `[trap]` in the config file), then point nginx at it.
If nginwho serves the site itself with `--serve`, there is no nginx to set up: the server
hands what it can't serve to the trap directly.

nginx forwards its `403`s and `404`s to nginwho, which decides what to do based on the path:

- **Fake files.** A probe for `.env`, `.git/config`, `phpinfo()`, `credentials` or a config
  file gets a believable file full of made up secrets that lead nowhere. Each fake secret is
  tied to the IP that asked for it, so if it ever turns up somewhere else you know who took it.
- **Slow drip.** Fake files are sent one byte at a time with a random pause between bytes, so
  a scan hangs for a long time on a single file.
- **Fake logins.** Login pages (`wp-login.php`, `/admin`, phpMyAdmin) show a login form that
  never lets anyone in and records the username and password that was typed.
- **Endless bodies and mazes.** Backup and API probes get a body that never ends, and `.git`
  probes get a maze of fake folders that link to more fake folders.
- **Gzip bombs.** Repeat offenders and probes for archives get about 10 MB on the wire that
  unpacks into about 10 GB. Clients that decode a gzip stream as they read it (Go's
  `net/http`, Python `requests`) get the whole 10 GB; `curl --compressed` stops after the
  first megabyte, and archive downloads land as a 10 MB file that only bites if it is opened.

Everything is saved in the `trap_hits` table and shows up under the `Trap:` entries in report
mode: who probed you, what they were after, how long you held them and what they typed into
the fake logins.

The matching nginx config sends misses and blocked requests to the trap while keeping the
real site read-only and still showing a normal 404 page for genuine typos:

```nginx
# a genuine missing page shows this. bots reach the trap through @trap instead
error_page 404 /404.html;

# blocked scrapers (403) and probe POSTs (405) are handed to the trap. if the trap
# returns a 404 for one of these, they get nginx's plain 404 page instead of 404.html.
# that is fine, they are not welcome here
error_page 403 405 = @trap;

location @trap {
    proxy_pass http://127.0.0.1:7777;
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_buffering off;         # or nginx holds back the slow drip
    proxy_read_timeout 15m;
    proxy_intercept_errors on;   # a genuine miss still gets the real 404 page
    error_page 404 /404.html;
    error_page 502 504 =404 /404.html;  # if nginwho is down, act like a normal site
    gzip off;                    # never re-compress the trap, it breaks the gzip bomb
    access_log off;              # the trap keeps its own record in trap_hits
}

location / {
    if ($request_method !~ ^(GET|HEAD)$) { return 405; }
    # ... your user agent and referer blocks return 403 here ...

    # a missing file goes to the trap. known probe paths get trapped,
    # a genuine typo gets the 404 page through @trap
    try_files $uri $uri/ @trap;
}
```

> Behind Cloudflare, check that the slow drip is streamed and that the gzip bomb is passed
> through before relying on either. Cloudflare gives up if no response starts within 100
> seconds, so the trap always sends its headers right away.

### Migrating v1 database to v2

Running the command below will first check your database for any errors and, if it detects any, will output what recovery command should be run. If everything is fine, it will read out the data from your source database, convert and write the data to version 2 so that nginwho can continue working as intended.

> Change the database file names according to your setup.

```bash
nginwho --migrateV1ToV2Db \
        --v1DbPath:nginwho_v1.db \
        --v2DbPath:nginwho.db
```
