# nginwho

<div align="center" style="width: 100%;">
 <img alt="nginwho" src="https://github.com/pouriyajamshidi/nginwho/blob/master/artwork/nginwho.jpeg?raw=true" width="700">
</div>

---

**nginwho** is a small and fast tool that looks after your website. It tells you who visits
your site, shows the real visitor IP when you are behind a CDN, keeps everyone but your CDN
away from your server, and wastes the time of the bots that scan your site for secrets.

It is a single file with nothing else to install. Every feature is off until you turn it on,
so you only use what you need.

## Table of contents

- [What nginwho can do](#what-nginwho-can-do)
- [Pick your setup](#pick-your-setup)
  - [I want to know who visits my site](#i-want-to-know-who-visits-my-site)
  - [My site is behind Cloudflare or Fastly and I see their IPs instead of my visitors'](#my-site-is-behind-cloudflare-or-fastly-and-i-see-their-ips-instead-of-my-visitors)
  - [I want only my CDN to reach my server](#i-want-only-my-cdn-to-reach-my-server)
  - [Bots keep scanning my site for .env files and WordPress logins](#bots-keep-scanning-my-site-for-env-files-and-wordpress-logins)
  - [I want to punish AI crawlers or other bots by their name](#i-want-to-punish-ai-crawlers-or-other-bots-by-their-name)
  - [I have a small static site and don't want to run nginx](#i-have-a-small-static-site-and-dont-want-to-run-nginx)
- [Installation](#installation)
  - [Binary release (Linux x86_64)](#binary-release-linux-x86_64)
  - [Nimble](#nimble)
  - [Build from source](#build-from-source)
  - [Run as a service](#run-as-a-service)
- [The config file](#the-config-file)
- [Flags](#flags)
- [How each feature works](#how-each-feature-works)
  - [Saving your logs](#saving-your-logs)
  - [Real visitor IPs behind a CDN](#real-visitor-ips-behind-a-cdn)
  - [Blocking everyone but your CDN](#blocking-everyone-but-your-cdn)
  - [The trap](#the-trap)
  - [Serving your site without nginx](#serving-your-site-without-nginx)
  - [Reports](#reports)
- [Where nginwho keeps its files](#where-nginwho-keeps-its-files)
- [Upgrading from older versions](#upgrading-from-older-versions)
  - [Migrating a v1 database to v2](#migrating-a-v1-database-to-v2)

## What nginwho can do

| Feature                 | In plain words                                                                                   |
| ----------------------- | ------------------------------------------------------------------------------------------------ |
| Save your logs          | Reads your nginx access log and saves every visit in a small database                            |
| Reports                 | Shows your top pages, top visitors, failed requests, referrers and what the bots tried           |
| Real visitor IPs        | Behind Cloudflare or Fastly, makes nginx log your visitors' IPs instead of the CDN's             |
| Block everyone but CDN  | Uses the firewall so only your CDN can reach your website ports                                  |
| The trap                | Bots looking for secrets get fake files, fake logins and endless answers instead of a plain 404  |
| Serve your site         | A simple web server for static sites, so you don't need nginx at all                             |

## Pick your setup

Find the situation that sounds like yours. Each one shows what to put in the
[config file](#the-config-file) at `/etc/nginwho/nginwho.conf`. You can mix them: turn on as
many as you like in the same file. Then [run nginwho as a service](#run-as-a-service), or run
`sudo nginwho` by hand to try it.

### I want to know who visits my site

You run nginx and want to see your most visited pages, your top visitors and what failed.

```ini
[nginx]
process_logs = true
```

nginwho reads `/var/log/nginx/access.log` and saves new lines every 10 seconds. When you want
to see the numbers, run:

```bash
sudo nginwho --report
```

See [Reports](#reports) for what you get.

### My site is behind Cloudflare or Fastly and I see their IPs instead of my visitors'

When a CDN sits in front of your site, nginx sees the CDN's address on every request. nginwho
fetches the CDN's address list and gives it to nginx, so nginx can find the real visitor IP.

```ini
[nginx]
cdn = cloudflare    # or fastly
show_real_ips = true
```

Then add this one line to your nginx config, inside the `http` block:

```nginx
include /etc/nginx/nginwho;
```

See [Real visitor IPs behind a CDN](#real-visitor-ips-behind-a-cdn). If you use Fastly, read
the warning there.

### I want only my CDN to reach my server

If your site is behind a CDN, nobody else should talk to your server directly. People who do
are usually scanners trying to get around the CDN's protection.

```ini
[nginx]
cdn = cloudflare    # or fastly
block_untrusted_cidrs = true
```

nginwho sets up the firewall (nftables) so only the CDN can reach ports 80 and 443. Your SSH
and everything else stay as they are. See
[Blocking everyone but your CDN](#blocking-everyone-but-your-cdn) before you turn this on.

### Bots keep scanning my site for .env files and WordPress logins

Your logs are full of requests for `/.env`, `/.git/config`, `/wp-login.php` and
`/phpinfo.php`. You don't have these files, but the bots keep asking. The trap answers them
with fake files full of made up passwords, sent one byte at a time, so each scan gets stuck
for minutes.

```ini
[trap]
enabled = true
```

nginx needs a few lines to send its 403 and 404 answers to the trap. They are in
[The trap](#the-trap). Real visitors who mistype a link still get your normal 404 page.

### I want to punish AI crawlers or other bots by their name

Some bots ask for normal pages but you still don't want them, like AI crawlers that copy your
content. List them by a part of their user agent and pick what each one gets:

```ini
[trap]
enabled = true

[trap.agents]
deepseek = drip     # a fake file, one byte every half second
gptbot = maze       # fake folders that lead to more fake folders
bytespider          # no choice: the default is used
```

Behind nginx, also block the same names with a 403 so nginx sends them to the trap:

```nginx
if ($http_user_agent ~* (deepseek|gptbot|bytespider)) { return 403; }
```

See [Trapping bots by their name](#trapping-bots-by-their-name) for all the choices.

### I have a small static site and don't want to run nginx

nginwho can serve a folder of HTML files by itself, write an access log like nginx does, and
hand the bots to the trap.

```ini
[nginx]
process_logs = true   # save visits for the reports

[server]
enabled = true
root = /var/www/html
port = 80

[trap]
enabled = true
```

There is no nginx config to write. Behind Cloudflare or Fastly, also set
`show_real_ips = true` under `[nginx]` so the logs and the trap see your visitors' IPs. See
[Serving your site without nginx](#serving-your-site-without-nginx).

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

To run the tests, use `nimble test`. The nftables tests run the real `nft` in a throwaway
network namespace, so they don't need root or touch your firewall. They are skipped if that is
not possible.

### Run as a service

The [systemd service](https://github.com/pouriyajamshidi/nginwho/blob/master/nginwho.service)
keeps nginwho running in the background and starts it again after a reboot. It reads
everything from `/etc/nginwho/nginwho.conf`, so put the
[sample config](https://github.com/pouriyajamshidi/nginwho/blob/master/nginwho.conf) there and
edit it first:

```bash
curl -Lo nginwho.conf https://raw.githubusercontent.com/pouriyajamshidi/nginwho/master/nginwho.conf
sudo install -m 644 nginwho.conf -D -t /etc/nginwho/
# edit /etc/nginwho/nginwho.conf to fit your setup

curl -Lo nginwho.service https://raw.githubusercontent.com/pouriyajamshidi/nginwho/master/nginwho.service
sudo install -m 644 nginwho.service -D -t /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now nginwho.service
```

To see what it is doing:

```bash
sudo journalctl -u nginwho -f
```

After you change the config file, run `sudo systemctl restart nginwho`.

## The config file

nginwho reads `/etc/nginwho/nginwho.conf` when it starts. Use `--config` to read another file.
A missing file is fine: everything is off and the defaults below are used. A bad value is
reported in the log and its default is kept.

Here is every setting with its default:

```ini
[database]
# where visits and trap hits are saved
path = /var/lib/nginwho/nginwho.db

[nginx]
# save the visits from the access log
process_logs = false
# the access log to read. with the server on, the default is /var/log/nginwho/access.log
log_path = /var/log/nginx/access.log
# seconds between reads of the access log
interval = 10
# don't save this referrer, like your own domain. off when not set
# omit_referrer = example.com
# the CDN in front of your site: cloudflare or fastly
cdn = cloudflare
# log real visitor IPs behind the CDN. writes the CDN's addresses for nginx,
# or with the server on, makes the server read the CDN's header
show_real_ips = false
# only let the CDN reach ports 80 and 443
block_untrusted_cidrs = false

[server]
# serve a folder of static files, without nginx
enabled = false
root = /var/www/html
port = 80

[trap]
enabled = false
# the port nginx sends its 403s and 404s to. it only listens on 127.0.0.1
port = 7777
# more bots than this at once get a plain 404
max_connections = 200
# the longest one bot is held, in seconds
max_seconds = 900
# the pause between bytes of a slow drip, picked between these two, in milliseconds
drip_min_ms = 500
drip_max_ms = 700
# send gzip bombs at all
bombs = true
# an IP gets a bomb after this many trapped hits in one day
bomb_after = 3

[trap.agents]
# bots to trap by their user agent, whatever they ask for. see "The trap"
```

## Flags

Flags do the same as the config file and win over it, which is handy for trying things out.

```text
  --help, -h              : Show help
  --version, -v           : Display version and quit
  --dbPath                : Path to SQLite database to log reports (default: /var/lib/nginwho/nginwho.db)
  --logPath               : Path to nginx access logs (default: /var/log/nginx/access.log,
                            or /var/log/nginwho/access.log with '--serve')
  --interval              : Refresh interval in seconds (default: 10)
  --omitReferrer          : Omit a specific referrer from being logged (default: none)
  --showRealIps           : Show real IP of visitors by getting the CDN's CIDRs to include in nginx config,
                            or with '--serve' to trust the CDN's header. Self-updates every six hours (default: false)
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

A few examples:

```bash
# save visits from the nginx log, but leave out visits that came from your own pages
nginwho --processNginxLogs --omitReferrer:example.com

# real visitor IPs behind Fastly
sudo nginwho --showRealIps --cdn:fastly

# the trap on a different port
nginwho --trap --trapPort:8888
```

The trap numbers and `[trap.agents]` can only be set in the config file.

## How each feature works

### Saving your logs

nginwho reads your nginx access log every 10 seconds and saves the new lines in a SQLite
database at `/var/lib/nginwho/nginwho.db`.

- It only reads what was added since last time, so a big log is no problem.
- After a restart it picks up where it stopped, and it notices when the log is rotated.
- Requests for fonts, scripts and styles (`.woff2`, `.js`, `.css`) are not saved. They only add
  noise, so reports show fewer requests than the raw log.
- It does not need nginx to be installed. Any program that writes the same log format works.

> [!WARNING]
> nginwho only understands nginx's default log format (`combined`).

### Real visitor IPs behind a CDN

Every six hours, nginwho asks your CDN for its list of addresses and writes them to
`/etc/nginx/nginwho`, along with the header nginx should read the real IP from
(`CF-Connecting-IP` for Cloudflare, `Fastly-Client-IP` for Fastly).

If the list changed, nginwho checks your nginx config with `nginx -t` and, if it passes,
reloads nginx. A reload does not drop open connections. If nothing changed, the file is left
alone.

Add this line to your nginx config, inside the `http` block:

```nginx
include /etc/nginx/nginwho;
```

> [!IMPORTANT]
> This needs root, since it writes to `/etc/nginx` and reloads nginx.

With the [built-in server](#serving-your-site-without-nginx) there is no nginx, so nothing is
written to `/etc/nginx`. The server reads the real IP from the CDN's header itself.

> [!WARNING]
> Fastly keeps a `Fastly-Client-IP` header that a visitor sends, so a visitor can fake their
> IP. To stop that, set it yourself in your Fastly VCL (`vcl_recv`):
>
> ```text
> if (fastly.ff.visits_this_service == 0 && req.restarts == 0) {
>   set req.http.Fastly-Client-IP = client.ip;
> }
> ```

### Blocking everyone but your CDN

Every six hours, nginwho gets your CDN's address list and updates your nftables firewall so
that only those addresses can reach ports 80 and 443. Anyone else is dropped, and the drop is
logged with the prefix `NGINWHO_DROPPED_v4` or `NGINWHO_DROPPED_v6`. If the list can't be
fetched, for example right after a boot with no network yet, it tries again every minute.

nginwho does not touch the rules you already have. It only adds its own parts next to them:

- Two sets with the CDN's addresses, like `Cloudflare_IPv4` and `Cloudflare_IPv6`.
- Its own chain called `nginwho`, which drops web traffic from everyone else.
- One rule in your `input` chain that lets ports 80 and 443 in, only if you don't have one
  already. Without it your own rules could drop the CDN's traffic.

Only what changed is updated, so when the CDN adds one address, only that address is added.
The `nginwho` chain is nginwho's alone, so don't put your own rules in it: they are removed
when nginwho updates it. When you switch CDN, the old CDN's rules there are replaced so they
don't block the new one.

> [!IMPORTANT]
> This needs root, since it changes the firewall.

> [!IMPORTANT]
> A firewall mistake can lock you out of your server. So nginwho only works on top of an
> existing `inet filter` table. If you don't have one, nginwho leaves the firewall alone and
> prints an example you can start from. Make sure your own rules let SSH in.

If something goes wrong with nftables, nginwho logs it and keeps the other features running.

### The trap

Bots scan every website for files that leak passwords: `.env`, `.git/config`, backups,
`phpinfo.php`, WordPress logins and many more. A normal site answers them with a quick 404 and
they move on to the next site. The trap plays along instead and wastes their time.

**What the bots get**

The trap looks at the path a bot asked for and picks an answer:

| The bot asked for                     | What it gets                                                              |
| ------------------------------------- | ------------------------------------------------------------------------- |
| `.env` files                          | A fake `.env` full of made up keys and passwords, sent one byte at a time |
| Keys and cloud logins (`.aws`, `.ssh`)| Fake AWS credentials or a fake private key, sent one byte at a time       |
| `.git`                                | A fake `config`, then a maze of fake folders                              |
| WordPress                             | A fake `wp-login.php` that never lets anyone in, endless `xmlrpc.php`     |
| PHP files                             | A fake `phpinfo()` page, and a gzip bomb for unknown `.php` files         |
| Config files                          | A fake config full of made up secrets, sent one byte at a time            |
| Backups and database dumps            | `.sql` that never ends, and a gzip bomb for `.zip` and `.gz`              |
| Admin and login pages                 | A fake login page                                                         |
| APIs and debug pages                  | A fake settings file, or an answer that never ends                        |
| Shells and `../` path traversal       | A fake `/etc/passwd`                                                      |

The five kinds of answer:

| Name      | What it does                                                                               |
| --------- | ------------------------------------------------------------------------------------------ |
| `drip`    | A believable fake file, sent one byte every half second or so                              |
| `endless` | An answer that never ends, like a database dump that keeps going                           |
| `maze`    | A fake folder listing whose links lead to more fake folders                                |
| `login`   | A fake login page. Every try waits 10 to 30 seconds, then says the password was wrong      |
| `bomb`    | A gzip bomb: about 10 MB to send, about 10 GB once the bot unpacks it                      |

- **Bots that come back get a bomb.** After `bomb_after` trapped requests in one day (3 by
  default), the next one from that IP gets the bomb. Set `bombs = false` to never send one,
  and bots get an endless answer instead.
- **The same bot sees the same file.** Asking twice gives the same fake content, so it looks
  real. Another bot gets different values.
- **Fake secrets are recorded.** The fake key a bot got is saved with its visit, and so is
  anything typed into a fake login. If that key shows up somewhere later, you know who took it.
- **Limits keep your server safe.** At most 200 bots are held at once, each for at most 15
  minutes. A bot that hangs up frees its place right away. After 1000 hits in a day, an IP is
  still trapped but no longer saved, so a flood can't fill your disk.

Gzip bombs only hurt clients that unpack as they read. Go's `net/http` and Python's
`requests`, which most scanners are built on, get the full 10 GB. `curl --compressed` stops
after the first megabyte, and a `.zip` or `.gz` download lands as a 10 MB file that only bites
if someone opens it.

**Setting up nginx**

The trap listens on `127.0.0.1:7777`. nginx sends it the requests it would answer with 403,
404 or 405. For a path that isn't a known probe, the trap says 404 and nginx shows your normal
404 page, so real visitors never notice anything.

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
    # ... your user agent and referer blocks return 403 here, for example:
    # if ($http_user_agent ~* (deepseek|gptbot|bytespider)) { return 403; }

    # a missing file goes to the trap. known probe paths get trapped,
    # a genuine typo gets the 404 page through @trap
    try_files $uri $uri/ @trap;
}
```

If nginwho is not running, nginx acts like a normal site and shows the 404 page.

> [!NOTE]
> Behind a CDN, check that the slow drip arrives byte by byte and that the gzip bomb gets
> through before you rely on either. Cloudflare gives up if an answer doesn't start within 100
> seconds, so the trap always sends its headers right away.

#### Trapping bots by their name

You can also trap bots by their user agent, whatever page they ask for. List them under
`[trap.agents]`:

```ini
[trap.agents]
deepseek = drip
gptbot = maze
claudebot = endless
bytespider
```

- The name on the left is matched anywhere in the `User-Agent` header, and upper or lower case
  doesn't matter. `deepseek` matches `Mozilla/5.0 (compatible; DeepSeekBot/1.0)`.
- The value on the right is one of `drip`, `endless`, `maze`, `login` or `bomb`. It always wins,
  even over the answer the path would get.
- **A name on its own gets the default:** the same answer any bot gets for that path, and a slow
  drip for a normal page. A value nginwho doesn't know is reported in the log and the default
  is used.
- If two names match, the first one in the list wins.

Behind nginx, a bot only reaches the trap if nginx blocks it with a 403. Block the same names
in nginx, as in the example above. With the built-in server there is nothing else to do.

### Serving your site without nginx

For a site made of plain files (HTML, images, a blog built with Hugo or Jekyll), nginwho can
be the web server:

```ini
[server]
enabled = true
root = /var/www/html
port = 80
```

- `/about/` serves `/about/index.html`, and a missing page gets your `404.html` if you have one.
- Every visit is written to `/var/log/nginwho/access.log` in nginx's format. Turn on
  `process_logs` under `[nginx]` and those visits are saved for the reports, as with nginx.
- With the trap on, the server hands the bots to it directly. Real files and typos are served
  as usual.
- Only `GET` and `HEAD` are answered, anything else gets a 405.
- A path that tries to leave `root` with `../` gets a 400. With the trap on, it is trapped
  instead, whether the file exists or not.
- Dot files like `.git` and `.env` are never served, only `.well-known`.
- At most 400 visitors are served at once, and a visitor that stops reading is dropped after
  30 seconds. Trapped bots don't count toward the 400.
- One IP can have at most 32 connections open, so it can't take all 400 places. An IPv6 user
  is counted by their /64. The CDN's own addresses have no limit, as long as `show_real_ips`
  or `block_untrusted_cidrs` is on so nginwho knows them.

The server speaks plain HTTP only, so HTTPS has to come from a CDN in front of it. Behind a
CDN, every request comes from the CDN's address. Turn on `show_real_ips` under `[nginx]` and
the server takes the visitor's IP from the CDN's header (`CF-Connecting-IP` or
`Fastly-Client-IP`) instead, for the log and the trap. Anyone can send that header, so it is
only believed when the request really comes from one of the CDN's addresses.

```ini
[nginx]
cdn = cloudflare
show_real_ips = true
```

### Reports

```bash
sudo nginwho --report
```

This opens a menu. Pick a report by its number and say how many rows you want:

```text
  1) Top IP addresses
  2) Top URIs
  3) Top unsuccessful requests
  4) Top referrers
  5) Top non-defaults (all time)
  6) Trap: top attackers
  7) Trap: what they wanted
  8) Trap: top probed paths
  9) Trap: credentials tried
  w) Change time window (now: last 30 days)
  q) Quit
```

Reports cover the last 30 days. Press `w` to switch to the last 24 hours, 7 days or all time.
The trap reports show how long each bot was held. For example, "what they wanted":

```text
  #  Target     Tactic  Time wasted  Hits       %
  1  env        drip    3h 12m        412   41.2%  ████████████████████
  2  wordpress  login   1h 40m        288   28.8%  █████████████
  3  php        bomb    4m             97    9.7%  ████
  4  agent      drip    2h 5m          64    6.4%  ███
```

`agent` is a bot trapped by its name while asking for a normal page.

The database can only be read by the user that created it. nginwho usually runs as root, so
use `sudo`.

## Where nginwho keeps its files

| File                          | What it is                                                     |
| ----------------------------- | -------------------------------------------------------------- |
| `/etc/nginwho/nginwho.conf`   | The config file                                                |
| `/var/lib/nginwho/nginwho.db` | The database with visits and trap hits                         |
| `/etc/nginx/nginwho`          | The CDN's addresses for nginx, with real visitor IPs turned on |
| `/var/log/nginwho/access.log` | The access log of the built-in server                          |
| `/run/nginwho.nft`            | The last firewall change, with blocking turned on              |

## Upgrading from older versions

- **The database moved** from `/var/log/nginwho.db` to `/var/lib/nginwho/nginwho.db`. If only
  the old one exists, nginwho keeps using it and asks you to move it. Stop nginwho, move the
  file, then start it again.
- **Reading the nginx log is now off by default.** Add `process_logs = true` under `[nginx]`,
  or the `--processNginxLogs` flag, to keep saving visits.
- **The database is upgraded once** the first time the new version starts or runs a report.
  This takes a few seconds on big databases. Older versions can't read an upgraded database,
  so keep a copy if you may go back.

The full list of changes is in the [changelog](CHANGELOG.md).

### Migrating a v1 database to v2

If you have used nginwho since version 1, convert your database to the version 2 format first.
The command below checks your old database for errors and tells you how to fix them if it
finds any. If all is well, it copies your data into a new version 2 database.

> Change the file names to match yours.

```bash
nginwho --migrateV1ToV2Db \
        --v1DbPath:nginwho_v1.db \
        --v2DbPath:nginwho.db
```
