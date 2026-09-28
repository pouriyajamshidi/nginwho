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

## TLDR

Every feature on, for a static site in `/var/www/html` behind Cloudflare. nginwho serves the
site itself, so stop nginx first if it uses port 80.

- The server speaks plain HTTP, so set Cloudflare's SSL mode to Flexible.
- On Fastly, change `cdn = cloudflare` to `cdn = fastly`.
- Not behind a CDN? Remove the `show_real_ips` and `block_untrusted_cidrs` lines, or only the
  CDN could reach your site.

```bash
curl -fLo nginwho https://github.com/pouriyajamshidi/nginwho/releases/latest/download/nginwho &&
sudo install nginwho -D -t /usr/local/bin/ &&
curl -fLo nginwho.service https://raw.githubusercontent.com/pouriyajamshidi/nginwho/master/nginwho.service &&
sudo install -m 644 nginwho.service -D -t /etc/systemd/system/ &&
sudo mkdir -p /etc/nginwho &&
sudo tee /etc/nginwho/nginwho.conf > /dev/null <<'EOF' &&
[nginx]
process_logs = true
cdn = cloudflare
show_real_ips = true
block_untrusted_cidrs = true

[server]
enabled = true
root = /var/www/html
port = 80

[trap]
enabled = true

[trap.agents]
deepseek = drip
gptbot = maze
bytespider
EOF
sudo systemctl daemon-reload &&
sudo systemctl enable --now nginwho.service
```

See what it does with `sudo journalctl -u nginwho -f`, and the numbers with
`sudo nginwho --report`. To keep nginx instead, [pick your setup](#pick-your-setup).

## Table of contents

- [nginwho](#nginwho)
  - [TLDR](#tldr)
  - [Table of contents](#table-of-contents)
  - [What nginwho can do](#what-nginwho-can-do)
  - [Pick your setup](#pick-your-setup)
    - [I want to know who visits my site](#i-want-to-know-who-visits-my-site)
    - [My site is behind Cloudflare or Fastly and I see their IPs instead of my visitors'](#my-site-is-behind-cloudflare-or-fastly-and-i-see-their-ips-instead-of-my-visitors)
    - [I want only my CDN to reach my server](#i-want-only-my-cdn-to-reach-my-server)
    - [I want my server closed to everything but SSH and my site](#i-want-my-server-closed-to-everything-but-ssh-and-my-site)
    - [Bots keep scanning my site for .env files and WordPress logins](#bots-keep-scanning-my-site-for-env-files-and-wordpress-logins)
    - [I want to punish AI crawlers or other bots by their name](#i-want-to-punish-ai-crawlers-or-other-bots-by-their-name)
    - [I have a small static site and don't want to run nginx](#i-have-a-small-static-site-and-dont-want-to-run-nginx)
  - [Installation](#installation)
    - [Binary release (Linux x86_64)](#binary-release-linux-x86_64)
    - [Nimble](#nimble)
    - [Build from source](#build-from-source)
    - [Run as a service](#run-as-a-service)
  - [The config file](#the-config-file)
  - [The nginx config](#the-nginx-config)
  - [Flags](#flags)
  - [How each feature works](#how-each-feature-works)
    - [Saving your logs](#saving-your-logs)
    - [Real visitor IPs behind a CDN](#real-visitor-ips-behind-a-cdn)
    - [Blocking everyone but your CDN](#blocking-everyone-but-your-cdn)
    - [Locking down your server](#locking-down-your-server)
    - [The trap](#the-trap)
      - [Trapping bots by their name](#trapping-bots-by-their-name)
    - [Serving your site without nginx](#serving-your-site-without-nginx)
    - [Reports](#reports)
  - [Where nginwho keeps its files](#where-nginwho-keeps-its-files)
  - [See it on Grafana](#see-it-on-grafana)
  - [Upgrading from older versions](#upgrading-from-older-versions)
    - [Coming from version 1](#coming-from-version-1)

## What nginwho can do

| Feature                | In plain words                                                                                  |
| ---------------------- | ----------------------------------------------------------------------------------------------- |
| Save your logs         | Reads your nginx access log and saves every visit in a small database                           |
| Reports                | Shows your top pages, top visitors, failed requests, referrers and what the bots tried          |
| Real visitor IPs       | Behind Cloudflare or Fastly, makes nginx log your visitors' IPs instead of the CDN's            |
| Block everyone but CDN | Uses the firewall so only your CDN can reach your website ports                                 |
| Lock down the server   | Uses the firewall to drop everything coming in but SSH and your website                         |
| The trap               | Bots looking for secrets get fake files, fake logins and endless answers instead of a plain 404 |
| Serve your site        | A simple web server for static sites, so you don't need nginx at all                            |

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

Then add this one line to your nginx config, inside the `http` block. The top of your site's
file in `/etc/nginx/sites-available` is inside it, as in [The nginx config](#the-nginx-config):

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

### I want my server closed to everything but SSH and my site

A web server only needs SSH and ports 80 and 443 open. Anything else listening on it, like a
database left open by mistake, should not be reachable from the internet.

```ini
[firewall]
lockdown = true
ssh_port = 22    # the port your SSH listens on
```

nginwho sets up the firewall so everything coming in is dropped, except SSH, ports 80 and 443,
and what the server needs to work. Use it with `block_untrusted_cidrs` to also keep everyone
but your CDN away from your site. See [Locking down your server](#locking-down-your-server)
before you turn this on.

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
[The nginx config](#the-nginx-config). Real visitors who mistype a link still get your normal
404 page.

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
curl -fLo nginwho https://github.com/pouriyajamshidi/nginwho/releases/latest/download/nginwho &&
sudo install nginwho -D -t /usr/local/bin/
```

### Nimble

```bash
nimble install nginwho
```

### Build from source

Requires [Nimble](https://github.com/nim-lang/nimble). It downloads the latest stable Nim if needed:

```bash
git clone https://github.com/pouriyajamshidi/nginwho.git &&
cd nginwho &&
nimble install -y --depsOnly &&
nimble c -d:release --opt:speed -o:nginwho src/nginwho.nim &&
sudo install nginwho -D -t /usr/local/bin/
```

To run the tests, use `nimble test`. The nftables tests run the real `nft` in a throwaway
network namespace, so they don't need root or touch your firewall. They are skipped if that is
not possible.

### Run as a service

The [systemd service](https://github.com/pouriyajamshidi/nginwho/blob/master/nginwho.service)
keeps nginwho running in the background and starts it again after a reboot. It reads
everything from `/etc/nginwho/nginwho.conf`, so put the
[sample config](https://github.com/pouriyajamshidi/nginwho/blob/master/nginwho.conf) there:

```bash
curl -fLo nginwho.conf https://raw.githubusercontent.com/pouriyajamshidi/nginwho/master/nginwho.conf &&
sudo install -m 644 nginwho.conf -D -t /etc/nginwho/
```

Edit `/etc/nginwho/nginwho.conf` to fit your setup, then install and start the service:

```bash
curl -fLo nginwho.service https://raw.githubusercontent.com/pouriyajamshidi/nginwho/master/nginwho.service &&
sudo install -m 644 nginwho.service -D -t /etc/systemd/system/ &&
sudo systemctl daemon-reload &&
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
# don't save referrers from this domain and its subdomains, like your own site. off when not set
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

[firewall]
# drop everything coming in but SSH, ports 80 and 443, and what the server needs to work
lockdown = false
# the SSH port to keep open. when not set, the port sshd listens on
# ssh_port = 22

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

## The nginx config

If nginx serves your site, here is a complete, basic config that works with every nginwho
feature. Save it as `/etc/nginx/sites-available/example.com`, change `example.com`, the site
folder and the certificate to yours, and leave out the parts for features you don't use.

```nginx
# real visitor IPs behind your CDN, written by nginwho (show_real_ips = true).
# at the top of the file it is in nginx's http block, so every server below uses it
include /etc/nginx/nginwho;

# the trap saves the bots it catches. the requests it lets go come back as a 404,
# and those are logged like any visit, blocked scrapers too
map $status $trap_let_go {
    404     1;
    default 0;
}

# plain HTTP goes to HTTPS
server {
    listen 80;
    listen [::]:80;
    server_name example.com www.example.com;
    return 301 https://example.com$request_uri;
}

server {
    listen 443 ssl;
    listen [::]:443 ssl;
    http2 on;
    server_name example.com www.example.com;

    ssl_certificate     /etc/ssl/example.com.pem;
    ssl_certificate_key /etc/ssl/example.com.key;

    root  /var/www/html;
    index index.html;

    # nginwho reads this log (process_logs = true). keep nginx's default format
    access_log /var/log/nginx/access.log combined;

    # a real missing page shows your 404 page. bots reach the trap through @trap
    error_page 404 /404.html;
    # blocked bots (403) and probing POSTs (405) go to the trap
    error_page 403 405 = @trap;

    location @trap {
        proxy_pass http://127.0.0.1:7777;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_buffering off;               # or nginx holds back the slow drip
        proxy_read_timeout 15m;            # the trap holds bots for a long time
        proxy_intercept_errors on;         # a real missing page still gets 404.html
        error_page 404 /404.html;
        error_page 502 504 =404 /404.html; # if nginwho is down, act like a normal site
        gzip off;                          # compressing again breaks the gzip bomb
        # only what the trap lets go. what it catches is saved in trap_hits instead
        access_log /var/log/nginx/access.log combined if=$trap_let_go;
    }

    location / {
        # a static site only needs GET and HEAD. a POST to a fake login still reaches the trap
        if ($request_method !~ ^(GET|HEAD)$) { return 405; }

        # the bots under [trap.agents] in nginwho.conf. nginx must send them a 403, or they
        # never reach the trap, so keep the two lists the same
        if ($http_user_agent ~* (deepseek|gptbot|bytespider)) { return 403; }

        # a missing file goes to the trap. known probe paths get trapped,
        # a real typo gets the 404 page through @trap
        try_files $uri $uri/ @trap;
    }
}

# nginx's numbers for the Grafana setup in observability/, only reachable from the server
server {
    listen 127.0.0.1:8080;
    access_log off;

    location = /stub_status {
        stub_status on;
    }
}
```

What each part is for:

| Part                                 | Needed for                                                               |
| ------------------------------------ | ------------------------------------------------------------------------ |
| `include /etc/nginx/nginwho`         | [Real visitor IPs behind a CDN](#real-visitor-ips-behind-a-cdn)          |
| `access_log ... combined`            | [Saving your logs](#saving-your-logs)                                    |
| `error_page`, `@trap`, `try_files`   | [The trap](#the-trap)                                                    |
| The `map` and `@trap`'s `access_log` | Logging the bots the trap lets go, like blocked scrapers on normal pages |
| The `$http_user_agent` line          | [Trapping bots by their name](#trapping-bots-by-their-name)              |
| The `stub_status` server             | The [Grafana dashboard](#see-it-on-grafana), optional                    |

Start nginwho first when `show_real_ips` is on, so `/etc/nginx/nginwho` exists. Without
`show_real_ips`, remove the `include` line, since the file isn't there. Then turn the site on:

```bash
sudo ln -s /etc/nginx/sites-available/example.com /etc/nginx/sites-enabled/ &&
sudo nginx -t &&
sudo systemctl reload nginx
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
  --report                : Enter report mode and query the database for statistics
  --config                : Path to the config file (default: /etc/nginwho/nginwho.conf).
                            Command line flags win over it
  --trap                  : Play with bots that probe for files we do not have.
                            nginx forwards its 403s and 404s to us, or with '--serve'
                            the server hands them over itself (default: false)
  --trapPort              : Port the trap listens on for nginx, on localhost only (default: 7777)
```

A few examples:

```bash
# save visits from the nginx log, but not the referrer when it is one of your own pages
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
that only those addresses can reach ports 80 and 443, over TCP and over UDP for HTTP/3.
Anyone else is dropped, and the drop is logged with the prefix `NGINWHO_DROPPED_v4` or
`NGINWHO_DROPPED_v6`, at most 10 times a minute each, so a flood can't fill your logs. If the
list can't be fetched, for example right after a boot with no network yet, it tries again
every minute. The rules are also checked every five minutes, so if a firewall reload wipes
them, they are back soon.

nginwho does not touch the rules you already have. It only adds its own parts next to them:

- The `inet filter` table, if you don't have one.
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
> A firewall mistake can lock you out of your server. What nginwho adds only drops traffic to
> ports 80 and 443, so SSH and everything else stay as your own rules have them.

If something goes wrong with nftables, nginwho logs it and keeps the other features running.

### Locking down your server

With `lockdown` on, nginwho adds a chain called `nginwho_input` to the `inet filter` table. It
drops everything coming in, except:

- Traffic from the server to itself, like nginx sending bots to the trap.
- Replies to connections the server made, like DNS lookups and updates.
- The ICMPv6 messages IPv6 needs to find the router and its neighbours. Ping is dropped.
- DHCPv6 replies, so the server keeps its IPv6 address.
- SSH on `ssh_port`.
- Ports 80 and 443, over TCP and UDP. With `block_untrusted_cidrs` on too, only your CDN gets
  this far.

The rest is dropped and logged with the prefix `NGINWHO_INPUT_DROPPED`, at most 10 times a
minute. Like the CDN rules, the chain is checked every five minutes and put back if a firewall
reload wipes it.

The chain is nginwho's alone, and your own rules stay as they are. But a packet has to get
through every chain, so a port you open in your own `input` chain is still dropped by
`nginwho_input`. Anything else that needs to be reached from outside, like a VPN or the
[built-in server](#serving-your-site-without-nginx) on a port other than 80, stops working.

When `ssh_port` is not set, nginwho uses the ports `sshd` listens on. It can't see them when
systemd starts SSH through `ssh.socket`, like on newer Ubuntu, so set `ssh_port` there. With no
SSH port known, nginwho does not lock down at all and logs an error, so a guess never locks
you out.

> [!IMPORTANT]
> A wrong SSH port locks you out. Your open SSH session stays up, since it is a reply to a
> connection that already exists, so check that a new SSH session gets in before you close it.

To undo it, set `lockdown = false`, then restart nginwho and remove the chain:

```bash
sudo systemctl restart nginwho && sudo nft delete chain inet filter nginwho_input
```

### The trap

Bots scan every website for files that leak passwords: `.env`, `.git/config`, backups,
`phpinfo.php`, WordPress logins and many more. A normal site answers them with a quick 404 and
they move on to the next site. The trap plays along instead and wastes their time.

**What the bots get**

The trap looks at the path a bot asked for and picks an answer:

| The bot asked for                      | What it gets                                                              |
| -------------------------------------- | ------------------------------------------------------------------------- |
| `.env` files                           | A fake `.env` full of made up keys and passwords, sent one byte at a time |
| Keys and cloud logins (`.aws`, `.ssh`) | Fake AWS credentials or a fake private key, sent one byte at a time       |
| `.git`                                 | A fake `config`, then a maze of fake folders                              |
| WordPress                              | A fake `wp-login.php` that never lets anyone in, endless `xmlrpc.php`     |
| PHP files                              | A fake `phpinfo()` page, and a gzip bomb for unknown `.php` files         |
| Config files                           | A fake config full of made up secrets, sent one byte at a time            |
| Backups and database dumps             | `.sql` that never ends, and a gzip bomb for `.zip` and `.gz`              |
| Admin and login pages                  | A fake login page                                                         |
| APIs and debug pages                   | A fake settings file, or an answer that never ends                        |
| Shells and `../` path traversal        | A fake `/etc/passwd`                                                      |

The five kinds of answer:

| Name      | What it does                                                                          |
| --------- | ------------------------------------------------------------------------------------- |
| `drip`    | A believable fake file, sent one byte every half second or so                         |
| `endless` | An answer that never ends, like a database dump that keeps going                      |
| `maze`    | A fake folder listing whose links lead to more fake folders                           |
| `login`   | A fake login page. Every try waits 10 to 30 seconds, then says the password was wrong |
| `bomb`    | A gzip bomb: about 10 MB to send, about 10 GB once the bot unpacks it                 |

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

**How nginx sends bots to the trap**

The trap listens on `127.0.0.1:7777`. nginx sends it the requests it would answer with 403,
404 or 405. For a path that isn't a known probe, the trap says 404 and nginx shows your normal
404 page, so real visitors never notice anything. If nginwho is not running, nginx acts like a
normal site and shows the 404 page.

nginx logs the requests the trap lets go, like a scraper you blocked asking for a normal page,
so they show up in your reports like any visit. The bots the trap catches are saved in
`trap_hits` instead, so nothing is counted twice.

The lines that do this are in [The nginx config](#the-nginx-config).

> [!NOTE]
> Behind Cloudflare, the gzip bomb gets through. A bot that asks for gzip, or for no
> compression at all, gets it as it was sent. A client that accepts zstd, like a browser, gets
> nothing, since Cloudflare unpacks the bomb on its side to compress it again. The trap tells
> CDNs never to cache what it sends, or a cached bomb would go out to bots the trap never sees.
> Cloudflare gives up if an answer doesn't start within 100 seconds, so the trap always sends
> its headers right away. Whether the slow drip arrives byte by byte through Cloudflare, and
> anything behind Fastly, is not tested yet, so check those before you rely on them.

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
in nginx, as in [The nginx config](#the-nginx-config). With the built-in server there is nothing
else to do.

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
  5) Top user agents
  6) Top non-defaults (all time)
  7) Trap: top attackers
  8) Trap: what they wanted
  9) Trap: top probed paths
  10) Trap: credentials tried
  t) Database totals (all time)
  w) Change time window (now: last 30 days)
  q) Quit
```

Reports cover the last 30 days. Press `w` to switch to the last 24 hours, 7 days or all time.
Press `t` to see how much is saved in the database and from when:

```text
  Requests          245,108  2024-11-01 08:30:12 to 2026-09-26 13:34:58
  Non-default logs       37
  Trap hits           9,412  2026-09-20 11:02:45 to 2026-09-26 13:34:46
```

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
| `/run/nginwho.nft`            | The last firewall change, with blocking or lockdown turned on  |

## See it on Grafana

The [observability](observability/README.md) folder sends your visits, trap hits and server
health to Grafana, with each visitor's country, and has a dashboard for them. It works with the
free tier of Grafana Cloud, and you can try it all on your machine first with Docker.

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

### Coming from version 1

Version 3 can't read a version 1 database. Stop nginwho, convert the database with the
[v2.4.1 release](https://github.com/pouriyajamshidi/nginwho/releases/tag/v2.4.1), then
[install](#installation) version 3. It picks up the converted database from
`/var/lib/nginwho/nginwho.db`.

> Change `/var/log/nginwho.db` to where your version 1 database is.

```bash
sudo systemctl stop nginwho &&
curl -fLo nginwho-v2 https://github.com/pouriyajamshidi/nginwho/releases/download/v2.4.1/nginwho &&
chmod +x nginwho-v2 &&
sudo mkdir -p /var/lib/nginwho &&
sudo ./nginwho-v2 --migrateV1ToV2Db \
  --v1DbPath:/var/log/nginwho.db \
  --v2DbPath:/var/lib/nginwho/nginwho.db &&
rm nginwho-v2
```
