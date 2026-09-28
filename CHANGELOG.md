# Changelog

All notable changes to **nginwho** are listed here.

## [Unreleased]

### Added

- Trap mode (`--trap`). nginx forwards its 403s and 404s to nginwho, which plays with the bots instead of returning an error. Based on the paths it asks for, a bot gets a fake `.env`, `.git/config`, `phpinfo()` or config file full of made up secrets, a fake login page that never lets it in but records what it typed, a body that never ends, a maze of fake folders, or a gzip bomb. Fake files are dripped one byte at a time so a scan hangs for a long time. A bot that keeps coming back gets a bomb.
- The trap can catch bots by their user agent too. List them under `[trap.agents]` in the config file and pick what each one gets (`drip`, `endless`, `maze`, `login` or `bomb`). A name on its own gets what any bot gets for that path, and a slow drip for a normal page.
- The trap also works without nginx. With `--serve`, nginwho's own server hands what it can't serve to the trap directly, and real files and typos are served as usual.
- The `--serve` server holds up against abuse. A client that stops reading is dropped after 30 seconds, at most 400 visitors are served at once (trapped bots don't count), a second `Content-Length` can't hide a request in the body, and `//evil.com` can't turn a folder redirect into a redirect to another site. nginwho raises its open file limit at start so the server and the trap have room.
- Path traversal (`../`, `..\`, `..;`) gets the trap's fake `/etc/passwd`. With `--serve`, it is trapped whether the file exists or not, so a bot can't learn which files are on the server. A trapped bot that stops reading is let go after 30 seconds instead of held until `max_seconds`.
- `--serve` with `--showRealIps` reads the visitor's IP from the CDN's header (`CF-Connecting-IP` or `Fastly-Client-IP`), so the access log and the trap see visitors instead of the CDN. The header only counts when the request comes from the CDN's own ranges, and nothing is written for nginx.
- Every trapped request is saved in a new `trap_hits` table: who it was, what they wanted, what we did, how long we held them and any credentials they typed. The hit is written as soon as the trap starts, so a slow drip still shows up right away.
- Report mode has four new trap reports: top attackers, what they wanted, top probed paths and credentials tried.
- Report mode has a top user agents report, and `t` shows how many requests, non-default logs and trap hits are saved in the database, with the dates of the first and last one.
- Fastly support. `--cdn:fastly` (or `cdn = fastly` under `[nginx]` in the config file) makes `--showRealIps` and `--blockUntrustedCidrs` use Fastly's ranges instead of Cloudflare's. nginx then reads the visitor IP from the `Fastly-Client-IP` header, see the README to stop visitors from faking it.
- A config file at `/etc/nginwho/nginwho.conf` (`--config` to point elsewhere). Command line flags override it. A sample `nginwho.conf` is in the repository.
- HTTPS for `--serve`. Give it a certificate and key with `--cert` and `--key` (or `cert` and `key` under `[server]`), the same files nginx takes. A renewed certificate is picked up without a restart.
- `--lockdown` (or `lockdown = true` under `[firewall]` in the config file) closes the server to everything but SSH, ports 80 and 443, and replies to the server's own connections. It adds its own `nginwho_input` nftables chain that drops the rest and logs it at most 10 times a minute, and leaves your own rules alone. The SSH port comes from `--sshPort` (or `ssh_port`), or else from the ports `sshd` listens on. With no SSH port known, nothing is locked down.
- An `observability` folder to see nginwho on Grafana, including the free tier of Grafana Cloud: a Grafana Alloy config that sends the access logs, trap hits, database size, nginx and server metrics, with each visitor's country and network from the free ip66.dev database, a dashboard, and a Docker Compose setup that runs it all on your machine with fake visitors and bots.

### Changed

- Every feature is off unless you turn it on, including reading nginx logs. Add `--processNginxLogs` (or `process_logs = true` under `[nginx]` in the config file) to keep collecting logs. Before, `nginwho --trap` also read the nginx log and quit when the log was missing.
- `--blockUntrustedCidrs` fetches Cloudflare's ranges itself. Before, without `--showRealIps` it read them once from `/etc/nginx/nginwho`, a file only `--showRealIps` writes. A failed fetch is retried after a minute instead of six hours.
- The `etag` in `/etc/nginx/nginwho` is now a hash of the CIDRs, since Fastly's API has no etag. nginx is reloaded once after upgrading.
- The `nginwho` nftables chain only keeps the drop rules for the current CDN. Any other rule in it is removed.
- The `nginwho` nftables chain runs at the `raw` priority (`-300`) instead of `-10`, before connection tracking, so dropped packets cost less. The old chain is replaced on the first run.
- `--blockUntrustedCidrs` blocks UDP to ports 80 and 443 too, so HTTP/3 (QUIC) can't reach the server without going through the CDN. The port is checked before the CDN's addresses, so traffic to other ports, like SSH, skips that lookup.
- The `NGINWHO_DROPPED_v4` and `NGINWHO_DROPPED_v6` log lines are limited to 10 a minute each, so a flood no longer writes one line per packet. Every dropped packet is still counted.
- `--blockUntrustedCidrs` checks its nftables rules every five minutes and puts back what is missing. Before, a firewall reload with `flush ruleset`, like `systemctl reload nftables`, left the server open until the next update, up to six hours later.
- An nftables error is logged and no longer stops nginwho, so log collection, the trap and the server keep running.
- The database moved from `/var/log/nginwho.db` to `/var/lib/nginwho/nginwho.db`, where program data belongs on Linux. If `/var/log/nginwho.db` exists and the new one does not, nginwho keeps using the old one and warns you to move it. A `path` set in the config file or `--dbPath` is used as is.
- Dates are saved in the `nginwho` table as unix seconds instead of in their own `dates` table. Nearly every log has its own date, so that table and its index were bigger than the logs themselves. A real 90.7 MB database went down to 54.9 MB.
- Inserting logs is about 35% faster, and time window reports are as fast or faster.
- Existing databases are upgraded once on start or when running `--report`, then vacuumed so the file shrinks. This takes a few seconds on big databases. Older versions can't read an upgraded database, so keep a backup if you may go back.
- A flag value after a space, like `--omitReferrer example.com`, stops nginwho with an error. Before, the value was quietly ignored, so the flag did nothing or `--logPath` fell back to the default log. Give values with `=` or `:`, like `--omitReferrer=example.com`.
- `nginwho.service` makes `/var/lib/nginwho` `0755` instead of `0700`, so a monitoring tool like Grafana Alloy can see how big the database is.
- `--blockUntrustedCidrs` creates the `inet filter` table when there is none. Before, it stopped with an example to start from, and took any `inet` table, like one from firewalld, for `inet filter`.
- `--omitReferrer` (`omit_referrer`) only drops referrers from that domain and its subdomains. Before, it matched anywhere in the referrer, so a search like `google.com/search?q=example.com` was dropped too.

### Removed

- V1 to V2 database migration (`--migrateV1ToV2Db`, `--v1DbPath` and `--v2DbPath`). Convert a v1 database with v2.4.1 first, then upgrade.

### Fixed

- `--blockUntrustedCidrs` took a chain or Set with the same name in another table, like the `input` chain of an `ip filter` table, for its own. It then added a rule to a chain that did not exist, and nothing was blocked.
- An empty `Cloudflare_IPv4` or `Cloudflare_IPv6` Set in nftables crashed nginwho instead of being filled.
- `--report=false` still started report mode. It now turns it off like `=false` does for the other flags.

## [2.4.1]

### Fixed

- In report mode, the number you type no longer shows up at the start of the prompt, like `1Select an option:`.

## [2.4.0]

### Changed

- Report mode uses colors: yellow menus, cyan prompts, red warnings, a green report title and green bars.
- CI runs the tests once per pull request instead of twice. Pushes only run the tests on `master`.

### Fixed

- The time window menu in report mode was white while the main menu was yellow.

## [2.3.1]

### Fixed

- Much lower memory use. Log lines are read in 1 MB chunks and only as much as was added is loaded, instead of a 16 MB buffer on every read.

## [2.3.0]

### Added

- Reports can be limited to the last 24 hours, 7 days or 30 days, or cover all time. The default is the last 30 days.

### Changed

- Report mode no longer mixes log lines into the results.
- Reports are shown as aligned tables with counts, percentages and bars. Long values are cut to keep the table readable.
- Top unsuccessful requests show the status code, URI and user agent in their own columns.
- Only read new lines from the nginx log instead of reading the whole file every time. Log rotation and truncation are handled.
- Big nginx logs are read in 16 MB chunks instead of all at once. After a restart, nginwho finds where it left off without loading the whole file.
- Reload nginx right away after the Cloudflare CIDRs change, as long as `nginx -t` passes. The reload is graceful and does not drop open connections.
- Use the async http client for Cloudflare so a slow call does not block log processing.
- Write nftables rules to `/run/nginwho.nft` instead of `/tmp/nginwho.nft`.
- Reduce unnecessary logging of accepted traffic.
- The systemd service restarts nginwho after a crash and has basic sandboxing.
- V1 to V2 database migration pages with `rowid` instead of `OFFSET`, which is much faster on big databases.
- Keep `.xml` requests during migration like live log processing does.
- Inserts prepare their SQL once per batch instead of once per row, about 7 times faster.
- New database files are only readable by their owner, since they hold visitor IPs and URIs.
- The database uses WAL mode, `synchronous = NORMAL`, a 5 second busy timeout and enforces foreign keys.

### Fixed

- `--migrateV1ToV2Db` flag was not recognized and depended on flag order.
- The leading `/` was removed from URIs ending with `/` (for example `/blog/` was stored as `blog`).
- Boolean flags passed without a value (for example `--showRealIps`) crashed.
- Bad flag values (for example `--interval:abc`) crashed with a stack trace instead of showing the usage.
- Empty log lines made log processing sleep.
- Logs with the same date, IP, method and URI could be inserted twice.
- Cloudflare CIDR updates stopped forever after the first change.
- Failed Cloudflare API calls crashed nginwho. The http client is now closed and has a timeout.
- Failed log inserts left the database transaction open.
- Logs from a failed insert were lost. They are now retried up to 3 times.
- Running `--report` while the service was writing could crash the service with "database is locked".
- Crashes when checking nftables rules with unexpected keys.
- Crash when the current nftables rules can't be read.
- Crash on trailing spaces or invalid CIDRs in `/etc/nginx/nginwho`.
- Crash on invalid CIDRs from the Cloudflare API.
- An empty IPv4 or IPv6 list from the Cloudflare API emptied its nftables Set and blocked all Cloudflare traffic of that IP version.
- Rules were applied even when writing the nftables rules file failed.
- The `--report` menu listed its options in a random order.
- `--report` with a wrong `--dbPath` created an empty database and crashed.
- Top unsuccessful requests showed a random user agent for each URI. Each status code, URI and user agent is now counted on its own, and the status code is shown.
- `--blockUntrustedCidrs` without `--showRealIps` slept six hours for nothing.
- Report mode crashed on Ctrl+D.
- Migration batch counting.
- `network.target` name in the systemd service.
- A request with an empty `User-Agent` made the whole batch of logs fail to save.
- CIDRs removed by Cloudflare stayed allowed in nftables, and the Sets were applied again every six hours.
- The sample `nft` commands shown when the `inet filter` table is missing failed because they never created the `input` chain.
- Crash on a single IP without a prefix length (for example `set_real_ip_from 1.2.3.4;`) in `/etc/nginx/nginwho`. Invalid prefix lengths are skipped now too.

### Removed

- Unused `insertLogV1` procedure.

## [2.2.0] - 2025-07-13

### Fixed

- `getTopUnsuccessfulRequests` reporting.
- Crashes when checking the nftables input chain for existing policy.

## [2.1.0] - 2024-11-17

### Added

- New database design that uses about 1/10th of the disk space of V1.
- V1 to V2 database migration using `--migrateV1ToV2Db`, `--v1DbPath` and `--v2DbPath`.
- Report mode using `--report` to query the database for statistics.
- Store logs that are not in the default nginx format.

### Changed

- Faster log inserts and no duplicate inserts.
- Remove trailing `/`s from URIs and referrers.

### Fixed

- Date parsing bug introduced in nginx 1.24.0.

## [2.0.0] - 2024-09-22

### Added

- IPv6 support for nftables.
- Check nginx log file existence before starting.

### Changed

- Separate database and types logic.

For older versions, see the git history.

[2.4.1]: https://github.com/pouriyajamshidi/nginwho/compare/v2.4.0...v2.4.1
[2.4.0]: https://github.com/pouriyajamshidi/nginwho/compare/v2.3.1...v2.4.0
[2.3.1]: https://github.com/pouriyajamshidi/nginwho/compare/v2.3.0...v2.3.1
[2.3.0]: https://github.com/pouriyajamshidi/nginwho/compare/v2.2.0...v2.3.0
[2.2.0]: https://github.com/pouriyajamshidi/nginwho/compare/v2.1.0...v2.2.0
[2.1.0]: https://github.com/pouriyajamshidi/nginwho/compare/v2.0.0...v2.1.0
[2.0.0]: https://github.com/pouriyajamshidi/nginwho/releases/tag/v2.0.0
