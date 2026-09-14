# Changelog

All notable changes to **nginwho** are listed here.

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

[2.4.0]: https://github.com/pouriyajamshidi/nginwho/compare/v2.3.1...v2.4.0
[2.3.1]: https://github.com/pouriyajamshidi/nginwho/compare/v2.3.0...v2.3.1
[2.3.0]: https://github.com/pouriyajamshidi/nginwho/compare/v2.2.0...v2.3.0
[2.2.0]: https://github.com/pouriyajamshidi/nginwho/compare/v2.1.0...v2.2.0
[2.1.0]: https://github.com/pouriyajamshidi/nginwho/compare/v2.0.0...v2.1.0
[2.0.0]: https://github.com/pouriyajamshidi/nginwho/releases/tag/v2.0.0
