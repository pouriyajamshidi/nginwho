# Changelog

All notable changes to **nginwho** are listed here.

## [2.3.0]

### Changed

- Only read new lines from the nginx log instead of reading the whole file every time. Log rotation and truncation are handled.
- Reload nginx right away after the Cloudflare CIDRs change, as long as `nginx -t` passes. The reload is graceful and does not drop open connections.
- Use the async http client for Cloudflare so a slow call does not block log processing.
- Write nftables rules to `/run/nginwho.nft` instead of `/tmp/nginwho.nft`.
- Reduce unnecessary logging of accepted traffic.
- V1 to V2 database migration pages with `rowid` instead of `OFFSET`, which is much faster on big databases.
- Keep `.xml` requests during migration like live log processing does.

### Fixed

- `--migrateV1ToV2Db` flag was not recognized and depended on flag order.
- The leading `/` was removed from URIs ending with `/` (for example `/blog/` was stored as `blog`).
- Boolean flags passed without a value (for example `--showRealIps`) crashed.
- Empty log lines made log processing sleep.
- Logs with the same date, IP, method and URI could be inserted twice.
- Cloudflare CIDR updates stopped forever after the first change.
- Failed Cloudflare API calls crashed nginwho. The http client is now closed and has a timeout.
- Failed log inserts left the database transaction open.
- Crashes when checking nftables rules with unexpected keys.
- Crash when the current nftables rules can't be read.
- Crash on trailing spaces or invalid CIDRs in `/etc/nginx/nginwho`.
- Rules were applied even when writing the nftables rules file failed.
- `--blockUntrustedCidrs` without `--showRealIps` slept six hours for nothing.
- Report mode crashed on Ctrl+D.
- Migration batch counting.
- `network.target` name in the systemd service.

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

[2.3.0]: https://github.com/pouriyajamshidi/nginwho/compare/v2.2.0...v2.3.0
[2.2.0]: https://github.com/pouriyajamshidi/nginwho/compare/v2.1.0...v2.2.0
[2.1.0]: https://github.com/pouriyajamshidi/nginwho/compare/v2.0.0...v2.1.0
[2.0.0]: https://github.com/pouriyajamshidi/nginwho/releases/tag/v2.0.0
