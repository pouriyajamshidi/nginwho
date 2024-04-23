# nginwho

<div align="center" style="width: 100%;">
 <img alt="nginwho" src="https://github.com/pouriyajamshidi/nginwho/blob/master/artwork/nginwho.jpeg?raw=true" width="700">
</div>

---

**nginwho** is a lightweight, efficient and extremely fast program offering three main features at its core:

1. **nginx** log parser: Stores nginx logs into a **sqlite3** database for further analysis and actions
2. Restore **Cloudflare** original visitor IP: Continuously parses **Cloudflare CIDRs** (`IPv4` and `IPv6`) through their **API**s so that nginx can leverage it to restore the original IP address of visitors
3. **Block** untrusted requests: Uses **nftables** to block HTTP and HTTPS requests coming from unknown IP addresses

Table of contents:

- [nginwho](#nginwho)
  - [Usage](#usage)
  - [Flags](#flags)
  - [How it works](#how-it-works)
    - [nginx Log Parser](#nginx-log-parser)
    - [Restore Cloudflare Original Visitor IP](#restore-cloudflare-original-visitor-ip)
    - [Block Untrusted Requests](#block-untrusted-requests)

## Usage

1. Download **nginwho** from this URL:

   ```bash
   wget https://github.com/pouriyajamshidi/nginwho/releases/latest/download/nginwho
   ```

   Optionally, **nginwho** can also be installed using nimble:

   ```bash
   nimble install nginwho
   ```

2. Make it executable and move it to your `$PATH`:

   ```bash
   chmod +x nginwho
   sudo cp nginwho /usr/local/bin
   ```

3. Run it:

   ```bash
    nginwho --logPath:/var/log/nginx/access.log --dbPath:/var/log/nginwho.db

    # If you want to omit a certain referrer from being logged (replace thegraynode.io with your domain):
    nginwho --logPath:/var/log/nginx/access.log \
            --dbPath:/var/log/nginwho.db \
            --omit-referrer:thegraynode.io

    # If you want to get real IP addresses of the visitors coming from Cloudflare:
    nginwho --logPath:/var/log/nginx/access.log \
            --dbPath:/var/log/nginwho.db \
            --omit-referrer:thegraynode.io \
            --show-real-ips:true
   ```

4. Optionally, use the [accompanying systemd](https://github.com/pouriyajamshidi/nginwho/blob/master/nginwho.service) to run **nginwho** as a service in the background and for the it to survive system reboots:

   ```bash
   sudo cp nginwho.service /etc/systemd/system/nginwho.service
   sudo systemctl enable nginwho.service
   sudo systemctl start nginwho.service
   ```

## Flags

Here are the available flags:

```text
  --help, -h              : Show help
  --version, -v           : Display version and quit
  --dbPath,               : Path to SQLite database to log reports (default: /var/log/nginwho.db)
  --logPath,              : Path to nginx access logs (default: /var/log/nginx/access.log)
  --interval              : Refresh interval in seconds (default: 10)
  --omit-referrer         : Omit a specific referrer from being logged (default: none)
  --analyze-nginx-logs    : Whether to analyze nginx logs or not. (default: true)
  --show-real-ips         : Show real IP of visitors by getting Cloudflare CIDRs to include in nginx config.
                            Self-updates every six hours (default: false)
  --block-untrusted-cidrs : Block untrusted IP addresses using nftables. Only allows Cloudflare CIDRs (default: false)
```

## How it works

Let's see how nginwho works in a somewhat detailed yet short fashion.

### nginx Log Parser

For the first and default feature, **nginwho** reads `nginx` logs from `/var/log/nginx/access.log` and stores the parsed results in a **sqlite3** database located in `/var/log/nginwho.db` unless overridden by the [available flags](#flags).

> [!WARNING]
> nginwho only supports the default nginx log format for now

The table name inside the `nginwho.db` database is also named `ngiwho` and here is the schema of it:

```text
sqlite> PRAGMA table_info(nginwho);
+-----+-------------------+---------+---------+------------+----+
| cid |       name        |  type   | notnull | dflt_value | pk |
+-----+-------------------+---------+---------+------------+----+
| 0   | id                | INTEGER | 0       |            | 1  |
| 1   | date              | TEXT    | 1       |            | 0  |
| 2   | remoteIP          | TEXT    | 1       |            | 0  |
| 3   | httpMethod        | TEXT    | 1       |            | 0  |
| 4   | requestURI        | TEXT    | 1       |            | 0  |
| 5   | statusCode        | TEXT    | 1       |            | 0  |
| 6   | responseSize      | TEXT    | 1       |            | 0  |
| 7   | referrer          | TEXT    | 1       |            | 0  |
| 8   | userAgent         | TEXT    | 1       |            | 0  |
| 9   | nonStandard       | TEXT    | 0       |            | 0  |
| 10  | remoteUser        | TEXT    | 1       |            | 0  |
| 11  | authenticatedUser | TEXT    | 1       |            | 0  |
+-----+-------------------+---------+---------+------------+----+
```

If you want to see the top 30 visited URIs of your server, then you could:

1. Run `sqlite3`'s shell:

   ```bash
   sqlite3 --readonly --table /var/log/nginwho.db
   ```

2. run a **SQL** query like:

   ```sql
   SELECT requestURI, count(*) as visits
   FROM nginwho
   GROUP BY requestURI
   ORDER BY visits DESC
   LIMIT 30;
   ```

This will give you a nice table with your top 30 visited URIs.

### Restore Cloudflare Original Visitor IP

The second feature, `--show-real-ips` flag fetches **Cloudflare CIDRs** (`IPv4` and `IPv6`) every _six hours_ through their **API**s and writes the result to a file located in `/etc/nginx/nginwho`.

It is worthwhile to mention that **nginwho** leverages the `etag` field in Cloudflare's API response, so, if the newly fetched `etag` is the same as the current one, the `/etc/nginx/nginwho` file will not be overwritten.

If the `/etc/nginx/nginwho` file has changed or this is a fresh run, **nginwho** schedules the **nginx** service to be soft reloaded (`nginx -s reload`) at 3 AM.

> [!IMPORTANT]
> The `--show-real-ips` flag requires **root privileges**.

For `--show-real-ips` flag to work, you need to alter your nginx configuration add this line:

```text
include /etc/nginx/nginwho;
```

So that nginx knows how to restore original visitor IP addresses.

### Block Untrusted Requests

The third feature, `--block-untrusted-cidrs` flag periodically gets Cloudflare CIDRs, either through:

1. Cloudflare APIs when used in conjunction with `--show-real-ips` flag
2. or the `/etc/nginx/nginwho` file when the `--show-real-ips` flag is not specified

The fetched CIDRs will be checked against your existing **nftables** rules and if necessary, the required rules will be created and added through _nftables JSON API_.

There will be a bunch of tests and pre-checks done before applying any policies. These checks include:

1. Existence of Cloudflare IPv4 CIDRs nftables Set (`Cloudflare_IPv4`)
1. Existence of Cloudflare IPv6 CIDRs nftables Set (`Cloudflare_IPv6`)
1. Existence of nftables `nginwho` chain (`prerouting` hook)
1. Existence of nftables `input` chain
1. Existence of **drop** policy inside `nginwho` chain for untrusted IP addresses on port **80** and **443**
1. Existence of **accept** policy inside `input` chain for trusted IP addresses on port **80** and **443**

**nginwho** only creates the necessary changes for **nftables**, if no changes are required, no action will be taken. For instance, if a CIDR gets added or removed, only that part of **nftables** configuration will be changed and the rest remain unchanged.

> [!IMPORTANT]
> Since playing with **nftables** could result in blocking yourself out, **nginwho** requires you to have some basic policies in place, in specific, having an `inet filter` table. If you do not have it, **nginwho** will detect that and shows you how to create one.
