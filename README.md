# nginwho

<div align="center" style="width: 100%;">
 <img alt="nginwho" src="https://github.com/pouriyajamshidi/nginwho/blob/master/artwork/nginwho.jpeg?raw=true" width="700">
</div>

---

**nginwho** is a lightweight, efficient and extremely fast program offering:

1. [nginx log parser](#nginx-log-parser): Stores nginx logs into a **sqlite3** database for further analysis and actions
2. [Restore Cloudflare](#restore-cloudflare-original-visitor-ip) original visitor IP: Continuously parses **Cloudflare CIDRs** (`IPv4` and `IPv6`) through their **API**s so that nginx can leverage it to restore the original IP address of visitors
3. [Block untrusted](#block-untrusted-requests) requests using **nftables** to prevent HTTP and HTTPS requests coming from unknown IP addresses
4. [Reporting](#reporting) on gathered data such as top visited URLs through a TUI

Table of contents:

- [nginwho](#nginwho)
  - [Usage](#usage)
  - [Flags](#flags)
  - [How it works](#how-it-works)
    - [nginx Log Parser](#nginx-log-parser)
    - [Restore Cloudflare Original Visitor IP](#restore-cloudflare-original-visitor-ip)
    - [Block Untrusted Requests](#block-untrusted-requests)
    - [Reporting](#reporting)
    - [Migrating v1 database to v2](#migrating-v1-database-to-v2)

## Usage

> [!IMPORTANT]
> If you have been a user since version 1, please check out [this section](#migrating-v1-database-to-v2) to migrate your database scheme to version 2.

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
            --omitReferrer:thegraynode.io

    # If you want to get real IP addresses of the visitors coming from Cloudflare:
    nginwho --logPath:/var/log/nginx/access.log \
            --dbPath:/var/log/nginwho.db \
            --showRealIps:true
   ```

> Please note that you can mix these flags. They operate independently.

1. Optionally, use the [accompanying systemd](https://github.com/pouriyajamshidi/nginwho/blob/master/nginwho.service) to run **nginwho** as a service in the background and for the it to survive system reboots:

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
  --omitReferrer          : Omit a specific referrer from being logged (default: none)
  --showRealIps           : Show real IP of visitors by getting Cloudflare CIDRs to include in nginx config.
                            Self-updates every six hours (default: false)
  --blockUntrustedCidrs   : Block untrusted IP addresses using nftables. Only allows Cloudflare CIDRs (default: false)
  --processNginxLogs      : Process nginx logs (default: true)
  --report                : Enter report mode and query the database for statistics

  --migrateV1ToV2Db       : Migrate V1 database to V2 and exit (default: false).
                            Use with '--v1DbPath' and '--v2DbPath' flags
  --v1DbPath              : Path and name of the V1 database (e.g: /var/log/nginwho_v1.db)
  --v2DbPath              : Path and name of the V2 database (e.g: /var/log/nginwho.db)

```

## How it works

Let's see how nginwho works in a somewhat detailed yet short fashion.

### nginx Log Parser

**nginwho** by default reads `nginx` logs from `/var/log/nginx/access.log` and stores the parsed results in a **sqlite3** database located in `/var/log/nginwho.db` unless overridden by the [available flags](#flags).

> [!WARNING]
> nginwho only supports the default nginx log format or any application that logs in the same format for now

### Restore Cloudflare Original Visitor IP

The second feature, `--showRealIps` flag fetches **Cloudflare CIDRs** (`IPv4` and `IPv6`) every _six hours_ through their **API**s and writes the result to a file named `nginwho` located in `/etc/nginx/`.

It is worthwhile to mention that **nginwho** leverages the `etag` field in Cloudflare's API response, so, if the newly fetched `etag` is the same as the current one, the `/etc/nginx/nginwho` file will not be overwritten.

If the `/etc/nginx/nginwho` file has changed or this is a fresh run, **nginwho** schedules the **nginx** service to be soft reloaded (`nginx -s reload`) at 3 AM.

> [!IMPORTANT]
> The `--showRealIps` flag requires **root privileges**.

For `--showRealIps` flag to work, you need to alter your **nginx** configuration add this line to include the generated configuration inside the `/etc/nginx/nginwho` file:

```text
include /etc/nginx/nginwho;
```

So that nginx knows how to restore original visitor IP addresses.

### Block Untrusted Requests

The third feature, `--block-untrusted-cidrs` flag periodically gets Cloudflare CIDRs, either through:

1. Cloudflare APIs when used in conjunction with `--showRealIps` flag
2. or the `/etc/nginx/nginwho` file when the `--showRealIps` flag is not specified

The fetched CIDRs will be checked against your existing **nftables** rules and if necessary, the required rules will be created and added through _nftable's JSON API_.

There will be a bunch of tests and pre-checks done before applying any policies. These checks include:

1. Existence of Cloudflare IPv4 CIDRs nftables _Set_ (`Cloudflare_IPv4`)
1. Existence of Cloudflare IPv6 CIDRs nftables _Set_ (`Cloudflare_IPv6`)
1. Existence of nftables `nginwho` chain (`prerouting` hook)
1. Existence of nftables `input` chain
1. Existence of **drop** policy inside `nginwho` chain for untrusted IP addresses on port **80** and **443**
1. Existence of **accept** policy inside `input` chain for trusted IP addresses on port **80** and **443**

**nginwho** only creates the necessary changes. Otherwise, no actions will be taken. For instance, if a CIDR gets added or removed, only that part of **nftables** configuration will be changed and the rest remain unchanged.

> [!IMPORTANT]
> Since playing with **nftables** could result in blocking yourself out, **nginwho** requires you to have some basic policies in place, in specific, having an `inet filter` table. If you do not have it, **nginwho** will detect that and shows you how to create one.

### Reporting

Running **nginwho** with the `--report` flag will launch a TUI, providing some options (top visited URLs, top visiting IP addresses, etc.) that you can select and specify how many records to be queried.

```bash
nginwho --report --dbPath:/var/log/nginwho.db
```

### Migrating v1 database to v2

Running the command below will first check your database for any errors and, if it detects any, will output what recovery command should be run. If everything is fine, it will read out the data from your source database, convert and write the data to version 2 so that nginwho can continue working as intended.

> Also, please be noted to change the database file names according to your setup.

```bash
nginwho --migrateV1ToV2:true \
        --v1DbPath:nginwho_v1.db \
        --v2DbPath:nginwho.db \
```
