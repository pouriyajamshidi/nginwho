# nginwho

<div align="center" style="width: 100%;">
 <img alt="nginwho" src="https://github.com/pouriyajamshidi/nginwho/blob/master/artwork/nginwho.jpeg?raw=true" width="700">
</div>

---

**nginwho** is a lightweight, efficient and extremely fast `nginx` log parser that stores the logs into a **sqlite3** database for further analysis and actions.

Additionally, it has the ability (`--show-real-ips` flag) to continuously parse **Cloudflare CIDRs** through their APIs so that nginx can leverage it to get the real IP addresses of requests hitting your servers.

## How it works

By default, **nginwho** reads `nginx` logs from `/var/log/nginx/access.log` and stores the parsed results in `/var/log/nginwho.db` unless overridden by the [available flags](#flags).

Using the `--show-real-ips` flag requires **root privileges** and leads to fetching the Cloudflare CIDRs every six hours and storing them in `/etc/nginx/reverse_proxies`.

Inside your nginx configuration add this line:

```text
include /etc/nginx/reverse_proxies;
```

So that the fetched CIDRs could be loaded into your configuration.

> [!IMPORTANT]
> The `--show-real-ips:true` option causes a **soft reload** (nginx -s reload) at 3AM **only if there are CIDR changes** in comparison to the last fetch. Specifying the reload time will be available through a flag in the future.

## Usage

1. Download the executable file from this URL:

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

    # If you want to get real IP addresses of the visitors coming from Cloudflare (replace thegraynode.io with your domain):
    nginwho --logPath:/var/log/nginx/access.log \
            --dbPath:/var/log/nginwho.db \
            --omit-referrer:thegraynode.io \
            --show-real-ips:true
   ```

4. Optionally, use the [accompanying systemd](https://github.com/pouriyajamshidi/nginwho/blob/master/nginwho.service) service to run `nginwho` in the background and for the program to survive system reboots:

   ```bash
   sudo cp nginwho.service /etc/systemd/system/nginwho.service
   sudo systemctl enable nginwho.service
   sudo systemctl start nginwho.service
   ```

## Flags

Here are the available flags:

```text
--help, -h         : show help
--version, -v      : Display version and quit
--dbPath,          : Path to SQLite database to log reports (default: /var/log/nginwho.db)
--logPath,         : Path to nginx access logs (default: /var/log/nginx/access.log)
--interval         : Refresh interval in seconds (default: 10)
--omit-referrer    : omit a specific referrer from being logged (default: "")
--show-real-ips    : Show real IP of visitors by getting Cloudflare CIDRs to include in nginx config. Updates every three hours. (default: false)
```
