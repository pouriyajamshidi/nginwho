# nginwho

<div align="center" style="width: 100%;">
 <img alt="nginwho" src="https://github.com/pouriyajamshidi/nginwho/blob/master/artwork/nginwho.jpeg?raw=true" width="700">
</div>

---

**nginwho** is a lightweight, efficient and extremely fast `nginx` log parser that stores the logs into a **sqlite3** database for further analysis and actions.

## How it works

By default, **nginwho** reads `nginx` logs from `/var/log/nginx/access.log` and stores the parsed results in `/var/log/nginwho.db` unless overridden by the [available flags](#flags).

## Usage

1. Download the executable file from this URL:

   ```bash
   wget https://github.com/pouriyajamshidi/nginwho/releases/latest/download/nginwho
   ```

2. Make it executable and move it to your `$PATH`:

   ```bash
   chmod +x nginwho
   sudo cp nginwho /usr/local/bin
   ```

3. Run it:

   ```bash
    nginwho --logPath:/var/log/nginx/access.log --dbPath:/var/log/nginwho.db
    # If you want to omit a certain referrer from being logged:
    nginwho --logPath:/var/log/nginx/access.log \
            --dbPath:/var/log/nginwho.db \
            --omit-referrer:thegraynode.io
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
--omit-referrer    : omit a specific referrer from being logged
```
