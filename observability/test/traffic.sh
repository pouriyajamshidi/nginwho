#!/bin/sh
# fakes visitors and bots against both sites, forever, so the dashboard has something to show.
# nginx takes the visitor IP from X-Forwarded-For. nginwho --serve only trusts a CDN,
# so its visitors show up with docker's private IPs

people="81.2.69.160 5.255.255.5 202.12.27.33 200.160.0.8 196.25.1.1 168.126.63.1 139.130.4.5 41.203.64.1 177.43.35.1 212.58.244.1 193.0.6.139 185.60.216.35"
bots="45.33.32.156 223.5.5.5 84.200.69.80 62.210.16.6 95.216.1.1 13.107.21.200 134.209.1.1 159.89.1.1 47.74.1.1 49.12.1.1"
pages="/ /about/ /posts/index.xml /robots.txt /abuot /about/team"
probes="/.env /wp-login.php /.git/config /phpmyadmin/ /admin.php /backup.zip /config.php /xmlrpc.php"
browser="Mozilla/5.0 (X11; Linux x86_64; rv:130.0) Gecko/20100101 Firefox/130.0"
referrers="https://duckduckgo.com/ https://news.ycombinator.com/ https://github.com/pouriyajamshidi/nginwho"

pick() {
  # prints a random word from the list in $1
  set -- $1
  shift $((RANDOM % $#))
  echo "$1"
}

visit() {
  # visit <site> <ip> <path> <user agent> [extra curl flags]
  site=$1 ip=$2 path=$3 agent=$4
  shift 4
  curl -s -o /dev/null --max-time 3 -H "X-Forwarded-For: $ip" -A "$agent" "$@" "http://$site$path" || true
}

round() {
  for site in nginx nginwho-serve; do
    # people read pages, some come from a link
    for _ in 1 2 3 4 5 6; do
      visit $site "$(pick "$people")" "$(pick "$pages")" "$browser" -e "$(pick "$referrers")"
    done
    # feed readers and crawlers run in data centers, they are welcome
    visit $site 178.128.1.1 /posts/index.xml "Feedbin feed-id:1234 - 1 subscribers"
    visit $site "$(pick "$bots")" / "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)"
    # scrapers get a 403 from nginx, then the trap
    visit $site "$(pick "$bots")" / "python-requests/2.32"
    # probes for files we don't have, sometimes a fake login
    visit $site "$(pick "$bots")" "$(pick "$probes")" "Mozilla/5.0 zgrab/0.x"
    visit $site "$(pick "$bots")" /wp-login.php "Mozilla/5.0" -d "log=admin&pwd=admin"
  done
}

# a busy start, then a steady trickle
for _ in $(seq 1 30); do round; done
while true; do
  round
  sleep $((5 + RANDOM % 10))
done
