import times

const
  VERSION*: string = "1.0.0"

  DATE_FORMAT*: string = "yyyy-MM-dd HH:mm:ss"

  NGINWHO_DB_FILE*: string = "/var/log/nginwho.db"

  FIVE_SECONDS*: int = int(initDuration(seconds = 5).inMilliseconds)
  TEN_SECONDS*: int = int(initDuration(seconds = 10).inMilliseconds)
  ONE_MINUTE*: int = int(initDuration(minutes = 1).inMilliseconds)
  THREE_HOURS*: int = int(initDuration(hours = 3).inMilliseconds)
  SIX_HOURS*: int = int(initDuration(hours = 6).inMilliseconds)
  TWELVE_HOURS*: int = int(initDuration(hours = 12).inMilliseconds)

  CLOUDFLARE_CIDR_API_URL*: string = "https://api.cloudflare.com/client/v4/ips"

  # FASTLY_CIDR_API_URL:string = "https://api.fastly.com/public-ip-list"

  NGINX_CMD*: string = "nginx"
  NGINX_TEST_CMD*: string = "nginx -t"
  NGINX_RELOAD_CMD*: string = "nginx -s reload"
  NGINX_DEFAULT_LOG_PATH*: string = "/var/log/nginx/access.log"
  NGINX_CIDR_FILE*: string = "/etc/nginx/nginwho"
  # NGINX_CIDR_FILE*: string = "temp/reverse_proxies.txt"
  NGINX_SET_REAL_IP_FROM*: string = "set_real_ip_from"
  NGINX_REAL_IP_HEADER*: string = "real_ip_header"
  NGINX_CF_REAL_IP_HEADER*: string = "CF-Connecting-IP;"

  TEMP_NFT_FILE_PATH*: string = "temp/nft_working_output.json"

  NFT_CMD*: string = "nftables"
  NFT_GET_RULESET_CMD*: string = "nft -j list ruleset"
  NFT_CONFIG_FILE_PATH*: string = "/etc/nftables.conf"
  NFT_MIN_RULE_LEN*: int = 2
  NFT_SET_NAME_CF_IPv4*: string = "Cloudflare_IPv4"
  NFT_SET_NAME_CF_IPv6*: string = "Cloudflare_IPv6"
  NFT_KEY_NAME*: string = "nftables"
  NFT_CHAIN_NGINWHO_NAME*: string = "nginwho"
  NFT_CHAIN_INPUT_NAME*: string = "input"
  NFT_CIDR_RULES_FILE* = "/tmp/nginwho.nft"
  # NFT_CIDR_RULES_FILE*: string = "temp/nginwho.nft"
  NFT_LOG_PREFIX*: string = "NGINWHO_DROPPED "

  NFT_SAMPLE_POLICY*: string = """
##########################################
#      Pick either option 1 or 2         #
##########################################


1) Using /etc/nftables.conft:

#!/usr/sbin/nft -f

flush ruleset

table inet filter {
  chain input {
    type filter hook input priority filter; policy drop;
    log prefix "NFTABLES_DROPPED "
    ip saddr 127.0.0.1 counter accept
    ct state established,related accept
    tcp dport 22 counter accept
  }

  chain forward {
    type filter hook forward priority filter; policy drop;
  }

  chain output {
    type filter hook output priority filter; policy accept;
  }
}


#####################################################################
#####################################################################
#####################################################################


2) Using the `nft` command (might require `sudo`):

nft add table inet filter
nft add rule inet filter input ct state established,related accept
nft add rule inet filter input ip saddr 127.0.0.1 accept
nft add rule inet filter input tcp dport 22 accept
nft 'add rule inet filter input tcp dport { 80, 443 } counter accept'
nft 'add chain inet filter forward { type filter hook forward priority filter; policy drop; }'
nft 'add chain inet filter output { type filter hook output priority filter; policy accept; }'


"""
