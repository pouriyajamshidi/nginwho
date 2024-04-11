const
  VERSION*: string = "1.0.0"

  DATE_FORMAT*: string = "yyyy-MM-dd HH:mm:ss"

  DB_FILE*: string = "/var/log/nginwho.db"

  CLOUDFLARE_CIDR_API_URL*: string = "https://api.cloudflare.com/client/v4/ips"

  FASTLY_IP_API_URL:string = "https://api.fastly.com/public-ip-list"
  
  NGINX_DEFAULT_LOG_PATH*: string = "/var/log/nginx/access.log"
  NGINX_CIDR_FILE*: string = "/etc/nginx/reverse_proxies"
  NGINX_SET_REAL_IP_FROM*: string = "set_real_ip_from"
  NGINX_REAL_IP_HEADER*: string = "real_ip_header"
  NGINX_CF_REAL_IP_HEADER*: string = "CF-Connecting-IP;"
  NGINX_PROCESS_NAME*: string = "nginx"
  NGINX_TEST_CMD*: string = "nginx -t"
  NGINX_RELOAD_CMD*: string = "nginx -s reload"

  FIVE_SECONDS*: int = 5_000
  TEN_SECONDS*: int = 10_000
  ONE_MINUTE*: int = 60_000
  THREE_HOURS*: int = 108_000_00
  SIX_HOURS*: int = 216_000_00
  TWELVE_HOURS*: int = 432_000_00
  # TWELVE_HOURS*: int = int(12.hours.milliseconds)

  TEMP_NFT_FILE_PATH*: string = "nft_working_output.json"
  TEMP_PROXY_FILE_PATH*: string = "reverse_proxies.txt"
  NFT_CONFIG_FILE_PATH*: string = "/etc/nftables.conf"
  NFT_MIN_RULE_LEN*: int = 2
  NFT*: string = "nftables"
  NFT_SET_NAME_CF*: string = "Cloudflare"
  NFT_CHAIN_NAME*: string = "nginwho"
  NFT_GET_RULESET_CMD*: string = "nft -j list ruleset"

  # NFT_CIDR_RULES_FILE* = "/tmp/nginwho.nft"
  NFT_CIDR_RULES_FILE*: string = "nginwho.nft"
