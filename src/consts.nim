const
  CF_IP_API: string = "https://api.cloudflare.com/client/v4/ips"
  CF_REAL_IP_HEADER: string = "CF-Connecting-IP;"

  FASTLY_IP_API:string = "https://api.fastly.com/public-ip-list"
  
  DEFAULT_OUTPUT_PATH: string = "/etc/nginx/reverse_proxies"
  
  CFG_SET_REAL_IP_FROM: string = "set_real_ip_from"
  CFG_REAL_IP_HEADER: string = "real_ip_header"

  ONE_MINUTE: int = 60_000
  THREE_HOURS: int = 108_000_00
  SIX_HOURS: int = 216_000_00
  TWELVE_HOURS: int = 432_000_00
  # TWELVE_HOURS: int = int(12.hours.milliseconds)

  NGINX_PROCESS_NAME: string = "nginx"
  NGINX_TEST_CMD: string = "nginx -t"
  NGINX_RELOAD_CMD: string = "nginx -s reload"
