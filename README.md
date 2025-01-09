# Caddy-Trojan

Caddyfile:

```
{
  servers {
    listener_wrappers {
      trojan {
        user PASSWORD
      }
    }
  }
}
:443, EXAMPLE.COM {
  tls EMAIL@EMAIL.com {
    protocols tls1.2 tls1.3
  }
     file_server {
      root /usr/share/caddy
    }
  } 
  ```
  
fork from :


https://github.com/wen-long/caddy-trojan

https://github.com/imgk/caddy-trojan
 
