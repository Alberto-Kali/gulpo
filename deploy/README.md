# Production Deployment Notes

## Topology

- `panel-web`, `panel-api`, `postgres` run from `compose.prod.panel.yaml`
- `node-agent + sing-box` runs from `compose.prod.node.yaml`
- `nginx` runs on the host and terminates HTTPS for the panel at `https://gulpo.pw/panel`
- node protocols keep their own node domain and ports, for example `alpha.gulpo.pw:8443` for Trojan and `alpha.gulpo.pw:2087/udp` for Hysteria2
- public subscriptions stay on:
  - `https://gulpo.pw/sub/{token}`
  - `https://gulpo.pw/subj/{token}`
  - node-adjacent subscription aliases such as `https://alpha.gulpo.pw/sub/{token}` may remain enabled while a panel and node share one server

## Required files on the server

1. `deploy/env/panel.env`
2. `deploy/env/node.env`
3. `deploy/nginx/gulpo.conf`

Create them from the `.example` files before first launch.

## Expected launch order

1. Start panel stack:
   - `docker compose -f compose.prod.panel.yaml up -d`
2. Start node stack:
   - `docker compose -f compose.prod.node.yaml up -d`
3. Enable nginx config and reload:
   - symlink `deploy/nginx/gulpo.conf` into `/etc/nginx/sites-available/`
   - enable in `/etc/nginx/sites-enabled/`
   - `nginx -t && systemctl reload nginx`
4. Issue host certificates with certbot webroot:
   - panel: `certbot certonly --webroot -w /var/www/certbot -d gulpo.pw`
   - node web/SNI: `certbot certonly --webroot -w /var/www/certbot -d alpha.gulpo.pw`
   - install a deploy hook that runs `nginx -t && systemctl reload nginx` after renewal
5. Run smoke checks:
   - `bash deploy/scripts/smoke-prod.sh alpha.gulpo.pw`
