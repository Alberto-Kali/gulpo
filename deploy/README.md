# Production Deployment Notes

## Topology

- `panel-web`, `panel-api`, `postgres` run from `compose.prod.panel.yaml`
- `node-agent + sing-box` runs from `compose.prod.node.yaml`
- `nginx` runs on the host and terminates HTTPS for `https://alpha.gulpo.pw/panel`
- public subscriptions stay on:
  - `https://alpha.gulpo.pw/sub/{token}`
  - `https://alpha.gulpo.pw/subj/{token}`

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
4. Run smoke checks:
   - `bash deploy/scripts/smoke-prod.sh alpha.gulpo.pw`
