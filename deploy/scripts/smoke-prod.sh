#!/usr/bin/env bash
set -euo pipefail

DOMAIN="${1:-alpha.gulpo.pw}"

echo "[1/6] panel web"
curl -fsS "https://${DOMAIN}/panel" >/dev/null

echo "[2/6] panel api health"
curl -fsS "https://${DOMAIN}/panel/api/healthz" | grep -q '"status":"ok"'

echo "[3/6] raw subscription route"
curl -fsSI "https://${DOMAIN}/sub/invalid-token" >/dev/null || true

echo "[4/6] panel docker services"
docker compose -f compose.prod.panel.yaml ps

echo "[5/6] node docker services"
docker compose -f compose.prod.node.yaml ps

echo "[6/6] open ports"
ss -tulpn | grep -E ':(80|443|2080|8443|9443|8444|8445)\b' || true

echo "smoke complete"
