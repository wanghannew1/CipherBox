#!/usr/bin/env bash
# =============================================================================
# deploy/server_start.sh — cipherbox 服务器日常启动（HTTPS 8443，仅 TLS）
#
# 由 deploy/server_setup_uv.sh 部署完成后使用：
#   bash deploy/server_start.sh
# 端口/地址可用环境变量覆盖: CIPHERBOX_HOST=0.0.0.0 CIPHERBOX_PORT=8443 bash deploy/server_start.sh
# exec 保证 systemd/Ctrl+C 信号直达 uvicorn。
# =============================================================================
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

VENV_PY="server/.venv/bin/python"
HOST="${CIPHERBOX_HOST:-0.0.0.0}"
PORT="${CIPHERBOX_PORT:-8443}"

if [ ! -x "$VENV_PY" ]; then
  echo "[server] 虚拟环境不存在，先运行: bash deploy/server_setup_uv.sh" >&2
  exit 1
fi
if [ ! -f server/audit-hmac.key ]; then
  echo "[server] 缺 server/audit-hmac.key，先运行: bash deploy/server_setup_uv.sh" >&2
  exit 1
fi

export CIPHERBOX_HMAC_KEY_FILE="$REPO_ROOT/server/audit-hmac.key"
echo "[server] HTTPS https://${HOST}:${PORT}  (无 HTTP 监听；CA=server/certs/ca.crt)"
exec "$VENV_PY" -m uvicorn server.app:create_app --factory \
  --host "$HOST" --port "$PORT" \
  --ssl-certfile server/certs/server.crt --ssl-keyfile server/certs/server.key
