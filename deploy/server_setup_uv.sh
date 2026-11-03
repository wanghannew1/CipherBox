#!/usr/bin/env bash
# =============================================================================
# deploy/server_setup_uv.sh — cipherbox 服务器一键部署（uv 虚拟环境版，Ubuntu/Linux）
#
# 幂等：重复执行安全（已完成的步骤自动跳过）。
#   1. 检查/安装 uv（--install-uv 自动装，装到 ~/.local/bin）
#   2. uv venv 创建 server/.venv（uv 缺系统 Python 时会自动下载 CPython 3.11）
#   3. uv pip 安装 server/requirements.txt
#   4. 生成自签 CA/服务器证书（已存在则跳过；Ubuntu 自带 openssl）
#   5. 种子数据库 + HMAC 审计密钥（已存在则跳过；--reseed 重新签发令牌）
#
# 用法：
#   bash deploy/server_setup_uv.sh                # 常规
#   bash deploy/server_setup_uv.sh --install-uv   # uv 缺失时
#   bash deploy/server_setup_uv.sh --recreate     # 重建虚拟环境
#   bash deploy/server_setup_uv.sh --reseed       # 重新签发令牌
# =============================================================================
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"
VENV_PY="server/.venv/bin/python"

INSTALL_UV=0; RECREATE=0; RESEED=0
for arg in "$@"; do
  case "$arg" in
    --install-uv) INSTALL_UV=1 ;;
    --recreate)   RECREATE=1 ;;
    --reseed)     RESEED=1 ;;
    *) echo "[setup] 未知参数: $arg（支持 --install-uv / --recreate / --reseed）"; exit 1 ;;
  esac
done

step() { echo "[setup] $*"; }
ok()   { echo "[setup] $*"; }

# -- 0. 国内镜像默认（npmmirror 同步 python-build-standalone，TUNA 同步 PyPI；
#      已自行设置 UV_* 变量则尊重现有值）----------------------------------------------
export UV_PYTHON_INSTALL_MIRROR="${UV_PYTHON_INSTALL_MIRROR:-https://registry.npmmirror.com/-/binary/python-build-standalone}"
export UV_DEFAULT_INDEX="${UV_DEFAULT_INDEX:-https://pypi.tuna.tsinghua.edu.cn/simple}"
PYTHON_VERSION="${CIPHERBOX_PYTHON:-3.11}"

# -- 1. uv -------------------------------------------------------------------
if ! command -v uv >/dev/null 2>&1; then
  if [ "$INSTALL_UV" -ne 1 ]; then
    echo "[setup] 未找到 uv。二选一：" >&2
    echo "  a) 重新运行并加 --install-uv 自动安装" >&2
    echo "  b) 手动安装: curl -LsSf https://astral.sh/uv/install.sh | sh" >&2
    exit 1
  fi
  step "安装 uv ..."
  curl -LsSf https://astral.sh/uv/install.sh | sh
  export PATH="$HOME/.local/bin:$PATH"
  command -v uv >/dev/null 2>&1 || { echo "[setup] uv 安装后仍不可用（重开终端再试）" >&2; exit 1; }
fi
ok "uv $(uv --version)"

# -- 2. 虚拟环境（uv 自动补齐缺失的 CPython，无需 apt 装 python3.11）----------------
if [ "$RECREATE" -eq 1 ] && [ -d server/.venv ]; then
  step "删除旧虚拟环境（--recreate）..."
  rm -rf server/.venv
fi
if [ ! -x "$VENV_PY" ]; then
  step "uv venv 创建 server/.venv (python $PYTHON_VERSION)..."
  uv venv server/.venv --python "$PYTHON_VERSION"
else
  ok "虚拟环境已存在: $VENV_PY"
fi

# -- 3. 依赖 -------------------------------------------------------------------
step "uv pip 安装 server/requirements.txt ..."
uv pip install --python "$VENV_PY" -r server/requirements.txt

# -- 4. 证书（Ubuntu 自带 openssl）------------------------------------------------
if [ -f server/certs/server.crt ]; then
  ok "证书已存在: server/certs/（跳过；--force 语义见 gen_certs.py）"
else
  if ! command -v openssl >/dev/null 2>&1; then
    echo "[setup] 未找到 openssl: sudo apt install openssl 后重跑" >&2
    exit 1
  fi
  step "生成自签 CA + 服务器证书 ..."
  "$VENV_PY" deploy/gen_certs.py
fi

# -- 5. 种子数据库 -----------------------------------------------------------------
if [ -f server/cipherbox.db ] && [ "$RESEED" -ne 1 ]; then
  ok "数据库已存在: server/cipherbox.db（跳过；--reseed 重新签发令牌）"
else
  if [ "$RESEED" -eq 1 ]; then
    step "重新签发令牌（旧令牌仍有效，建议先 /admin/revoke）..."
  else
    step "种子数据库 + HMAC 审计密钥 ..."
  fi
  "$VENV_PY" deploy/seed_local.py --db server/cipherbox.db --hmac-out server/audit-hmac.key
fi

# -- 完成 ---------------------------------------------------------------------------
echo ""
ok "服务器部署完成。日常操作："
echo "  启动:   bash deploy/server_start.sh                （前台；systemd 自启见 Ubuntu 部署指南）"
echo "  健康检查: curl -sk https://127.0.0.1:8443/health"
echo "  审计校验: $VENV_PY -m server.verify_audit server/cipherbox.db server/audit-hmac.key"
echo "  令牌只打印过一次——丢失请用 --reseed 重新签发。"
