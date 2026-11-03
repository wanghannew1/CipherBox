# CipherBox 服务器部署指南（Ubuntu）

> 适用：Ubuntu 20.04/22.04/24.04（服务器仅需 Python ≥3.11 + openssl，**无需 LibreOffice**——那是客户端的事）。
> 本指南全部命令已在 **WSL Ubuntu-24.04 真机验证**：一键部署、53 项测试全绿、HTTPS 健康检查通过。
> Windows 部署见《[服务器部署指南](服务器部署指南.md)》。

## 方式一：一键部署（推荐）

```bash
cd /opt/cipherbox        # 仓库位置（git clone 或 scp 上去）
bash deploy/server_setup_uv.sh --install-uv
```

脚本幂等（重复执行安全），自动完成：

| 步骤 | 内容 | 说明 |
|---|---|---|
| 1 | 安装 uv（`--install-uv` 时，装到 `~/.local/bin`） | 已装则跳过 |
| 2 | `uv venv server/.venv`（Python 3.11） | **系统没有 3.11 时 uv 自动下载 CPython**，无需 apt |
| 3 | `uv pip install -r server/requirements.txt` | TUNA PyPI 镜像 |
| 4 | `gen_certs.py` 自签 CA + 服务器证书 | Ubuntu 自带 openssl；`server/certs/server.crt` 已存在则跳过 |
| 5 | `seed_local.py` 建库 + 种子令牌 + HMAC 审计密钥 | db 已存在则跳过（`--reseed` 重签） |

**国内镜像内置默认**（可被同名环境变量覆盖）：
- CPython 下载 → `UV_PYTHON_INSTALL_MIRROR` = npmmirror（TUNA 不同步 python-build-standalone，勿改回）
- PyPI → `UV_DEFAULT_INDEX` = TUNA

**重要输出**：admin/employee 令牌**只打印一次**，当场保存。丢失用 `--reseed` 重签。

参数：`--install-uv` / `--recreate`（重建 venv）/ `--reseed`；Python 版本可用 `CIPHERBOX_PYTHON=3.12 bash deploy/server_setup_uv.sh` 覆盖。

## 手动分步（等效）

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh    # 装 uv（已有跳过）
export PATH="$HOME/.local/bin:$PATH"
cd /opt/cipherbox
uv venv server/.venv --python 3.11                  # uv 会自动下载缺失的 CPython
uv pip install --python server/.venv/bin/python -r server/requirements.txt
server/.venv/bin/python deploy/gen_certs.py
server/.venv/bin/python deploy/seed_local.py --db server/cipherbox.db --hmac-out server/audit-hmac.key
```

## 日常运维

```bash
# 前台启动（Ctrl+C 停止；只绑 TLS，无 HTTP 端口）
bash deploy/server_start.sh
# 覆盖端口: CIPHERBOX_PORT=9443 bash deploy/server_start.sh

# 健康检查
curl -sk https://127.0.0.1:8443/health        # {"status":"ok"}

# 审计链完整性校验
server/.venv/bin/python -m server.verify_audit server/cipherbox.db server/audit-hmac.key

# 查审计事件（admin 令牌）
curl -sk -H "Authorization: Bearer <ADMIN_TOKEN>" "https://127.0.0.1:8443/events"
```

## systemd 开机自启（生产推荐）

```bash
# 1. 部署到固定路径（unit 文件默认假定 /opt/cipherbox）
sudo cp -r <仓库> /opt/cipherbox

# 2.（推荐）专用服务账户
sudo useradd -r -s /usr/sbin/nologin cipherbox
sudo chown -R cipherbox:cipherbox /opt/cipherbox
sudo sed -i 's/^# User=cipherbox/User=cipherbox/; s/^# Group=cipherbox/Group=cipherbox/' \
  /opt/cipherbox/deploy/cipherbox-server.service

# 3. 启用
sudo cp /opt/cipherbox/deploy/cipherbox-server.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now cipherbox-server
systemctl status cipherbox-server
journalctl -u cipherbox-server -f          # 跟日志
```

## 防火墙（双机部署时）

```bash
sudo ufw allow 8443/tcp
# 客户端 config/client.json: server_url=https://<服务器IP>:8443
```

## 双机部署要点：证书 SAN

自签证书默认 SAN 只含 `localhost / 127.0.0.1`，客户端从别的机器访问会证书校验失败。用 `--san` 加入服务器 IP 后重签（然后重新分发 ca.crt 给客户端）：

```bash
server/.venv/bin/python deploy/gen_certs.py --force \
  --san DNS:cipherbox.corp --san IP:192.168.1.10
```

## 运行测试（可选，验证部署完整性）

```bash
server/.venv/bin/python -m pytest server/tests -q        # 53 passed（Ubuntu 24.04 实测）
```

## 常见问题

| 现象 | 处理 |
|---|---|
| 浏览器访问 `https://<IP>:8443/` 返回 `{"detail":"Not Found"}` | **正常**——这是纯 API 服务，没有网页。`/` 未定义路由即 404；能收到这个 JSON 恰好证明 TLS 和跨机器访问是通的。健康检查用 `/health` |
| 客户端（浏览器/Agent）报证书校验失败 | 证书默认 SAN 只有 localhost/127.0.0.1。双机部署必须 `--force --san IP:<服务器IP>` 重签并重启服务，再把 `ca.crt` 分发给客户端 |
| `curl astral.sh` 超时装不上 uv | 手动从 GitHub release 下载 uv 二进制放 `~/.local/bin/`，或代理后重试（安装器自带备用下载地址，失败会自动切换） |
| venv 步骤 404 / 下载慢 | 确认 `UV_PYTHON_INSTALL_MIRROR` 指向 npmmirror（脚本默认已设；勿用 TUNA——它不同步 python-build-standalone） |
| 端口被占 | `ss -ltnp \| grep 8443` 找进程，或 `CIPHERBOX_PORT=9443` 换端口 |
| `bash: 行N: 未预期的记号` / `\r` 报错 | 脚本被 CRLF 污染：仓库 `.gitattributes` 已强制 `*.sh eol=lf`；手动修复 `sed -i 's/\r$//' deploy/*.sh` |
| 401 | 令牌错/过期；`--reseed` 重签（正式环境先 `/admin/revoke`） |
| pytest 里集成测试 2 failed | 多半是 8443 已有服务器在跑（端口冲突）——先停再测 |

## 安全须知

```bash
chmod 600 server/certs/*.key server/audit-hmac.key   # 私钥与 HMAC 密钥仅运行账户可读
```

- `server/certs/`、`*.db`、`audit-hmac.key` 均在 `.gitignore` 内，不入库。
- 正式环境配专用系统账户运行（见 systemd 小节；todo 20⑥ 完整 ACL/DPAPI 为已登记缺口）。
- 主密钥目前明文存 DB（DPAPI 包裹待补，见交接文档 v2）。
