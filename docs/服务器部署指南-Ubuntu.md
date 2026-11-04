# CipherBox 服务器部署指南（Ubuntu）

> 适用：Ubuntu 20.04/22.04/24.04（服务器仅需 Python ≥3.11 + openssl，**无需 LibreOffice**——那是客户端的事）。
> 本指南全部命令已在 **WSL Ubuntu-24.04 真机验证**：一键部署、53 项测试全绿、HTTPS 健康检查通过。
> Windows 部署见《[服务器部署指南](服务器部署指南.md)》。

## 0. 先决定：部署身份与目录（⚠️ 权限报错先看这里）

部署命令必须**以拥有目录的账户身份执行**。两种受支持的布局：

### 布局 A（简单）：家目录 + 你的日常账户

```bash
git clone <仓库> ~/cipherbox && cd ~/cipherbox
bash deploy/server_setup_uv.sh --install-uv     # 你自己跑，全部写在你自己的家目录
```

一切命令（部署/`git pull`/seed 签发/重启）都以**同一个用户**执行即可，无权限问题。个人/测试环境用这个。

### 布局 B（生产推荐）：/opt + 专用服务账户

`/opt/cipherbox` 归 `cipherbox` 服务账户所有（见 systemd 小节）后，**所有**服务器操作都要以该账户身份执行——包括部署本身：

```bash
# 一次性准备：服务账户要有 home（uv 缓存需要；useradd -r 默认没有）
sudo mkdir -p /home/cipherbox && sudo chown cipherbox:cipherbox /home/cipherbox
# uv 放系统路径，服务账户才能用
sudo cp ~/.local/bin/uv /usr/local/bin/

# 部署（注意：以 cipherbox 身份，不是你的日常用户）
sudo -u cipherbox env HOME=/home/cipherbox bash /opt/cipherbox/deploy/server_setup_uv.sh
```

之后的 `git pull`、`seed_local.py` 签发、重启，同样走 `sudo -u cipherbox ...`。
**混用账户（自己跑部署、服务账户跑服务）→ `Permission denied (os error 13)`**——这是本指南此前未写清的坑。

### 从旧位置迁移（如 ~/github-src → /opt）

数据库、CA、HMAC 密钥与已部署客户端是**配对**的，换目录必须带走，否则客户端全部 401：

```bash
sudo cp ~/旧位置/server/cipherbox.db   /opt/cipherbox/server/
sudo cp ~/旧位置/server/audit-hmac.key /opt/cipherbox/server/
sudo cp -r ~/旧位置/server/certs       /opt/cipherbox/server/
sudo chown -R cipherbox:cipherbox /opt/cipherbox/server
```

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

**⚠️ 第 0 步：单元路径必须与实际部署位置一致。** `deploy/cipherbox-server.service` 里三处路径（WorkingDirectory、HMAC 环境变量、ExecStart）默认写死 `/opt/cipherbox`。部署在别处（如布局 A 的家目录）**必须先替换**，否则服务起不来（`status=203` 或日志报找不到密钥文件）：

```bash
cd <你的仓库位置>     # 例如 /home/vodserver/github-src/cipher-box
sudo sed -i "s|/opt/cipherbox|$PWD|g" deploy/cipherbox-server.service
grep -n 'cipherbox' deploy/cipherbox-server.service   # 核对三处路径已替换
```

```bash
# ── 布局 B（/opt + 专用账户）────────────────────────────────────────────
sudo cp -r <仓库> /opt/cipherbox                        # 且已按第 0 节迁移运行状态
sudo useradd -r -s /usr/sbin/nologin cipherbox
sudo chown -R cipherbox:cipherbox /opt/cipherbox
sudo sed -i 's/^# User=cipherbox/User=cipherbox/; s/^# Group=cipherbox/Group=cipherbox/' \
  /opt/cipherbox/deploy/cipherbox-server.service
# 部署/后续运维都以服务账户身份：sudo -u cipherbox ...

# ── 布局 A（家目录）────────────────────────────────────────────────────
# 服务以部署用户运行：取消 unit 里 User=/Group= 两行注释并改成你的用户名
# sudo sed -i 's/^# User=cipherbox/User=vodserver/; s/^# Group=cipherbox/Group=vodserver/' \
#   deploy/cipherbox-server.service

# ── 启用（两种布局相同）───────────────────────────────────────────────
sudo cp deploy/cipherbox-server.service /etc/systemd/system/
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

## 双机部署要点：证书 SAN + CA 分发（⚠️ 客户端连不上的头号原因）

自签证书默认 SAN 只含 `localhost / 127.0.0.1`。客户端从别的机器访问会双重失败：证书链对不上 + 主机名不匹配。**在服务器上**重签（`--san` 必须带真实 IP，替换占位符！`--force` 会连 CA 一起更换）：

```bash
server/.venv/bin/python deploy/gen_certs.py --force --san IP:192.168.1.10
# 然后重启服务生效（前台 Ctrl+C 重跑，或 sudo systemctl restart cipherbox-server）
```

**⚠️ 重签后 CA 也变了——必须把新的 `server/certs/ca.crt` 重新分发给每一个客户端**（覆盖客户端配置里 `ca_cert_file` 指向的文件），否则客户端全部报 `unable to get local issuer certificate`：

```bash
cat server/certs/ca.crt        # 复制输出内容到客户端
```

客户端 `config\client.json` 的 `server_url` 用 IP 直连时，SAN 里必须有对应 `IP:<服务器IP>` 条目。

## 运行测试（可选，验证部署完整性）

```bash
server/.venv/bin/python -m pytest server/tests -q        # 53 passed（Ubuntu 24.04 实测）
```

## 常见问题

| 现象 | 处理 |
|---|---|
| 浏览器访问 `https://<IP>:8443/` 返回 `{"detail":"Not Found"}` | **正常**——这是纯 API 服务，没有网页。`/` 未定义路由即 404；能收到这个 JSON 恰好证明 TLS 和跨机器访问是通的。健康检查用 `/health` |
| systemd 服务起不来（status=203）或报找不到密钥文件 | `cipherbox-server.service` 内三处路径默认写死 `/opt/cipherbox`，与实际部署位置不一致——按 systemd 小节第 0 步 sed 替换后 `daemon-reload` 重启 |
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
