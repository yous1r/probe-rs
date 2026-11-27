# u3-vps agent 部署记录

本次由本机持有 SSH 认证，通过 **本机 → u2-vps ProxyJump → u3-vps** 完成安装。没有把 SSH 私钥复制到跳板机，没有在 u2-vps/u3-vps 编译。

## 运行配置

| 项目 | 值 |
| --- | --- |
| 目标主机 | u3-vps，Debian 12 / x86_64 / Linux 6.8 |
| Agent 身份 | `u3-vps` |
| 服务 | `rprobe-agent.service`，active / enabled |
| 运行账号 | 独立非 root `rprobe-agent`，nologin |
| 二进制 | `/opt/rprobe/rprobe-agent` |
| 凭据 | `/etc/rprobe-agent/agent.token`，0600，仅 agent 账号可读 |
| Server | `https://rprobe.721721.xyz`，Cloudflare Tunnel 转发到 u2-vps |
| 传输 | WSS，必要时回退同一入口的 HTTPS POST |
| 周期 | 5 秒 |
| 采集范围 | `RPROBE_CGROUP_SCOPE=mount`，监控 VPS 容器整体资源 |
| 资源限制 | MemoryMax=64M、CPUQuota=10%、TasksMax=16 |

unit 文件见 [rprobe-agent-u3.service](../../deploy/rprobe-agent-u3.service)。Agent 仅主动出站，无需开放入站端口。使用正常 TLS 证书/主机名校验；此次未改变 Cloudflare DNS、Tunnel 或主机 SSH 配置。

## 构建来源与身份隔离

- GitHub CI：[45958389504](https://github.com/yous1r/probe-rs/actions/runs/45958389504)。代码提交 `a38f4350c09706194271daf286cab2dfef1cf60f`。
- 使用独立 agent 包，安装前核验 artifact 摘要、包内 `SHA256SUMS`、COMMIT 及 ELF 二进制哈希。
- 二进制 2,024,520 字节，SHA-256：`0f04bc74887ca4b7aae5b63d989b06466e15b1d1834604352561e0cf2dcd30cc`。
- u2-vps 的 `/etc/rprobe/agents.tokens` 追加 `u3-vps` 的独立随机 token，保留原 `u2-vps` token 和管理员凭据。原 token 未复制给新 agent。
- 凭据与安装包通过本机 SSH 的标准输入加密传送，token 未进入命令参数、回复或部署日志；u3-vps 不持有管理员 token。
- u2-vps 追加凭据前备份位置：`/var/backups/rprobe/before-u3-20261127T132427Z-2a7471/`，包含原接入清单与 SQLite backup API 生成的一致性备份，仅 root 可访问。
- 加入两台主机后的 SQLite 一致性备份：`/var/backups/rprobe/after-u3-20261127T133123Z.sqlite`，0600。

## 已完成验证

- 从 u3-vps 访问 HTTPS 首页返回 200；匿名 `/api/overview` 返回 401。
- 安装完成后 agent 为 active / enabled；凭据权限为 0600，token 不在进程参数中。
- u2-vps server 同时显示 `u2-vps`、`u3-vps` 在线，最新报告持续更新。
- SQLite `/var/lib/rprobe/rprobe.sqlite` 中有两个主机记录且均保存最新报告，`quick_check` 通过。
- 使用 u3-vps 身份向公网 WSS 发起第二条连接，返回 409，确认第一条 agent WebSocket 会话已占用且重复连接限制生效。
- 上报 VPS 内存限额 1,572,864,000 字节、CPU 限额 0.3496 核，与 u3-vps cgroup 根限额一致。
- 已实际重启 u3-vps agent，确认 PID 变化后服务恢复为 active/enabled；server 收到重启后的新报告，SQLite 中仍为两条独立主机记录。
- 验证了 token 未出现在进程参数或 journal 中，agent 未开放入站监听；出站连接为 IPv6 到 Cloudflare 443。重启后单次 RSS 采样为 1,916 KiB（约 1.87 MiB），不作为长期性能保证。

## 管理

```sh
# 本机经跳板管理 u3-vps；其登录会话可能需要等待一两分钟。
ssh -J u2-vps u3-vps
sudo systemctl status rprobe-agent
sudo journalctl -u rprobe-agent -f
sudo systemctl restart rprobe-agent
```

常驻 agent 的上报不依赖本机 SSH 连接或跳板登录会话；部署完成后它直接出站访问配置的 HTTPS 域名。SSH 连接复用在本机 Git Bash 环境存在 fd 传递问题，部署使用普通 ProxyJump 会话，未修改用户全局 SSH 配置。
