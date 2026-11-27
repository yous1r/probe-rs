# u2-vps server 和 agent 部署记录

已于 2026-11-27 UTC 完成 SQLite 持久化升级，并将 `u2-vps` 作为常驻 agent 加入。代码提交 `a38f4350c09706194271daf286cab2dfef1cf60f`，产物来自 [GitHub Actions 45958389504](https://github.com/yous1r/probe-rs/actions/runs/45958389504)。构建全部在 GitHub 执行，VPS 只校验并运行产物。

## 服务与文件

| 项目 | 位置/状态 |
| --- | --- |
| Server | `rprobe-server.service`，active / enabled |
| Agent | `rprobe-agent.service`，active / enabled |
| Server 二进制 | `/opt/rprobe/rprobe-server`，3,201,856 字节 |
| Agent 二进制 | `/opt/rprobe/rprobe-agent`，2,024,520 字节 |
| Server 地址 | `http://127.0.0.1:8080`，仅 loopback |
| Agent 身份与周期 | `u2-vps`，每 5 秒上报 |
| SQLite | `/var/lib/rprobe/rprobe.sqlite`，WAL、synchronous FULL、schema v1 |
| Server 接入凭据清单 | `/etc/rprobe/agents.tokens`，原文件和 token 保留 |
| 管理员 token | `/etc/rprobe/admin.token`，原文件和 token 保留 |
| Agent 独立凭据 | `/etc/rprobe-agent/agent.token`，0600，原 u2-vps token 的受限副本 |

新增 agent 后，面板可看到 `u2-vps` 在线。同机 server/agent 经 loopback 通信，不依赖 Cloudflare 绑定是否已完成。现有 Cloudflare Tunnel、DNS、防火墙和其他业务服务均未修改。

## 本地持久化

以下内容在每次成功更新时先提交 SQLite，再发布到面板缓存：主机 Hello 信息、分组（含层级/颜色/排序）、手动分组归属、最新接受的报告、最后接收时间和时钟偏差。服务正常重启或崩溃后保留。面板仍从内存缓存读取，启动时由数据库恢复。

重启后的记录暂时显示离线，直到新的有效报告到达；旧报告重发和 Hello 本身不会把旧数据误标在线。凭据文件继续控制谁可以接入，删除凭据不删除已保存的资产记录。

这次实现的是注册表和最新状态，不是 90 天历史图表。每台主机只保留最新报告；agent 的五分钟待发队列仍在 agent 内存中。

数据库目录由 systemd `StateDirectory=rprobe` 创建，权限 0700，数据库及旁路文件为 0600。独占锁位于 `rprobe.sqlite.lock`，运行时不要删除该文件。数据库损坏、未知 schema 或无写入权限会明确失败，不自动换成空库或内存库。

## 权限与采集范围

- Server 使用专用非 root `rprobe` 账号；`MemoryMax=256M`，`TasksMax=64`，禁止提权、系统文件只读，仅状态目录可写。
- Agent 使用独立非 root `rprobe-agent` 账号；`MemoryMax=64M`，`CPUQuota=10%`，`TasksMax=16`。它能读自己的凭据，不能读取 server 管理员 token、接入清单或 SQLite 文件。
- Agent 配置 `RPROBE_CGROUP_SCOPE=mount`，读取容器挂载根的指标，而不是 agent 服务子 cgroup。实测上报 u2-vps 的 1,572,864,000 字节内存限额和 0.3496 CPU，与 VPS 配额一致。
- Token 不出现在 agent 的进程参数中。系统服务使用 token 文件路径，不输出实际值。

部署 unit 对应 [server 配置](../../deploy/rprobe-server.service) 与 [u2-vps agent 配置](../../deploy/rprobe-agent.service)。若在其他机器使用，需要修改 agent ID、目标地址和凭据路径。

## 验证与备份

- GitHub CI 完成格式、Linux musl Clippy、单元测试、安全回归和持久化崩溃恢复测试，两个独立产物校验通过。
- u2-vps 临时端口的 11 项持久化检查通过：SIGKILL 后恢复、分组层级与手动归属保留、显式未分组保留、最新报告与接收时间保留、重复报告不续在线、损坏库和内存库拒绝。
- 正式部署验收通过：停止 agent → 重启 server → 在 agent 尚未启动时确认主机和最新报告仍在；恢复 agent 后上线；保持 agent 运行再重启 server，验证自动重连且数据库仍只有一条 `u2-vps` 记录。
- 使用 SQLite backup API 生成并检查一致性备份：`/var/backups/rprobe/registry-20261127T113504Z.sqlite`。
- 升级前备份（旧二进制、unit、凭据及空注册表）：`/var/backups/rprobe/pre-sqlite-20261127T113247Z-be3410/`，仅 root 可访问。

升级前备份用于回退程序，不包含升级后新采集的数据。备份正在运行的 WAL 数据库应使用 SQLite backup API；或先停止 server 再一起复制数据库及存在的 `-wal`/`-shm` 文件，不要在线仅复制主文件。

## 管理与 Cloudflare

```sh
sudo systemctl status rprobe-server rprobe-agent
sudo journalctl -u rprobe-agent -f
sudo systemctl restart rprobe-server
sudo systemctl restart rprobe-agent
```

管理员 token 仍在 `/etc/rprobe/admin.token`，由你在 VPS 上通过 `sudo cat /etc/rprobe/admin.token` 查看。无需更换原有面板登录 token。

按此前选择，由用户自行绑定 Cloudflare 域名：在现有远程托管 Tunnel 添加 Public Hostname，Service 类型 `HTTP`，Origin `127.0.0.1:8080`。绑定后浏览器访问 `https://<子域名>/`；不要直接公开 8080。此次只验证本机服务，没有擅自变更域名绑定。
