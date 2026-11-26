# rprobe：Rust 服务器探针 需求与设计 v0.3

版本 v0.3，2026-11-26。含 OpenVZ 适配、分组管理与到期提醒。

## 1. 目标
用一个面板集中查看所有机器的状态（在线、负载、流量、到期），出问题时主动提醒。
适配现有机器：普通 KVM VPS、OpenVZ 6/7 容器（含仅 IPv6、512MB 小鸡）、PaaS 容器（Northflank 0.1 vCPU/256MB、Bot-Hosting、Altare），以及只放行 HTTP(S) 出口的环境。

## 2. 需求
### 2.1 功能
- F1 主机状态：CPU、内存/Swap、磁盘、负载、网卡实时速率和累计流量、TCP/UDP 连接数、进程数、开机时长。
- F2 容器感知：读取 cgroup v1/v2 的 memory.max、cpu.max，按容器配额算百分比，避免 PaaS 上显示宿主机数据。
- F3 在线判定：超过 30 秒（可配）没上报就标记离线。
- F4 主动探测（服务端发起，也可指定由某台 agent 发起）：ICMP/TCP/HTTP(S) 延迟与可用性、TLS 证书到期、WebSocket 握手（检测 VLESS-WS 路径是否通）、关键字匹配。
- F5 资产与分组：每台机器记录厂商、区域、套餐、到期日、续期地址、标签、备注；支持两级分组和批量管理（详见第 13 节）。
- F6 告警：到期前分级提醒（详见第 13 节）、离线、CPU/内存/磁盘超阈值且持续 N 分钟、月流量达到上限的 X%、证书和免费套餐即将到期、探测失败。支持 Telegram、Discord Webhook、邮件（SMTP）、通用 Webhook；带静默时间和去重。
- F7 历史：图表查看 1 小时到 90 天的趋势。
- F8 面板：Web 实时面板（总览卡片 + 单机详情），手机可用；提供只读公开页（可选）。
- F9 API：REST 查询接口，可供 Hark 面板或脚本读取。

### 2.2 非功能
- Agent 常驻内存 < 6 MB，0.1 vCPU 下 CPU 占用 < 1%，静态二进制 < 3 MB（musl）。
- 只要求出站 HTTPS（443），兼容只允许 HTTP/1.1 WebSocket 的入口。
- 支持 OpenVZ 6（2.6.32 内核）和 OpenVZ 7（详见第 12 节）。
- 支持仅 IPv6 主机，IPv4/IPv6 双栈自动选择。
- 断线自动重连（指数退避，最长 60 秒），断线期间在内存中缓存最近 5 分钟数据补发。
- 单台服务端支撑 200 台 agent、每 5 秒一条上报。
- 安全：v1 不提供远程执行命令或远程终端（降低被入侵后全线失守的风险）。

## 3. 架构
```
[agent] --WSS(443)--> [server: axum] --> SQLite
[agent] --HTTPS POST (备用)-->        --> Web 面板 / REST API
                         server --> 主动探测 --> 目标
                         server --> 告警通道（Telegram/Discord/SMTP/Webhook）
```
- 推送模式（默认）：agent 主动连服务端，适合 NAT、PaaS、无公网入口的机器。
- 拉取模式（可选）：agent 暴露 /metrics（带 token），给只能被访问、不能出站的环境用。
- 嵌入模式：PaaS 容器里由现有启动脚本顺带拉起 agent（例如 VLESS 的 Node 脚本里 spawn），不另占服务槽。

## 4. 通信协议
- 传输：WebSocket over TLS（rustls），路径 /ws/agent；失败时降级为 HTTPS POST /api/report。
- 编码：JSON（v1 易调试），预留 version 字段，后续可换 MessagePack。
- 认证：每台 agent 一个 token；服务端只存 argon2 哈希；握手时在 Authorization 头携带。
- 消息：
  - Hello（上线一次）：agent_id、版本、OS、内核、CPU 型号/核数、内存总量、虚拟化类型、cgroup 配额、公网 IP。
  - Report（每 5 秒）：时间戳、cpu%、mem used/limit、swap、disk used/total、load1/5/15、net rx/tx 速率与累计、tcp/udp 数、进程数、uptime。
  - ProbeResult：主动探测结果。
  - 服务端下发 Config：上报间隔、要执行的探测任务。

## 5. 数据存储（SQLite，WAL）
- hosts：id、名称、token_hash、标签、厂商、区域、套餐、到期日、续期地址、备注。
- metrics_raw：保留 24 小时，5 秒粒度。
- metrics_1m：保留 7 天；metrics_1h：保留 90 天（后台任务降采样）。
- traffic_monthly：按账单日统计每月流量。
- probes / probe_results、alerts / alert_events、notifiers。
- 最新状态常驻内存，面板不查库。

## 6. 告警规则（TOML 示例）
```toml
[[rule]]
name = "离线"
kind = "offline"
for = "60s"

[[rule]]
name = "内存高"
kind = "metric"
expr = "mem_pct > 90"
for = "5m"

[[rule]]
name = "免费套餐到期"
kind = "expiry"
before = "48h"
```

## 7. 技术选型
- 公共：tokio、serde/serde_json、tracing、anyhow/thiserror。
- Agent：直接读 /proc、cgroup、user_beancounters（不用 sysinfo，更省内存）；为兼容 OpenVZ 6 不用 tokio，采用阻塞 std + 单线程 + tungstenite 同步版 + ureq（rustls，备用 POST）；release 开 LTO、opt-level="z"、panic=abort，目标 x86_64/aarch64-unknown-linux-musl。
- Server：axum、tokio-tungstenite、sqlx（SQLite）、argon2、teloxide 或直接调 Telegram API、lettre（SMTP）、surge-ping（ICMP）、rust-embed（内嵌前端）。
- 前端：轻量 SPA（Preact 或纯 TS），通过 SSE/WS 接实时数据，uPlot 画图。

## 8. 代码结构
```
rprobe/
  crates/common   协议结构体、版本
  crates/agent    采集、上报、重连、嵌入模式
  crates/server   接入、存储、降采样、探测、告警、API、面板
  web/            前端
  deploy/         systemd、Dockerfile、一键安装脚本
```

## 9. 部署
- 服务端需要一台常在线、有持久磁盘、能对外提供 HTTPS 的机器（免费 PaaS 多数没有持久存储，不适合放服务端）。单二进制 + systemd，或 Docker；前面可接 Caddy 自动证书。
- Agent：`curl | sh` 安装脚本下载对应架构二进制，写入 /etc/rprobe/agent.toml，注册 systemd 服务；容器里用嵌入模式。

## 10. 里程碑
- M1：agent 采集（含 OpenVZ）+ WSS 上报 + 服务端接入 + 实时总览页 + 分组。
- M2：SQLite 历史、降采样、图表、离线/阈值告警（Telegram）。
- M3：主动探测（HTTP/TCP/TLS/WebSocket）、到期设置与分级提醒、每日到期汇总、月流量统计。
- M4：拉取模式、公开只读页、更多告警通道、安装脚本。

## 11. 验收标准
- 在 256MB/0.1 vCPU 容器里 agent RSS < 6 MB、CPU < 1%。
- 拔掉网络 2 分钟后恢复，面板数据连续无缺口（补发生效）。
- 机器离线 60 秒内收到 Telegram 告警。
- WebSocket 探测能识别出 502（如端口协议设错）并告警。
- OpenVZ 6 实机上 agent 正常运行，beancounter failcnt 增长 5 分钟内告警。
- 到期前 7/3/1/0 天各收到一次提醒，点击「已续期」后剩余提醒取消。

## 12. OpenVZ 适配
- 识别：存在 /proc/vz 且不存在 /proc/bc → OpenVZ 容器；读 /proc/version 区分 OVZ6（2.6.32）和 OVZ7（3.10）。Hello 里上报 virt=openvz6/7。
- 内核兼容：Rust 官方最低支持 Linux 3.2，OVZ6 的 2.6.32 不在支持范围。agent 采用 musl 静态编译 + 精简依赖（不用 tokio，改为阻塞 std + 单线程 + ureq/tungstenite 同步版），CI 里加 2.6.32 实机冒烟测试；跑不起来时降级为纯 POST 上报。
- 资源上限：读 /proc/user_beancounters，上报 privvmpages/physpages、kmemsize、numproc、numtcpsock 的 held/limit/failcnt。failcnt 增长单独告警（OpenVZ 上"莫名其妙进程被杀"多半是它）。
- 内存/Swap：用 /proc/meminfo（vSwap 下已是容器视图），超售看 failcnt 而非 free。
- CPU：核数取 /proc/cpuinfo 与 beancounter cpus 中较小者；保留 steal；OVZ6 上 load average 可能反映宿主，标注为参考值。
- 磁盘：simfs/ploop 用 statvfs 取 /；同时上报 inode 使用率（OpenVZ 常先满 inode）。
- 网络：网卡多为 venet0（无 MAC，IP 在 venet0:0）或 veth；统计 venet0/eth*，排除 lo，别名不重复计算。
- 时间：容器不能校时，服务端以接收时间为准，并记录 agent 时钟偏差，超过 60 秒告警。
- 启动方式：老模板没有 systemd（CentOS 6 等），安装脚本自动选择 systemd / SysV init.d / OpenRC，最后兜底 crontab @reboot + 守护循环。

## 13. 分组管理与到期提醒
### 分组
- 每台主机属于一个分组（可嵌套两级，如 免费/PaaS），另可打多个标签。
- 分组可设：排序、颜色、默认告警通道、默认提醒规则、是否在公开页显示。
- 面板按分组折叠展示，显示组内 在线数/总数、即将到期数；批量操作：移组、加标签、静默告警。
- 新 agent 注册时可在 agent.toml 写 group = "xxx" 自动归组；未指定进"未分组"。

### 到期设置
- 字段：expires_at（日期+时区，默认 Asia/Singapore）、计费周期（月/季/年/一次性/免费需手动续期每 N 天）、价格与币种（可选）、续期地址、自动续费（是/否）。
- "已续期"按钮：按周期把到期日顺延一次，并记入续期历史；也可手动改日期。
- 过期后状态变为"已过期"，主机卡片标红；过期 N 天仍离线可一键归档。

### 提醒规则
- 默认提前 7 天、3 天、1 天、当天各提醒一次；可按主机或分组覆盖（如免费机改成 2 天、1 天、12 小时）。
- 每个提醒点只发一次（去重），续期后自动取消剩余提醒。
- 每天 09:00 发一条汇总："7 天内到期 N 台"，按到期先后列出主机、分组、续期地址。
- 走该主机所在分组的告警通道（Telegram/Discord/邮件/Webhook）。

### 数据表
- groups：id、parent_id、name、sort、color、notifier_ids、reminder_offsets、public。
- hosts 增加：group_id、expires_at、billing_cycle、price、currency、renew_url、auto_renew、reminder_offsets（可空，空则继承分组）。
- host_tags、renewals（host_id、旧到期日、新到期日、时间）、reminder_sent（host_id、expires_at、offset）。

### API
- GET/POST/PATCH/DELETE /api/groups
- PATCH /api/hosts/{id}（改分组、到期、周期等）
- POST /api/hosts/{id}/renew（顺延一个周期）
- GET /api/expiring?within=7d
