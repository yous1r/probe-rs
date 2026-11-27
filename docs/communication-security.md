# Agent 与 server 的通信和安全边界

Agent 主动连接配置的 server；不需要对 agent 开放入站端口。生产拓扑：

```text
agent -- WSS/HTTPS :443 --> TLS 反向代理 -- loopback HTTP --> rprobe-server
```

- 首选 `wss://域名/ws/agent`，发送 Hello 后按本地间隔上报 JSON。
- WS 失败时通过同一 HTTPS 地址的 `POST /api/report` 回退，认证要求相同。仅 loopback 调试允许明文 HTTP。
- 断线指数退避，最高 60 秒，内存保留最近五分钟报告。HTTP 成功才移除相应报告；WS 尚无应用层 ACK，写入成功不等于对端已处理，不能承诺零丢点。
- Agent 只理解有限的 Config 消息和 WS 控制帧，当前本地 `--interval` 优先。没有远程命令、终端、文件读写、代理转发或任意探测任务入口。

## 配置凭据

每台 agent 使用不同的随机 token，管理员 token 单独生成。建议 `openssl rand -hex 32` 生成 32 字节随机值。最少 16、最多 256 个可见 ASCII 字符是格式检查，不代表程序能判断随机性。

Agent 文件只包含自己的 token，服务账号可读、其他用户不可读：

```sh
chmod 600 /etc/rprobe/agent.token
./rprobe-agent --server https://monitor.example.com --id node-a \
  --token-file /etc/rprobe/agent.token
```

`--token` 已禁用，迁移旧启动命令时必须改为 `--token-file`。文件通过同一个打开句柄检查类型、权限与大小，Unix 拒绝组或其他用户可访问的凭据文件。权限不能防止 root 或同 UID 进程读取，因此运行在专用非 root 服务账号下。

Server 支持：

```sh
RPROBE_AGENT_TOKENS_FILE=/etc/rprobe/agents.tokens \
RPROBE_ADMIN_TOKEN_FILE=/etc/rprobe/admin.token \
RPROBE_LISTEN=127.0.0.1:8080 ./rprobe-server
```

两个文件均应为 0600 或更严格。`agents.tokens` 每行 `agent-id=对应随机token`；`admin.token` 只包含管理员 token。旧环境变量 `RPROBE_AGENT_TOKENS` / `RPROBE_ADMIN_TOKEN` 仍兼容，但同一项不能同时设置明文值和 `_FILE`。服务端将 agent token 转成随机盐 Argon2 哈希保存到运行状态；配置文件本身仍是需要保护的明文凭据，不是哈希数据库。

只配置允许接入的 ID，拒绝重复 ID、重复 token 或 agent/admin 共用 token。Agent token 只能写自己的状态，不能读取面板、操作其他机器或管理分组。首次 Hello 可指定初始分组；重连保留管理员分组，包括未分组。

目前轮换/吊销方式为修改配置、重启 server，并更新对应 agent 文件后重启 agent；重启会关闭旧连接。没有动态吊销 API。最新状态和去重记录是内存态，重启会清空。

## TLS 与入口

使用具有有效证书的域名，代理转发到 server 的 loopback 地址。Caddy 的最小配置示例：

```caddyfile
monitor.example.com {
    reverse_proxy 127.0.0.1:8080
}
```

这是配置示例，未自动部署或修改防火墙。公网仅暴露代理入口；保护 8080 不被外网直连。在代理/CDN/防火墙层配置连接和请求速率限制、读头/读体超时，防范 TCP 慢连接和大流量攻击；应用限流无法替代入口带宽防护。不要记录 Authorization、查询参数里的密钥或上报正文。

Agent 使用 rustls 的正常证书链/主机名验证，无跳过验证选项。拒绝 URL 中的用户名、密码、查询和 fragment；HTTP 与 WS 都不跟随重定向，避免凭据或指标发送到跳转目标。HTTP 请求有整体超时；WS 的 TCP 连接及读写有超时，但系统 DNS 解析、TLS/HTTP 握手被持续少量数据拖慢等情况尚非严格端到端时限。

## 应用层限制

| 边界 | 当前限制 |
| --- | --- |
| HTTP 请求体、WS 单帧和整条消息 | 16 KiB |
| 同时处理 HTTP 请求 | 64 |
| 全局 HTTP 速率 | 500 次/秒，突发 1000 |
| 同时运行 Argon2 验证 | 2，使用阻塞工作线程，不阻塞 Tokio I/O |
| 每个已配置 agent 的认证请求 | 2 次/秒，突发 20，HTTP/WS 共用 |
| 每个 agent 的 WS 连接 | 1，重复返回 409 |
| 每个 agent 的 Hello | 0.1 次/秒，突发 10 |
| 每个 agent 的消息/控制帧预算 | 4 次/秒，突发 640，支持五分钟补发 |
| WS 首条 Hello / 后续有效数据等待 | 10 秒 / 90 秒 |
| 管理员 SSE 连接 | 16，事件最多每秒一次 |
| 配置 agent / 分组总数 | 1000 / 500 |

预算对象只为配置的 agent 创建，伪造任意 ID 不会无限增加限流表。未经认证的请求在解析 JSON 前拒绝，认证字段重复也会拒绝。Agent 入口拒绝带浏览器 Origin 的请求，不允许网页建立 agent 连接。所有面板 API（包含 SSE）需要管理员 Bearer token；面板 token 只在当前页面内存中，不写入 URL 或浏览器存储。

报告字段有字符串、集合和数字范围检查。接收时间为在线时间依据；允许采集时间落在服务端接收时间前 360 秒至后 60 秒内，容纳五分钟补发和有限时钟偏差。重复或早于最新报告的记录被幂等忽略，不刷新在线状态。时钟偏差超出窗口会拒绝报告，应先检查主机时钟。

上述时间检查并不是带持久 nonce 的密码学防重放协议。持有有效 token 的被入侵 agent 能在自己身份范围内提交虚假指标、占用自己的预算；server 重启后内存去重状态不保留。TLS、独立 token、权限隔离和及时吊销共同减少影响，不能保证任何攻击下都不可滥用。

## 验证

GitHub CI 执行 Rust 单元测试以及 `scripts/verify_security.py`，后者用已有二进制在随机 loopback 端口验证身份隔离、请求大小、WS 连接/速率限制、SSE 鉴权/连接上限、重复报告在线状态、凭据文件权限、URL 绕过和不受信 TLS 证书拒绝。它不安装软件、不构建，并清理自己的进程和临时密钥。

```sh
python3 scripts/verify_security.py --bin-dir /path/to/binaries --output-dir /tmp/security-results
```

生产 TLS 代理配置、互联网 DDoS、仅 IPv6 和完整跨重启防重放需要另行验证；不能用 loopback 测试宣称这些场景已验收。
