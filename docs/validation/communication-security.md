# 通信安全加固验证

验证日期：2026-11-27（GitHub CI 日志 UTC）。实测代码提交：`42e133bf5b26dcff21fc605388dcbd8534d4ebe2`。

## 构建与产物

- [GitHub CI 45942056384](https://github.com/yous1r/probe-rs/actions/runs/45942056384)：格式、Linux musl Clippy、**22 个 Rust 测试**、release 构建、六组二进制安全回归均通过。
- 构建在 GitHub 托管 runner；u2-vps 没有执行 Rust 编译。
- Agent/server 保持独立 artifact；分别校验 GitHub artifact SHA-256、包内 `SHA256SUMS` 和 `COMMIT`。
- Agent 二进制 2,024,520 字节；server 1,764,168 字节，均为 static PIE。
- Agent artifact SHA-256：`636972a21a1cb090d716bdd342a95277ed943657d95068c6820586a46e26c7e2`。
- Server artifact SHA-256：`42b8d46976c0e63d7ded15e8bd83c5d7a252e5c03a8540fcf9a6a879c3e9d5f7`。

最初的加固提交因 HTTP 错误类型体积触发 Clippy 失败，已改成只向上层返回状态码；上述通过记录对应修复后的提交，没有跳过失败的检查。

## u2-vps 运行结果

环境为 Debian 12 / x86_64 / Linux 6.8 / cgroup v1，使用随机 loopback 端口和临时凭据文件。

`scripts/verify_security.py` 六组通过、退出码 0：

1. 面板 API 与 SSE 拒绝匿名和 agent token；跨 agent 使用 token 被拒绝；未认证 JSON 不进入解析；超大请求返回 413。
2. 正常 Hello/Report 可接收；重复报告不更新 `last_seen_at`，不会延长在线状态；过旧、过于超前的时间戳及超长主机名被拒绝。
3. WS 拒绝浏览器 Origin、第二条同身份连接、超过 16 KiB 的帧和超出消息预算的持续控制帧；连接关闭后名额可重新使用。
4. 带管理员身份可订阅 SSE，超过 16 条连接返回 429。
5. Agent 拒绝 0644 token 文件和带 userinfo 的 HTTP URL 绕过；错误输出不包含临时 token。
6. 使用临时自签名证书的 TLS 入口，观察到握手拒绝，未接收到应用层认证请求。

`scripts/verify_linux.py` **24 项通过、0 失败**：真实采集、分组、在线/离线、HTTP 回退仍正常；中断监听 120 秒后补发 **118 条**断线期间采集的报告，最大采集时间戳间隔 **2 秒**。该测试不代表有应用层 ACK 或持久历史保证。

`scripts/verify_limits.py` 在 256 MiB / 0.1 CPU 临时 systemd 配额下，以 5 秒上报间隔采样 30 秒，退出码 0：

| 指标 | 实测 |
| --- | --- |
| 上报配额 | 268,435,456 字节 / 0.1 CPU，与设置一致 |
| 峰值 RSS | 1,532 KiB，约 1.50 MiB |
| 单核 CPU 占用 | 约 0.33% |
| 占 0.1 CPU 配额比例 | 约 3.33% |

CPU 两种口径不能混用；该结果不满足“占 0.1 核配额不到 1%”的更严格解释。短采样不代表长期资源保证。

另直接检查运行中 agent 的 `/proc/<pid>/cmdline`，确认 token 内容未出现在参数列表。

## 面板验证

- Node 下 12 项行为检查通过：事件分片、更新合并、旧请求隔离、401 清空、429 退避、空 201/204 响应、文本渲染及事件大小边界。
- 通过 SSH 转发连接实际 u2-vps server，以隔离的无界面 Chrome 配置联调：匿名 SSE 401；登录后主机显示且实时刷新；正常更新保持单条 SSE；成功后清空 token 输入框，不持久化 token；新建分组的空 201 响应正确处理；切换错误 token 后清空主机并停止重试。
- 内置浏览器页面容器不可用，真实联调使用本机 Chrome，无需在验证主机构建或对公网开放测试端口。

## 清理与边界

测试进程、临时 systemd unit、远端测试目录和凭据文件、SSH 转发均已清理。原始 JSON 与浏览器联调结果仅保留于本次会话 scratch；没有把实际密钥写进仓库。

这些检查证明所列防护在本次条件下生效，不构成绝对安全保证。生产域名的 TLS 反代、互联网 DDoS、仅 IPv6、OVZ6、完整跨重启防重放和应用层 ACK 尚未验收。持有有效 token 的被入侵 agent 仍可伪造自己的指标；吊销需修改配置并重启 server。

配置和具体限额见 [通信与安全说明](../communication-security.md)。
