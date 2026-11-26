# u2-vps Linux 验证记录

本次验证时间：2026-11-26（UTC，以 GitHub Actions 和测试脚本记录为准）。所有 Rust 编译、Clippy 和单元测试均在 GitHub 托管 runner 执行；u2-vps 仅接收构建产物并运行验证脚本，没有安装 Rust 或执行构建。

## 产物来源

- 仓库：<https://github.com/yous1r/probe-rs>
- 初次构建：提交 `37230fc8250c1264cc983ac2d21266c45c22ad79`，运行 [45820658737](https://github.com/yous1r/probe-rs/actions/runs/45820658737)。
- 修复后实测：提交 `de9458d54bb8a1c9610b6847db4b98b8763b7672`，运行 [45829541825](https://github.com/yous1r/probe-rs/actions/runs/45829541825)。格式检查、Linux musl Clippy、单元测试、release 构建均成功。
- 工具链：Rust 1.100.0，目标 `x86_64-unknown-linux-musl`。
- Artifact：`rprobe-x86_64-unknown-linux-musl`。下载 ZIP 的 SHA-256 与 GitHub API 的 `digest` 一致：`afe6c17d71bb7ea9cb1fe51979a04c5ed640ceff9f1c9406c3a7d01b61998cd2`。
- 远端再次验证包内 `SHA256SUMS` 与 `COMMIT`。agent/server 均为剥离符号的 static PIE，无动态解释器；agent 大小 **2,028,656 字节**，低于 3 MB。

## 主机与测试条件

u2-vps：Debian 12，x86_64，Linux 6.8.0，存在 `/proc/vz`，磁盘为 ploop。可见 1 个逻辑 CPU，父容器 cgroup v1 配额为 0.3496 核，内存限额为 1,572,864,000 字节。

该主机没有可读的 `/proc/user_beancounters`，也不是 Linux 2.6.32；本次不能据此验收 OVZ6 或 failcnt 告警。所有测试服务仅监听随机 loopback 端口，使用临时随机 token，不接入现有业务服务。

## 实测发现和修复

1. 原缓存固定 60 条。使用 1 秒上报间隔、断开监听 120 秒后，只能保留约一分钟，采集时间序列出现 **67 秒缺口**。修复为按五分钟时间窗口保留，容量支持最短 1 秒间隔的 301 个采样点，并加入回归测试。
2. 原采集器只读 cgroup 挂载根目录。在 systemd 临时设置 256 MiB / 0.1 CPU 后，仍上报父容器的 1.5 GiB / 0.3496 核。修复为结合 `/proc/self/cgroup` 与 `/proc/self/mountinfo` 定位本进程层级，并取父级中更严格的限制；回归测试覆盖 v1 合并控制器、v2 命名空间及父级限制。
3. 调整 `statvfs` 的 Linux 类型使用，确保 Linux musl Clippy 的 `-D warnings` 检查通过。

## 修复后结果

`verify_linux.py` 于 13:35:14–13:37:59 UTC 运行，**24 项通过、0 项失败，退出码 0**：

- 真实 server/agent 启动，未认证上报返回 401。
- Hello/Report 入站，资源字段非零，内存限额与系统数据一致。
- 两级分组可创建，第三层被拒绝；管理员移组后 agent 重连保持分配。
- 测试离线阈值设为 3 秒，停止 agent 后正确离线。
- 拒绝 WebSocket 升级后，真实 agent 通过 HTTP POST 发送 Hello/Report。
- 关闭测试监听 120 秒后自动重连，补发 **115 条断线期间采集的报告**，并继续接收新报告。
- 1 秒采样测试的最大采集时间戳间隔为 **3 秒**，通过脚本的 5 秒容差；这是接收端补发验证，不代表零丢点或历史图表验收。当前没有历史库。
- 常规 5 秒上报周期、30 秒采样：RSS 1,520 KiB；CPU 约为单核的 0.43%。

`verify_limits.py` 另用临时 systemd unit 设置 **256 MiB / 0.1 CPU**，以 5 秒上报周期独立采样 60 秒：

| 指标 | 实测 |
| --- | --- |
| 上报内存限额 | 268,435,456 字节，与 256 MiB 配额一致 |
| 上报 CPU 限额 | 0.1 核，与设置一致 |
| 采样峰值 RSS | 1,516 KiB（约 1.48 MiB） |
| VmHWM | 1,520 KiB |
| CPU 时间增量 | 24 ticks，系统 `CLK_TCK=100` |
| 单核 CPU 占用 | 约 0.40% |
| 占 0.1 核配额的比例 | 约 4.0% |
| 采样期间上报 | 持续推进 |

资源脚本按“单核占用 <1%”判断通过。如果需求中的“CPU <1%”指 **0.1 核配额的 1%**，本次结果尚未达到；两个口径均记录于此，不能混用。短时间采样也不能代表长期稳定性。

## 验证边界

本次覆盖 Linux musl 启动、OpenVZ 环境下 procfs/cgroup v1 采集、WS/HTTP 回退、重连补发与资源采样。未验证生产 WSS/TLS 入口、网络黑洞、仅 IPv6、cgroup v2 实机、OVZ6/2.6.32、200 台并发、长期资源趋势、历史和告警功能。

测试脚本只停止本次启动的进程；临时 systemd unit 使用 `--collect` 回收。复现命令见 [README](../../README.md#github-ci-and-linux-validation)，脚本为 [verify_linux.py](../../scripts/verify_linux.py) 和 [verify_limits.py](../../scripts/verify_limits.py)。

## ServerStatus-Rust 参考

参考了 [zdz/ServerStatus-Rust](https://github.com/zdz/ServerStatus-Rust) 的 `client/src/sys_info.rs`、`client/src/main.rs`、`client/src/grpc.rs`，查询时源码树标识为 `485b2ddaa65da738ed456e09fdb16522e16b5b63`（Apache-2.0）。

该项目使用 sysinfo、独立采样线程与明确的连接/请求超时。rprobe 保留需求指定的直接 procfs/cgroup 采集和同步单线程结构；本次没有复制其源代码，也没有将其测试结果当作本项目的验证结果。其超时策略作为后续网络黑洞与慢响应验证的参考。
