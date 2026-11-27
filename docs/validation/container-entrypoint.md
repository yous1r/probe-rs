# 容器启动 agent 脚本验证

实现：`deploy/rprobe-entrypoint.sh`。最终脚本提交 `61a735bc05def90617ff3dc4664cae2ae95dde86`；固定 Release 的 agent 构建提交为 `4ac6efbc9985415c40d138bdc4a408b275048ee5`。

## CI

- [首次 Docker 行为验证](https://github.com/yous1r/probe-rs/actions/runs/46011340969)：完整 Linux CI 与 Docker 检查通过。
- [固定版本构建与发布](https://github.com/yous1r/probe-rs/actions/runs/46013219286)：再次通过格式、shell/Python 语法、Clippy、Rust 单元、安全、持久化和 Docker 检查，随后发布 `agent-bootstrap-v0.1.0`。
- [最终兼容性回归](https://github.com/yous1r/probe-rs/actions/runs/46014923058)：补充非 root + Docker `--init` 场景，完整 CI 与 Docker 检查通过。

`verify_container_entrypoint.py` 在 GitHub runner 使用真实 Docker Engine，17 项行为检查全部通过：

1. 人为阻塞后台下载时，前台应用仍在测试限时内启动为 PID 1；参数（空格、分号）不变；SIGTERM 到达主程序，保留退出码 37。
2. 已校验的缓存直接启动，不再调用下载器；重复 `--start-only` 不创建第二个 agent。
3. 错误 SHA-256 不发布安装结果、不执行文件、不影响应用。
4. 下载失败不影响应用。
5. tar.gz 只读取预期二进制成员。
6. ZIP 中的 tar.gz 只读取预期成员；恶意路径不会被解包到文件系统。
7. agent 立即失败不会终止应用。
8. 显式禁用不会下载或阻碍应用。
9. 缺少配置不会下载或阻碍应用。
10. HTTP 下载源被拒绝，应用继续。
11. 原命令退出码 42 原样返回。
12. 非 root 用户在私有可写缓存目录安装和运行。
13. 只读缓存失败与主程序隔离。
14. 从已有入口脚本（包括管道调用）启动两次，主程序正常 exec，仅一份 agent。
15. 安装目标是目录时拒绝安装，主程序继续。
16. 使用 CI 构建的真实 Linux agent，在 Docker 内完成安装、认证 HTTP 回退和真实 procfs/cgroup 指标上报。
17. 非 root 容器启用 Docker `--init`，用 `--start-only` 安装/启动 agent，主程序仍正常启动并保留 SIGTERM 退出码。

测试中有意使用可控下载器和模拟 agent 注入故障；第 16 项使用真实 agent 二进制。容器启动检查不能被解读为所有镜像都已兼容。镜像依赖、权限、tmpfs 和入口接入要求见 [使用说明](../deployment/docker-agent.md)。

## 默认下载源

首次选择的 Actions 下载代理连续返回 HTTP 500，且其 artifact 有保留期限，因此最终默认改为固定 GitHub Release：

<https://github.com/yous1r/probe-rs/releases/download/agent-bootstrap-v0.1.0/rprobe-agent-x86_64-unknown-linux-musl.tar.gz>

通过 GitHub CI 发布完成后，从 u2-vps 发起真实 HTTPS 下载并在内存中检查包内容：

- 归档大小：1,041,845 字节。
- 归档 SHA-256：`323ae2df00962aab24a651779597306ecccb9b720a2c2ca77bb6490875d2576d`，与 GitHub Release API 摘要一致。
- agent 二进制 SHA-256：`0f04bc74887ca4b7aae5b63d989b06466e15b1d1834604352561e0cf2dcd30cc`，与脚本固定值一致。
- 包内 `COMMIT` 为 `4ac6efbc9985415c40d138bdc4a408b275048ee5`，内部 `SHA256SUMS` 全部通过；后续修正仅改入口脚本和测试，不改变 agent 二进制。

本机下载曾超时/返回空响应，但 VPS 下载成功。脚本对这种网络失败会后台重试，不阻止主应用启动。没有向 u2-vps/u3-vps 安装本脚本，也没有改动它们的现有服务。

## 边界

支持有 POSIX shell 和所需基础工具的 Linux 容器；默认发布包仅 amd64。非 root 缓存需要正确归属，token 私有副本要求容器私有 tmpfs；无 shell 的 distroless/scratch 镜像不适用。必须先给每个容器配置独立的 server 授权 ID/token。脚本隔离启动等待与失败，不提供 CPU/内存的独立配额或进程安全沙箱。
