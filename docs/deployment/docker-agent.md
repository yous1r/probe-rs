# Docker 容器启动时自动部署 agent

入口脚本：[deploy/rprobe-entrypoint.sh](../../deploy/rprobe-entrypoint.sh)。它在后台检测、下载、校验和启动 agent，前台立即 `exec` 原命令。下载慢、下载失败、缺少工具、token 错误或 agent 退出，都不会成为应用启动的前置条件。

已安装的判断标准是：`RPROBE_AGENT_DIR/rprobe-agent` 是可执行的普通文件，且 SHA-256 与配置值一致。符合则直接复用；不符合则下载到临时目录，校验通过后原子替换。文件锁保证同一缓存目录最多有一个脚本管理的 agent；安装失败或 agent 退出后每 60 秒重试。脚本不会调用 systemd、sudo、apt/apk，也不会编译。

## 配置

| 环境变量 | 用途/默认值 |
| --- | --- |
| `RPROBE_SERVER` | 必填，server HTTPS 地址，例如 `https://rprobe.721721.xyz` |
| `RPROBE_AGENT_ID` | 必填，server 已授权的独立 agent ID |
| `RPROBE_TOKEN_FILE` | 必填，容器内只读挂载的该 agent token 文件 |
| `RPROBE_ENABLED` | `0` 禁用 agent，默认启用 |
| `RPROBE_AGENT_DIR` | 可写的私有安装/缓存目录，默认 `/tmp/rprobe-agent-<UID>` |
| `RPROBE_INTERVAL` | 上报间隔，默认 5 秒，agent 接受 1–60 秒 |
| `RPROBE_GROUP` | 可选，首次注册分组 |
| `RPROBE_CGROUP_SCOPE` | 默认 `process`，按容器/进程所在 cgroup 采集 |
| `RPROBE_AGENT_URL` | 可选，固定版本的 HTTPS 下载地址，必须与下项一起设置 |
| `RPROBE_AGENT_SHA256` | 上项下载包中 **agent 二进制** 的 SHA-256，64 位小写 hex，不是压缩包校验和 |
| `RPROBE_AGENT_FORMAT` | `zip`（默认，Actions artifact）、`tar.gz` 或 `binary` |
| `RPROBE_RUNTIME_DIR` | token 私有副本的 tmpfs 根目录，默认 `/dev/shm` |

每个容器实例需要独立 ID/token，并先在 server 的接入清单中配置。脚本不会以管理员身份注册新凭据；共享同一 ID 的多副本会触发 server 的单连接限制。

默认 amd64 来源固定在 GitHub CI run `45958389504`，提交 `a38f4350c09706194271daf286cab2dfef1cf60f`，二进制 SHA-256 固定为 `0f04bc74887ca4b7aae5b63d989b06466e15b1d1834604352561e0cf2dcd30cc`。**Actions artifact 只保留 14 天**；有效缓存不受影响，但过期后无法首次下载。长期运行请将已校验的独立包放到自己的稳定 HTTPS 下载地址，并配置 URL、二进制 SHA-256、格式，或在镜像构建时预置相同哈希的 agent。脚本不追踪可变的 latest。

目前仓库仅发布 x86_64 musl 产物。arm64 需要提供匹配架构的 URL 和哈希；未提供时跳过 agent。其他架构同样跳过，主程序继续。

## 方式一：包装原 ENTRYPOINT

下面以已有 Nginx 镜像为例，保留其原 `/docker-entrypoint.sh` 和 CMD。依赖在镜像构建阶段安装，不放进容器启动路径：

```dockerfile
FROM nginx:stable-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl unzip util-linux coreutils tar \
    && rm -rf /var/lib/apt/lists/*
COPY deploy/rprobe-entrypoint.sh /usr/local/bin/rprobe-entrypoint.sh
RUN chmod 755 /usr/local/bin/rprobe-entrypoint.sh
ENTRYPOINT ["/bin/sh", "/usr/local/bin/rprobe-entrypoint.sh", "/docker-entrypoint.sh"]
CMD ["nginx", "-g", "daemon off;"]
```

将 `./container-a.token` 准备为 server 为 `container-a` 配置的 token，然后运行：

```sh
docker run -d --name my-app --init \
  -e RPROBE_SERVER=https://rprobe.721721.xyz \
  -e RPROBE_AGENT_ID=container-a \
  -e RPROBE_TOKEN_FILE=/run/secrets/rprobe-agent \
  -e RPROBE_AGENT_DIR=/var/cache/rprobe/agent \
  --mount type=bind,src="$(pwd)/container-a.token",dst=/run/secrets/rprobe-agent,readonly \
  --mount type=volume,src=container-a-rprobe-cache,dst=/var/cache/rprobe \
  my-app-with-rprobe
```

镜像名 `my-app-with-rprobe` 是你构建后的应用镜像。缓存子目录由脚本以 0700 创建；使用非 root 镜像时，提前在构建阶段为应用 UID 创建/授权缓存目录，或使用默认 `/tmp` 目录。不同容器不要共用同一个安装目录或缓存卷，以免文件锁把它们当作同一个 agent。

Docker 内仍应让主程序前台运行，例如 `nginx -g 'daemon off;'`，不要 fork 到后台后让 PID 1 退出。`--init` 建议用于回收后台子进程；脚本仍通过 `exec` 交给原 ENTRYPOINT，保留它原有的参数、信号转发和退出码。

## 方式二：现有启动脚本中加一行

```sh
#!/bin/sh
# 已有的应用初始化逻辑……
/bin/sh /usr/local/bin/rprobe-entrypoint.sh --start-only
exec /path/to/original-daemon --foreground
```

不需要再给 `--start-only` 加 `&`，它自己派生后台任务并立即返回；不要用 `source`/`.` 执行此脚本。此模式跟随容器 PID 1，入口脚本仍应最终 `exec` 主程序；不要在宿主机上使用 `--start-only`。若应用入口会切换 UID，先切换到最终运行用户，再调用本脚本，避免 agent 以不必要的 root 权限运行。

## 安全与失败行为

- token 不接受环境变量明文或命令行明文；源文件只读挂载。Docker secret 常为 0444，脚本只读取并复制到 tmpfs 下的私有 0700 目录，副本 0600，不修改源文件权限。
- `/dev/shm` 必须是容器私有、可写的 tmpfs，不使用 host/shared IPC。若另配 `RPROBE_RUNTIME_DIR`，同样必须是容器私有 tmpfs；普通磁盘路径会被拒绝。容器停止时 tmpfs 被回收，避免 PID 1 退出导致清理 trap 来不及执行而遗留凭据。
- TLS 下载必须验证证书；重定向只能走 HTTPS。下载有连接/总超时和大小限制，运行前核对预先固定的二进制 SHA-256。ZIP/TAR 只读取指定成员到 stdout，不解包任意路径。
- 安装目录必须归当前运行用户所有、模式 0700；拒绝符号链接或目录形式的二进制目标。缓存和源 token 文件应由可信部署配置提供。
- 主程序的文件权限、umask、退出码不会被后台工作修改；agent 不会读取主程序 stdin。后台日志发往容器 PID 1 的 stderr；无权限访问该日志句柄时静默丢弃，避免占住调用方管道。
- 缺少配置、依赖、架构或无法写目录时跳过 agent；下载/校验失败和 agent 退出后后台限频重试，不结束主应用。
- 镜像需有 POSIX `/bin/sh`、`flock`、GNU/BusyBox 兼容 `stat`、`sha256sum`、`mktemp` 等基础工具；下载安装另需 `curl`、CA 证书，打包格式需要 `tar`/`unzip`。Debian 示例安装所需工具；Alpine 可在构建时安装 `ca-certificates curl unzip util-linux coreutils tar`。没有 shell 的 scratch/distroless 镜像不能直接使用本脚本。
- “不影响启动”指没有网络/安装等待作为启动依赖、不改变前台执行与退出语义；agent 和主应用仍共享容器资源。同 UID 的主程序也能读 agent 凭据，脚本不构成进程安全沙箱。用容器资源限制控制整体占用。

## 检查

```sh
# 日志
 docker logs my-app
# 本地或 CI 的 Docker 回归：agent-binary 必须是已构建的 Linux agent
python3 scripts/verify_container_entrypoint.py \
  --agent-binary target/x86_64-unknown-linux-musl/release/rprobe-agent \
  --output-dir /tmp/rprobe-entrypoint-check
```

测试用可控的下载器/agent fixture 注入慢下载和故障，再用 CI 构建的真实 agent 在 Docker 内验证采集上报。测试不修改任何现有 VPS 服务。
