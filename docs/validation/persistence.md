# SQLite 注册表持久化验证

代码提交：`a38f4350c09706194271daf286cab2dfef1cf60f`。构建及测试使用 [GitHub Actions 45958389504](https://github.com/yous1r/probe-rs/actions/runs/45958389504)，目标 `x86_64-unknown-linux-musl`。没有在 u2-vps 编译。

## 验证内容

- SQLite WAL + synchronous FULL，版本化 schema，主机和初始分组原子写入；成功提交后更新面板缓存。
- 单元测试覆盖正常重启恢复、磁盘写入失败不改缓存、调用方取消不打断 commit/cache 更新、主机/分组事务回滚、数据库独占锁，以及拒绝其他 schema 时文件保持原状。
- GitHub CI 的 `verify_persistence.py` 和 u2-vps 上的同脚本均通过。VPS 专项结果为 11 项通过：真实 server 接口写入后，用 SIGKILL 终止再启动，同库恢复，无需 agent 自动重新注册来掩盖状态丢失。
- 主机信息、最新报告、最后接收时间、分组层级、颜色、排序、手动归属和显式未分组均恢复；重复报告不会刷新重启后在线状态。
- 损坏 SQLite 文件保持原字节，启动失败；`:memory:` 和目录路径启动失败。

## 正式部署检查

正式服务已升级，u2-vps 常驻 agent 已加入。停止 agent 后重启 server，API 仍返回相同 `u2-vps` 主机和最新报告，只将 online 置为 false。恢复 agent 后更新原记录；保持 agent 运行并再次重启 server，自动恢复上报，数据库主机数始终为 1。

数据库 `/var/lib/rprobe/rprobe.sqlite` 通过 `quick_check`，schema=1，WAL 模式。agent 采用独立账号，不能读取 server 密钥和数据库；两服务均 active/enabled，server 仅绑定 `127.0.0.1:8080`。已完成一致性在线备份。

## 产物与边界

| 产物 | 二进制字节数 | 二进制 SHA-256 |
| --- | --- | --- |
| Agent | 2,024,520 | `0f04bc74887ca4b7aae5b63d989b06466e15b1d1834604352561e0cf2dcd30cc` |
| Server | 3,201,856 | `24c5c1b4cc1ae7ec1e206d65b5d6b09bfc8fa8305dda24e92ee9debad68b593d` |

两个 artifact 均核验 GitHub API 摘要、包内校验和及 COMMIT。Agent 保持小于 3 MB；server 增加内置 SQLite 后不依赖系统 SQLite 动态库。

本次验证的是注册信息与最新状态本地持久化，未加入长期历史采样、降采样、历史图表或 agent 磁盘发送队列。未进行整台 VPS 重启和断电测试；进程 SIGKILL 与服务重启已验证，服务开机启用状态已确认。

操作说明、路径及备份位置见 [u2-vps 部署记录](../deployment/u2-vps.md)。
