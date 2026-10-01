# 依赖准入与当前评估

评估日期：2026-09-30。下载量来自 crates.io；活跃度来自对应 GitHub 仓库。数值会变化，升级时必须重新核验。

## 准入规则

外部 crate 至少满足：

1. 所有权清楚，优先成熟组织或长期维护者。
2. 有显著真实使用量，或属于不可替代的平台生态边界。
3. 最近仍有发布或提交，不使用 archived/无人维护项目。
4. 许可证与发布目标兼容。
5. 依赖树、unsafe 与 build script 可审计。
6. 只在拥有该能力的 crate 中引入，不泄漏进纯协议核心。
7. `Cargo.lock` 提交，并通过 RustSec 与未使用依赖检查。

## 已准入的首批依赖

| crate | 版本 | 总下载量 | 近期下载量 | 维护来源 | 结论 |
| --- | ---: | ---: | ---: | --- | --- |
| `thiserror` | 2.0.21 | 1,535,534,361 | 385,210,203 | dtolnay，仓库近期活跃 | 准入，用于稳定错误类型 |
| `zeroize` | 1.9.0 | 725,392,027 | 185,808,302 | RustCrypto，仓库近期活跃 | 准入，用于秘密内存清零 |
| `md-5` | 0.11.0 | 373,657,654 | 102,462,632 | RustCrypto，仓库近期活跃 | 准入，仅用于协议要求的 EAP-MD5 |
| `libc` | 0.2.189 | 1,696,483,439 | 378,519,025 | rust-lang，仓库近期活跃 | 准入，仅用于平台 FFI 边界 |
| `pcap` | 2.5.0 | 8,098,647 | 1,323,279 | rust-pcap，2026 年持续维护 | 准入，仅用于对应平台 native Ethernet crate |

MD5 不是一般安全哈希；这里只作为网络协议互操作原语，不能用于密码存储、签名或完整性设计。

## 已评估但尚未引入

| crate | 版本 | 总下载量 | 维护信号 | 当前决定 |
| --- | ---: | ---: | --- | --- |
| `bytes` | 1.12.1 | 1,086,246,249 | tokio-rs，持续维护 | runtime 出现零拷贝需求时再引入 |
| `tokio` | 1.53.1 | 1,012,040,221 | tokio-rs，持续维护 | runtime crate 建立时引入最小 feature 集 |
| `tracing` | 0.1.44 | 885,823,609 | tokio-rs，持续维护 | observability crate 建立时引入 |
| `rustls` | 0.23.45 | 954,011,207 | rustls 组织，持续维护 | PEAP 原型验证 TLS over EAP 与 exporter 后引入稳定版 |
| `wl-nl80211` | 0.7.0 | 187,130 | rust-netlink 组织，近期活跃但使用量低 | 不直接准入；Linux 无线前先源码与能力审计 |

`wl-nl80211` 的同组织底层依赖 `netlink-packet-generic` 与 `genetlink` 分别约 171 万和 94 万下载。若高层 API 无法满足关联、受控端口或密钥安装，优先在隔离的 Linux 平台 crate 中直接使用成熟的 rust-netlink 底层，而不是污染协议核心。

`pcap` 当前只在 macOS target dependency 中启用。Windows 后续接入前仍须验证 Npcap SDK 链接、驱动分发许可和 CI 镜像；Linux 是否采用 libpcap 或 AF_PACKET 由 Linux 平台 crate 独立决定。
