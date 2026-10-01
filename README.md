# rjconnect-rs

面向 Windows、macOS、Linux 的锐捷网络认证客户端重写。

## 产品范围

- Windows：有线 Ethernet 认证。
- macOS：有线 Ethernet 认证。
- Linux：有线 Ethernet 与无线 PEAP/MSCHAPv2。
- Windows/macOS Wi-Fi 使用 Web Portal，不由本客户端认证。
- 认证协议由 Rust 核心实现；操作系统只负责设备驱动、密钥落地和网络参数配置。
- DHCP、IP、路由与 DNS 由系统网络栈拥有。
- 不迁移旧 `updateproduct` 和旧自更新链路。
- 不保留旧 C++ 类结构或旧配置格式兼容层。
- 本仓库只提供底层 library crates，不提供 CLI、TUI 或 GUI。

## 当前 workspace

| crate | 所有权 |
| --- | --- |
| `rjconnect-eapol` | Ethernet、EAPOL、EAP 的严格编解码 |
| `rjconnect-ruijie` | 锐捷私有 TLV 的有界编解码 |
| `rjconnect-auth` | 纯认证状态机与 EAP-MD5 challenge-response |
| `rjconnect-platform-api` | 平台设备与系统网络能力契约 |
| `rjconnect-platform-macos` | macOS BPF/libpcap Ethernet backend |
| `rjconnect-wired` | 有线 Ethernet/EAPOL 帧边界与锐捷 trailer |

平台实现、Linux 无线、PEAP/TLS/MSCHAPv2 与应用入口将在这些稳定边界上直接实现，不建立薄转发层。

## 工程门槛

```sh
cargo fmt --all -- --check
cargo check --workspace --all-targets --all-features --locked
cargo test --workspace --all-targets --all-features --locked
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo audit
cargo machete
```

## 文档

- [变更记录](CHANGELOG.md)
- [架构与所有权](docs/architecture.md)
- [依赖准入与当前评估](docs/dependencies.md)
- [ADR-0001：平台 crate 与 native 边界](docs/adr/0001-platform-crate-boundary.md)
- [ADR-0002：底层库 workspace](docs/adr/0002-library-only-scope.md)
- [ADR-0003：接口选择，不做多网卡阻断](docs/adr/0003-interface-selection-not-enforcement.md)
