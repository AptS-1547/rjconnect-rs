# Changelog

本项目所有重要变更记录在此。格式遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，版本遵循语义化版本。

## [Unreleased]

### Added

- **协议基础** — 提供有界的 Ethernet、双层 VLAN、EAPOL 和 EAP 编解码，保留未知协议值并严格区分声明负载与 Ethernet trailing 数据。
- **认证核心** — 提供无 I/O 的类型化认证状态机，支持 Identity、EAP-MD5、锐捷私有请求、NAK、超时、退避重试、Logoff 和匹配 EAP identifier 的 Success/Failure。
- **锐捷私有协议** — 分离无线 compact 属性、有线 RADIUS Vendor-Specific Attribute 与固定 70 字节 wired preamble，验证 Ruijie enterprise magic、嵌套长度和 1,400 字节边界。
- **有线帧边界** — 提供完整 Ethernet/EAPOL/EAP 帧组合与解析，显式支持经过验证的锐捷 vendor trailer，并限制普通 Ethernet payload 不超过 1,500 字节。
- **平台能力契约** — 定义不泄漏 OS 句柄的网卡、原始帧和系统网络参数接口，为 Windows、macOS 与 Linux 独立平台 crate 建立稳定边界。
- **macOS Ethernet backend** — 使用 libpcap/BPF 枚举网卡、读取 AF_LINK MAC、过滤 EAPOL、执行有界超时接收和完整帧发送；无 MAC 的 tunnel 接口保持可枚举而不会被错误解引用。
- **Library-only workspace** — 当前仓库只交付可嵌入底层 crate，不提供 CLI、TUI、GUI、自更新程序或产品交互层。
- **接口选择模型** — 平台层枚举全部接口，会话只绑定调用者选择的接口；多个网口、Wi-Fi、bridge、Tailscale、WireGuard 或 TUN 同时存在不会触发认证阻断。
- **工程治理** — 建立集中 lint、三平台 CI、依赖准入记录、RustSec 审计、未使用依赖检查以及平台/native 与 library-only ADR。

### Security

- **秘密与设备边界** — 凭据离开作用域时清零，`Debug` 始终隐藏密码和 MD5 challenge；协议解析拒绝截断、伪造长度、超限嵌套与不匹配认证结果；无 MAC 的 Tailscale/WireGuard/TUN 接口保持可枚举但不会进入 wired EAPOL，避免旧客户端的空指针崩溃。
- **认证 effect 脱敏与清零** — `AuthEffect` 的 `Debug` 不再输出 EAP 包内容，出站 EAP 包使用 `Zeroizing`，锐捷 private PAP 响应不会通过常规日志或析构路径留下明文密码。

### Fixed

- **认证状态封闭** — 认证成功后不再接受新的 EAP-Request，避免 `Authenticated` 隐式回退到 `Authenticating`。
- **有线控制帧长度** — EAPOL-Start 和 EAPOL-Logoff 显式补齐到 60 字节以太网最小帧长；平台发送边界也改为拒绝小于 60 字节的 runt frame，不再依赖驱动自动补齐。
- **EAP 编码不变量** — 拒绝未知 EAP code 携带 method 字节，拒绝 EAP-MD5 challenge 的多余字节，并拒绝 `encode_eap` 输入中的 EAP trailing 字节。
- **macOS 接口选择** — `MacosEthernet::open` 只允许 `InterfaceKind::Ethernet`，不会误开 Wi-Fi、Tunnel 或 Loopback。
