# 架构与所有权

## 不变量

1. 协议核心不依赖操作系统类型、句柄或条件编译。
2. 平台层只传输字节、控制设备并观察系统网络状态，不决定认证流程。
3. 状态机接收类型化事件并产出 effect，不直接执行 I/O。
4. 所有长度、编码和字节序在边界处验证。
5. 凭据不实现 `Display`，离开作用域时清零。
6. 未知协议值保留原始数值，保证前向可诊断性。
7. 不用旧类名建立一对一兼容 facade。

## 依赖方向

```text
上层消费者与可嵌入 runtime
  ├─ rjconnect-auth
  │    ├─ rjconnect-eapol
  │    └─ rjconnect-ruijie
  ├─ rjconnect-wired
  │    ├─ rjconnect-eapol
  │    └─ rjconnect-ruijie
  └─ rjconnect-platform-api
        ├─ Windows Ethernet 实现
        ├─ macOS Ethernet 实现
        └─ Linux Ethernet/Wi-Fi 实现
```

`rjconnect-auth` 不能依赖任何平台实现。平台 crate 也不能重写认证状态，只执行核心产生的 effect。

`rjconnect-wired` 拥有原始 Ethernet 帧与 EAPOL/EAP 之间的边界、MTU 约束和锐捷 VSA trailer；它不打开设备，也不驱动状态机。

平台 `FrameChannel` 是有界阻塞接口：每次 receive 要么返回 owned frame，要么在配置的短 timeout 后返回正常超时。未来 runtime 使用专用 worker 驱动该接口并在 timeout 边界处理取消，避免把某一种 async runtime 写进公共平台契约。

## 后续最终模块

```text
crates/
  rjconnect-peap/           PEAP 分片与 TLS 会话
  rjconnect-mschapv2/       MSCHAPv2
  rjconnect-wifi-security/  WPA 四次握手和密钥派生
  rjconnect-runtime/        会话 actor 与取消
  rjconnect-config/         新配置模型
  rjconnect-observability/  脱敏 tracing
  rjconnect-platform-windows/ Npcap、Windows 接口与网络状态
  rjconnect-platform-macos/   BPF/libpcap、macOS 接口与网络状态
  rjconnect-platform-linux/   AF_PACKET、nl80211 与系统网络状态
```

只有出现真实调用方时才新增 crate 和依赖，避免空壳模块与预先设计的薄抽象。

## 平台差异收口

平台实现采用与 AsterForge native cloud-files adapter 相同的边界模式：

- `rjconnect-platform-api` 只定义跨平台值与能力契约。
- 三个平台分别拥有兄弟 crate，不通过一个“万能 pcap wrapper”掩盖 native 生命周期差异。
- 各平台 crate 中可移植的配置、快照和错误分类在所有开发主机编译和测试。
- 真实系统调用位于 `native` 子模块，由 `cfg(target_os = "...")` 在模块和导出边界收口。
- Npcap、BPF/libpcap、AF_PACKET、nl80211 等依赖只出现在对应 target dependency。
- native 回调只复制有界输入并提交任务，不在回调线程执行认证、DHCP 或其他长任务。

详细决策见 [ADR-0001](adr/0001-platform-crate-boundary.md)。

## 产品接入边界

本 workspace 不提供 CLI、TUI 或 GUI。未来 `rjconnect-runtime` 仍是可嵌入 library，通过类型化事件和 effect 与上层交互，不拥有终端输入、桌面窗口、用户文案或服务安装流程。

详细决策见 [ADR-0002](adr/0002-library-only-scope.md)。

## 接口选择

底层枚举全部接口，但认证会话只绑定调用者明确选择的 `InterfaceId`。多个 Ethernet、Wi-Fi、bridge 或 VPN/TUN 同时存在不会阻断认证，底层也不移植旧客户端的多网卡、多 IP 或代理共享检测。

详细决策见 [ADR-0003](adr/0003-interface-selection-not-enforcement.md)。
