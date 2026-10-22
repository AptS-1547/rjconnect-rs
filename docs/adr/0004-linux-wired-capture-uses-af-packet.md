# ADR-0004：Linux wired capture 使用 AF_PACKET

状态：Accepted
日期：2026-10-22

## 背景

Linux wired platform adapter 需要读取和发送 EAPOL Ethernet 帧。libpcap 能复用 macOS 的代码形状，但会为 Linux crate 引入额外的系统库与构建依赖，并弱化 Linux 原生权限、socket 生命周期和接口分类的边界。

## 决策

`rjconnect-platform-linux` 使用由 target-specific `libc` 绑定的 AF_PACKET raw socket 实现首版 wired Ethernet adapter。公共 `InterfaceId` 使用接口名；ifindex 仅在 native 实现内部用于绑定设备。首版只允许实体 Ethernet，不包含 Wi-Fi、nl80211 或系统网络配置。

## 不采用的方案

### 复用 libpcap

不采用。虽然首版代码更接近 macOS，但会引入 Linux 开发库依赖，并继续依赖 pcap 对接口类型、权限和生命周期的抽象。

### 通过单一 pcap wrapper 同时支持 macOS 与 Linux

不采用。ADR-0001 已拒绝以统一 wrapper 抹平各平台 native 差异。

## 后果

- unsafe socket、filter、timeout 和 fd 生命周期集中在 Linux `native` 子模块。
- 默认 CI 验证可移植 contract 与接口枚举；真实 `CAP_NET_RAW` 和 EAPOL 收发由 Linux 实机验收。
- Linux wired adapter 的运行权限要求是 raw packet socket 权限，而不是 libpcap 或其开发包。
