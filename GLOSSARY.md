# rjconnect-rs

锐捷网络认证的可嵌入 Rust library workspace；认证协议与流程独立于操作系统，平台能力由各目标平台的 adapter 提供。

## 平台能力

**Platform adapter**：
某个操作系统上平台能力契约的具体实现。
_Avoid_: universal pcap wrapper

**Linux wired platform adapter**：
Linux 上仅面向有线 Ethernet 的 `EthernetLink` 实现；不提供 Wi-Fi 认证或系统网络配置。
_Avoid_: Linux backend, Linux wired backend

**Wired EAPOL**：
直接承载在实体 Ethernet 接口上的 EAPOL 认证流量。
_Avoid_: 无线认证, Wi-Fi 认证

**Physical Ethernet interface**：
由实体有线网卡提供、可直接承载 wired EAPOL 的接口；不包含 loopback、Wi-Fi、bridge、bond、VLAN、veth 或 tunnel。
_Avoid_: Ethernet interface

**InterfaceId**：
platform adapter 在一次接口枚举快照中暴露给调用者的不透明网络接口标识；Linux adapter 对非 UTF-8 接口名使用可逆转义。
_Avoid_: ifindex, 网卡序号

**Padavan validation environment**：
用于 Linux native 验收和锐捷现场诊断的真实设备，不是当前 workspace 的编译目标或长期 CI target。
_Avoid_: Padavan target
