# ADR-0001：平台 crate 与 native 边界

状态：Accepted  
日期：2026-09-30

## 背景

Windows、macOS、Linux 都需要有线 Ethernet 认证，但设备接口分别依赖 Npcap、BPF/libpcap 与 AF_PACKET。Linux 还需要 nl80211 无线控制。把三平台塞进一个实现 crate 会让依赖、权限、回调生命周期和错误语义互相污染。

## 决策

采用一个平台无关契约 crate 和三个兄弟平台 crate：

```text
rjconnect-platform-api
  ├─ rjconnect-platform-windows
  ├─ rjconnect-platform-macos
  └─ rjconnect-platform-linux
```

每个平台 crate：

1. 拥有自身设备标识映射、配置、错误分类、回调快照和关闭生命周期。
2. 将真实 OS/FFI 调用放进 `native` 子模块。
3. 仅在目标平台启用 native dependency 和导出。
4. 保留可在任意主机运行的 contract tests。
5. 不包含认证状态机、锐捷业务语义、凭据或用户文案。

## 不采用的方案

### 单一 `rjconnect-link-pcap`

不采用。虽然 libpcap API 表面统一，但 Windows 需要 Npcap SDK/驱动，macOS 使用 BPF 权限模型，Linux 还需要 capability 与 nl80211 协作。共享 wrapper 只会把真实差异压进条件分支。

### 核心 crate 内散布 `cfg`

不采用。协议和状态机必须在三平台保持同一份行为，不能根据目标系统编译出不同认证规则。

## 后果

- workspace 的协议核心在没有任何 native SDK 时也能在三平台检查和测试。
- Windows/macOS/Linux 的实机验收分别负责各自 native 生命周期。
- 平台 crate 可能有少量结构相似代码；只有重复机制被证明稳定后才抽取，不预建薄兼容层。
- CI 需要区分 portable contract、交叉编译和 native runtime acceptance。

## 验收

- 核心 crate 中不存在 `target_os`/`windows`/`unix` 条件编译。
- native 依赖只在对应 target dependency 中出现。
- 三个平台都拥有 portable contract tests。
- 回调输入被复制为 owned snapshot，native 指针不跨越 FFI 调用。
- 每个已接受请求在成功、失败、取消、关闭和队列拒绝路径恰好完成一次。
- 接口 MAC 必须建模为可选值；Tailscale、WireGuard、TUN 等无 MAC tunnel 正常枚举但永不进入 wired EAPOL 会话。

## 阻塞设备通道

libpcap/BPF 类设备通过带短 read timeout 的阻塞 channel 暴露。未来 runtime 在专用 worker 中调用它，并在每次正常 timeout 后检查取消状态；公共平台契约不绑定 Tokio 或其他 async runtime，也不允许在协议状态机线程执行阻塞设备读取。
