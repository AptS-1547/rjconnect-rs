# ADR-0002：底层库 workspace，不提供用户界面

状态：Accepted  
日期：2026-09-30

## 背景

同一套认证底层未来可能被 CLI、TUI、GUI、后台服务或其他产品集成。如果在当前 workspace 直接加入交互、文案、终端状态或桌面生命周期，协议与平台能力会反向依赖具体产品形态。

## 决策

`rjconnect-rs` 只交付可嵌入的底层 library crates：

- 线上协议编解码。
- 认证状态机与 challenge-response。
- 可嵌入的会话 runtime。
- 三个平台的设备与系统网络 adapter。
- Linux 无线 PEAP/MSCHAPv2/WPA 安全链路。
- 配置值模型、凭据抽象和结构化诊断事件。

本 workspace 不提供：

- CLI、TUI 或 GUI 二进制。
- 账号密码交互输入。
- 用户文案、语言包、进度渲染或桌面通知。
- 服务安装器、开机启动配置或系统托盘。
- 产品特定配置目录与升级流程。

上层通过公开 Rust API 订阅类型化状态、提供凭据和执行产品交互。

## Runtime 定义

未来的 `rjconnect-runtime` 是库，不是应用入口。它负责：

- 驱动纯状态机 effect。
- 管理 timer、取消和平台数据通道。
- 产生类型化会话事件。
- 保证关闭和资源回收顺序。

它不读取终端、不弹窗口，也不决定错误文案。

## 后果

- 底层 API 必须能被多个并发会话安全复用。
- 公共错误以稳定类别和结构化上下文表达，不包含展示字符串策略。
- 测试使用内存 channel、协议黄金样本和平台 contract fixture，不通过 CLI 驱动核心。
- 上层产品可以位于独立仓库，也可以以后作为独立 workspace 消费这些 crates。

## 验收

- workspace member 中不存在 `src/main.rs`。
- 协议、状态机和平台 API 不依赖终端、GUI 或国际化 crate。
- 用户可观察状态通过公开 enum/struct 表达。
- 所有 runtime 行为可通过 library integration test 驱动。
