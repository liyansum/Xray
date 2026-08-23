# Trojan 配置下的三协议入站

本项目在原有 Trojan + TLS 入站上增加了 TLS 握手后的协议识别。面板、节点配置和用户下发格式不需要改变；配置仍然可以是 `trojan`，同一个监听端口实际接受：

- Trojan
- VLESS + TCP + TLS（支持空 flow 和 `xtls-rprx-vision`）
- AnyTLS v2（包含多路复用、SYNACK、心跳和 UDP-over-TCP v2）

三种协议均使用面板下发的同一个 UUID：Trojan 使用 UUID 字符串作为密码，VLESS 使用 UUID 的 16 字节形式，AnyTLS 使用 `SHA-256(UUID 字符串)`。

## 不变的部分

协议识别发生在现有 TLS listener 完成握手之后，因此证书、SNI、ALPN、TLS cipher suites、TLS 版本策略和混合后量子密钥交换均继续由原 TLS 组件处理。本实现没有修改 TLS 配置或握手代码。

无法通过三种认证的连接继续进入原 Trojan fallback 选择逻辑，保留按 SNI、ALPN、HTTP path 和 PROXY protocol 版本进行回落的行为。已认证但协议头损坏的连接会被关闭，不会把用户认证数据转发给伪装站点。

## 协议与统计行为

VLESS 仅接受 TCP 命令。空 flow 使用标准 VLESS TCP 数据路径，可沿用现有 TLS 1.2/1.3 策略；`xtls-rprx-vision` 要求外层 TLS 1.3，其 padding、TLS-in-TLS 识别和满足条件后的 raw-copy/splice 路径沿用 Xray-core 的实现。其他 flow 会被拒绝。

空 flow 不会使用 Vision padding，因此代理 HTTPS 时仍具有普通 VLESS TLS-in-TLS 的流量特征；该选择不会改变 Trojan、AnyTLS、Vision 或 fallback 的流量行为。

AnyTLS 仅接受协议版本 2。每条复用 stream 都建立独立的路由上下文，但继承同一入站用户，因此现有用户上下行统计、在线设备限制、路由和限速逻辑仍按原 email 标识工作。UDP 使用 AnyTLS 规范指定的 `sp.v2.udp-over-tcp.arpa` 与 sing-box UoT v2 数据格式；支持 connect 和非 connect 两种 UDP 模式，并复用 Xray 的 UDP dispatcher。

## 实现依据

- Xray-core 的 VLESS request framing 与 `xtls-rprx-vision` 数据路径
- AnyTLS 官方协议文档和官方 Go 实现的 v2 session 行为
- sing-box 的 UDP-over-TCP v2 线格式
- mihomo 对 AnyTLS v2 SYNACK 与 UoT 的处理行为

Vision 代码来自 MPL-2.0 的 Xray-core。AnyTLS session 和 UoT 代码依据公开线协议在本项目内独立实现，没有引入新的运行时依赖。
