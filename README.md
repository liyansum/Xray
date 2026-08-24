# Xray

这是一个修改版的 XrayR，将专用 Xray-core 直接整合进同一源码仓库，并在普通 Trojan + TLS 节点上提供同端口多协议入站。

本项目支持对接 [liyansum/v2board](https://github.com/liyansum/v2board) 修改版 V2board。面板服务端和 XrayR 均按照普通 Trojan 节点配置即可，不需要在面板中新增 VLESS 或 AnyTLS 节点类型。

> 本项目只适用于下方列出的协议和功能，不是完整上游 XrayR/Xray-core 的替代品。

## 免责声明

本项目仅供个人学习、研究和合法用途。维护者不保证任何可用性，也不对使用本软件造成的任何后果负责。请遵守所在地区的法律法规。

## 特点

- XrayR 服务端和精简、优化后的 Xray-core 位于同一项目中，编译时直接使用本地 core 源码。
- 普通 Trojan 节点的同一个 TCP + TLS 端口可同时接受 Trojan、VLESS 和 AnyTLS。
- 支持 VLESS + TCP/UDP + TLS 空 flow，UDP 使用标准 VLESS 长度分帧。
- 支持 VLESS + TCP + TLS + `xtls-rprx-vision`；Vision 要求外层 TLS 1.3，UDP 使用 Mux/XUDP。
- VLESS 两种 flow 均接受 UDP/443（包括 QUIC），服务端不按目标端口过滤。
- 支持 AnyTLS v1/v2 多路复用；v2 额外支持 SYNACK、心跳及服务端版本协商。
- AnyTLS UDP 支持 connect 和非 connect 模式，并复用 Xray 的 UDP dispatcher。
- 三种协议使用面板下发的同一个 UUID，保留用户热更新、流量统计、在线设备限制、用户限速和路由规则。
- 未通过认证的连接继续使用 Trojan 原有 fallback，保留 SNI、ALPN、HTTP path 和 PROXY protocol 选择行为。
- 支持单实例对接多面板、多节点，无需为每个节点重复启动进程。
- 支持 Trojan、Shadowsocks 和 Shadowsocks 2022 托管节点。
- 支持 TCP、UDP、TLS、路由、DNS、DoH 和 DoQ。
- 支持文件证书热加载和 TLS session resumption。
- 使用 Go 1.26.7，保留 TLS 1.3 混合 ML-KEM 后量子密钥交换。

## 多协议入站

当节点类型为 Trojan 且启用本地 TLS 时，同一个监听地址和端口支持：

| 客户端协议 | 传输与安全层 | 认证信息 |
| --- | --- | --- |
| Trojan | TCP + TLS | UUID 字符串作为密码 |
| VLESS | TCP/UDP + TLS，空 flow | 同一 UUID 的 16 字节形式 |
| VLESS Vision | TCP + XUDP + TLS 1.3，`xtls-rprx-vision` | 同一 UUID 的 16 字节形式 |
| AnyTLS | AnyTLS v1 或 v2 + TLS | `SHA-256(UUID 字符串)`，由客户端自动计算 |

协议识别发生在现有 TLS listener 完成握手后，不会修改证书、SNI、ALPN、cipher suites、TLS 版本策略或后量子协商。

未匹配完整有效凭据的连接不会收到多协议特有响应，原始应用层字节会完整交给 Trojan fallback。协议检测不会根据已登记用户的 VLESS UUID 或 AnyTLS 哈希前缀延长等待，避免形成可逐字节试探用户凭据的时序 oracle。只有已经提供完整有效 AnyTLS 凭据的客户端才会进入版本协商；此后的非法设置会在加密连接内收到 AnyTLS Alert 并关闭，不会把已认证协议头转发给伪装站点。

普通 VLESS 空 flow 不使用 Vision padding，因此代理 HTTPS 时仍具有普通 VLESS TLS-in-TLS 的流量特征；这不会改变 Trojan、AnyTLS、Vision 或 fallback 的行为。空 flow 支持标准 VLESS TCP、直接 UDP 和 Mux。Vision 支持 TCP，并按照 Xray 的兼容行为只允许 Mux 内的 XUDP，不接受 Vision + 直接 VLESS UDP，也不允许在 Vision Mux 中隐藏 TCP stream。

UDP/443 在服务端没有特殊封锁，QUIC 与其他 UDP 目标使用同一派发、路由和统计路径。官方 Xray 客户端使用 Vision 时，可将客户端账户 flow 配置为 `xtls-rprx-vision-udp443`；客户端会在发送前将它归一化为线上协议中的 `xtls-rprx-vision`，服务端也兼容直接收到两种写法。如果客户端还启用了通用 outbound Mux，其版本可能另有 `xudpProxyUDP443` 开关，应设置为 `allow`，或使用 `skip` 绕过该层后交给 VLESS Vision 自身的 XUDP。其他客户端必须确认其 Vision 实现支持 XUDP 和 UDP/443；仅服务端放行无法绕过客户端自身的发送限制。

AnyTLS 接受协议版本 1 和 2，并按照客户端上报的版本协商：v1 不发送 v2 专有的 ServerSettings、SYNACK 或心跳控制帧；v2 保持完整协商和连接存活检测。客户端新建 stream 的 ID 必须严格递增（无需连续），重复或倒退会在已鉴权的加密会话内返回标准 Alert 并关闭该会话；服务端不限制同时活跃的 stream 数量。每条复用 stream 都使用独立路由上下文并继承同一个面板用户，因此流量统计、限速和设备限制仍按照原用户归集。两个 AnyTLS 会话版本的 UDP 都使用规范指定的 `sp.v2.udp-over-tcp.arpa` 和 UoT v2 数据格式。

AnyTLS 接收端为每条 stream 使用独立的非阻塞队列，慢目标不会阻塞同一 TLS 会话中的其他 stream。队列按底层缓冲区的真实分配容量计费，单 stream 最多缓存 256 KiB/64 帧、单会话最多 2 MiB/512 帧、单个入站实例合计最多 32 MiB/8192 帧；达到窗口时只关闭对应 stream（v2 会在加密会话内返回带错误的 SYNACK）。这些是待处理数据的内存窗口，不是活跃 stream 数量限制。用户限速在 UDP 路径上按完整数据报等待令牌，不会为了适配令牌桶 burst 而拆分游戏或 QUIC 数据报。

## 面板与节点配置

### 修改版 V2board

配合 [liyansum/v2board](https://github.com/liyansum/v2board) 使用时：

1. 在面板中创建普通 Trojan 节点，配置节点端口和域名。
2. 用户信息继续由面板下发 UUID，不需要为不同协议创建多份用户；不同用户必须使用不同 UUID，重复 UUID（包括仅大小写不同的写法）会被拒绝，避免认证和流量归属被覆盖。
3. XrayR 中使用 `PanelType: "NewV2board"` 和 `NodeType: Trojan`。
4. 配置本地 TLS 证书和私钥；多协议入口依赖该 Trojan TLS listener。
5. 客户端根据需要选择 Trojan、VLESS 空 flow、VLESS Vision 或 AnyTLS v1/v2，服务器地址、端口、SNI 和 UUID 保持一致；Vision 客户端需要按上一节说明启用 XUDP/UDP 443。

示例配置：

```yaml
Log:
  Level: warning
  AccessPath:
  ErrorPath:

Nodes:
  - PanelType: "NewV2board"
    ApiConfig:
      ApiHost: "https://panel.example.com"
      ApiKey: "YOUR_API_KEY"
      NodeID: 1
      NodeType: Trojan
      Timeout: 30
      SpeedLimit: 0
      DeviceLimit: 0
      RuleListPath:
    ControllerConfig:
      ListenIP: 0.0.0.0
      SendIP: 0.0.0.0
      UpdatePeriodic: 60
      DeviceOnlineMinTraffic: 100
      EnableDNS: false
      DNSType: AsIs
      EnableProxyProtocol: false
      EnableFallback: false
      CertConfig:
        CertMode: file
        CertFile: /etc/XrayR/cert/node.example.com.cert
        KeyFile: /etc/XrayR/cert/node.example.com.key
        RejectUnknownSni: false
        DisableSessionResumption: false
```

完整配置字段可参考仓库中的 [`release/config/config.yml.example`](release/config/config.yml.example)。面板和 XrayR 仍然只需要配置普通 Trojan 节点；不要额外建立 VLESS 或 AnyTLS 节点。

文档和部署兼容基线为 `liyansum/v2board` 的 `master` 分支，基线提交是 `074dd516cd3f936908d8905b8fae89c0d6114c49`（2024-12-29）。该仓库 fork 自 [wyx2685/v2board](https://github.com/wyx2685/v2board)。截至 2026-08-24，检查的上游提交 `3cfb3f0d318e7158a0394e247e1479622cd21d3e` 所提供的 UniProxy JSON 接口与本项目使用的 Trojan 字段仍保持代码级兼容，但没有将该上游版本作为生产部署组合进行完整验证；已有面板不要仅依据代码级兼容结论直接升级，应先备份并在测试环境验证数据库迁移、缓存、队列和用户/流量上报。

`NewV2board` 适配器会自动兼容两种设备统计接口：旧版面板（已验证 `71bb51d395cd939a04630df68b4ce05f87e164ca`）从 `/UniProxy/user` 的 `alive_ip` 字段读取，新版面板从独立的 `/UniProxy/alivelist` 读取。旧版不会额外请求不存在的接口；新版在用户列表返回 `304 Not Modified` 时仍会刷新在线设备数。临时面板错误会保留最后一次有效快照，设备限制按“面板已有设备数 + 当前统计周期新增 IP”原子判断。`ApiConfig.DeviceLimit: 0` 表示使用面板为各用户配置的限制，并非关闭设备限制。旧版面板只为本身已设置设备限制的用户返回 `alive_ip`，因此旧版组合应保持 `DeviceLimit: 0` 并在面板用户侧配置限制。

### 其他面板

代码保留以下面板适配器，但本修改版明确支持的主要适配目标是 `liyansum/v2board`：

| 面板类型 | `PanelType` | Trojan | Shadowsocks |
| --- | --- | --- | --- |
| `liyansum/v2board` 修改版 | `NewV2board` 或 `V2board` | 支持 | 支持 |
| SSPanel-UIM | `SSpanel` | 支持 | 支持 |
| PMPanel | `PMpanel` | 支持 | 支持 |
| ProxyPanel | `Proxypanel` | 支持 | 支持 |
| V2RaySocks | `V2RaySocks` | 支持 | 支持 |
| GoV2Panel | `GoV2Panel` | 支持 | 支持 |
| BunPanel | `BunPanel` | 支持 | 支持 |

多协议同端口能力只挂载在 Trojan 入站上；Shadowsocks 节点保持原行为。

## TLS 行为

- 证书由外部工具申请和续期，本项目不包含自动 ACME。
- `CertMode: file` 加载本地证书和私钥；文件变化后可热加载。
- TLS session resumption 默认启用，可通过 `DisableSessionResumption: true` 关闭。
- 使用预期的 ECDSA 证书时，TLS 1.2 仅使用 ECDHE-ECDSA AES-GCM 或 ChaCha20-Poly1305，已排除旧式 ECDSA CBC suites。
- TLS 1.3 和 Go 1.26 的混合 ML-KEM 密钥交换保持启用。
- VLESS Vision 强制外层 TLS 1.3；Trojan、VLESS 空 flow 和 AnyTLS 沿用节点现有 TLS 策略。

## 功能范围

| 功能 | Trojan 多协议入站 | Shadowsocks |
| --- | --- | --- |
| 获取节点与用户信息 | 支持 | 支持 |
| 用户流量统计 | 支持 | 支持 |
| 在线用户与设备限制 | 支持 | 支持 |
| 节点级、用户级限速 | 支持 | 支持 |
| 审计及路由规则 | 支持 | 支持 |
| 自定义 DNS | 支持 | 支持 |
| Trojan fallback | 支持 | 不适用 |
| 自动申请/续期 TLS 证书 | 不支持 | 不支持 |

本精简版本不包含 VMess、REALITY、WebSocket、gRPC、mKCP/KCP、HTTPUpgrade、XHTTP/SplitHTTP、TUN、WireGuard、Hysteria、FinalMask、SS-Plugin 和自动 ACME。未支持的旧节点或自定义代理配置会记录日志并跳过，避免陈旧配置影响受支持节点启动。

## 项目结构与源码基线

- 仓库根目录：XrayR 服务、面板适配、控制器和程序入口。
- `xray-core/`：内置的专用 Xray-core，保留 `github.com/xtls/xray-core` module path。
- 根目录 `go.mod`：通过 `replace github.com/xtls/xray-core => ./xray-core` 强制使用本地 core，不会下载另一个 core fork。

初始整合源码基线：

| 组件 | 来源 | 分支 | Commit |
| --- | --- | --- | --- |
| XrayR 服务 | `https://github.com/liyansum/XrayR` | `master` | `a9df56584ebd97b68e6987fcf2cd207cbbc27d3f` |
| 专用 Xray-core | `https://github.com/liyansum/Xray-core` | `main` | `f5b4e833af34694c4b936629591c52c7c49cef91` |

Vision 数据路径来自 MPL-2.0 的 Xray-core。AnyTLS v1/v2 和 UoT v2 依据 AnyTLS 官方协议、sing-box UoT 格式及 mihomo 的兼容行为在本项目内实现，没有增加新的运行时依赖。

## 编译

要求 Go `1.26.7`：

```bash
git clone https://github.com/liyansum/Xray.git
cd Xray
./build.sh
```

默认生成静态 Linux amd64-v3 二进制，构建参数包括：

- `CGO_ENABLED=0`
- `GOAMD64=v3`
- `-trimpath`
- `-ldflags="-s -w"`

目标 CPU 必须支持 x86-64-v3。旧处理器可使用：

```bash
GOAMD64=v1 ./build.sh
```

运行不依赖外部面板的默认测试：

```bash
go test ./...
go test -race ./...
```

旧面板的手工联调测试使用 `integration` build tag，默认不会访问本机或外部面板。验证内置核心和多协议入口：

```bash
cd xray-core
go test ./...
go test -race ./...
go vet ./...
```

## Release workflow

`Release integrated Xray` workflow 仅支持手动触发。它会校验 `releaseX.Y.Z` 格式的 tag，构建 `XrayR-linux-amd64-v3`、生成 SHA-256 校验文件并创建 GitHub Release；已存在的 tag 或 Release 不会被覆盖。

## 使用注意

- 生产环境的面板密钥、证书私钥和节点配置不要提交到仓库。
- Freedom/direct outbound 允许本地和公网 IPv6 目标，需要限制时请使用路由规则或主机防火墙。
- fallback 目标应是可信的本地或内部服务，并按需要配置 PROXY protocol。
- 多协议共用同一 UUID；撤销或更新用户时，三种协议的认证会同步更新。

## Thanks

- [Project X](https://github.com/XTLS/)
- [XrayR](https://github.com/XrayR-project/XrayR)
- [liyansum/v2board](https://github.com/liyansum/v2board)
- [wyx2685/v2board](https://github.com/wyx2685/v2board)
- [V2Fly](https://github.com/v2fly)
- [sing-box](https://github.com/SagerNet/sing-box)
- [AnyTLS](https://github.com/anytls/anytls-go)
- [mihomo](https://github.com/MetaCubeX/mihomo)

## License

本项目使用 Mozilla Public License 2.0，详见 [LICENSE](LICENSE)。
