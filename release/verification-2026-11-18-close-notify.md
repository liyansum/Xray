# TLS close_notify 与有效数据同批返回的修复验证

## 问题与修复

Trojan TCP 改为直接分发后，TLS 1.2 可能把最后一批有效请求数据与 `io.EOF` 一起返回。嗅探缓存原先先判断错误，直接丢掉同批数据，客户端因此等待响应并超时。复现中读取结果为 95 字节 + EOF：旧版通过，新版开启嗅探时 12/12 超时。该边界不能直接解释所有普通批量测试的 200–300ms 波动。

本次修复同一数据链路上的以下问题：

- 自定义 dispatcher 和集成核心原生 dispatcher：先保留有效数据用于嗅探及分流，再向出站传递缓存数据和原始终止错误。保留 EOF、unexpected EOF 和其他读取错误，不再额外读取已结束的数据源。中断后释放迟到批次，Vision 也不能通过 raw/splice 绕过待处理错误。
- 通用 BufferedReader：`Read`、`ReadByte`、`ReadAtMost`、`ReadMultiBuffer` 和 `WriteTo` 混用时保留最后一批数据及错误，避免读取半个协议头、UDP/Mux 帧或复制尾部时丢失数据/错误。
- Trojan 多协议入口：协议判别首读同时返回有效数据和 EOF 时，先验证协议及用户，并把数据与错误一并保留。截断头部和无效用户仍拒绝。
- `CopyOnceTimeout`：先写出读取到的数据，再返回原始读取错误；写入失败优先报告并保留写错误分类。Mux 将正常 EOF 作为正常结束，Shadowsocks 在 EOF 或其他读取错误前先刷新已成功编码的数据，正常 EOF 后仍能接收响应。

无中间 pipe 的 Trojan TCP 路径、嗅探/分流、流量统计、设备限制和 Vision splice 保留。Go 继续使用 1.27.4，依赖版本不变，默认 `multipathtcp=0,tlsmlkem=1,tlssecpmlkem=1`。

## 验证

- 在修复前，新增嗅探及 BufferedReader 回归测试均失败；修复后通过，覆盖有效数据与 EOF、unexpected EOF、其他读取错误同批返回，以及错误和数据的顺序、所有权及重复读取检查。
- 真实 TCP + TLS 1.2/1.3 + 项目完整 Trojan 入站、dispatcher、Freedom 出站：覆盖完整首包、头部中断点、应用首读、HTTP 头分段四个到达阶段及嗅探开关，共 16 种组合。验证 204 响应、正常关闭、请求只到达一次、上下行计数准确。另测无效用户与截断头部，均被拒绝。
- 独立批量探测：24 种组合、32 并发、5,760 次真实 TLS 连接全部通过。包含上述四种关闭阶段，以及正常 HTTP 和内层 HTTPS；TLS 1.2/1.3 与嗅探开关均覆盖。原先必现的 TLS 1.2 场景不再超时。
- Mux 测试解码首个数据帧及结束帧，验证最终数据存在且正常 EOF 不携带错误标志。Shadowsocks 使用 AES-128-GCM、ChaCha20-Poly1305 的真实协议编解码验证最终请求刷新、正常 EOF 后响应以及其他读取错误前的数据刷新。
- 主模块及集成核心完整测试通过；包含 dispatcher、limiter、controller、proxy、buf、mux、freedom、shadowsocks、trojan、TLS 的 11 个关键包通过 race。新缓存/缓冲/Mux/TLS 集成回归另重复五次 race，通过。
- 两个模块 vet、模块校验、`go mod tidy -diff` 通过；govulncheck v1.10.0 对两个模块源码及最终二进制扫描为 0 条 finding，数据库更新时间为 2026-11-11T02:51:11Z。

日志及批量探测程序保存在 `/root/code/Xray/audit/close-notify-fix-20261118/`。最终静态 Linux amd64-v3 二进制、SHA-256 及构建元数据在 `/root/code/Xray/dist/`；上一版 `95b954b` 已归档至 `dist/archive/`。本次未连接或部署远程机器。
