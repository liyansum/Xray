# Vision 双向 splice 与转发性能验证（2026-11-18）

本次变更针对主仓库 `liyansum/Xray` 的集成内核。编译继续使用 Go 1.26.11，默认关闭 MPTCP；未改动旁边两个历史仓库。

## 行为变化

- Vision TCP 的上行（客户端 → 服务端 → 目标）新增内核 splice；下行继续支持 splice。需要 Linux/Android、原始 Freedom TCP 出站和已完成的 Vision direct copy 切换。
- 读写方向分别暴露就绪状态。上行必须先交付 TLS 缓冲、嗅探缓存及尚未交付的异步读取结果；下行必须完成最后的 Vision/TLS 帧及同批原始后缀写入。上行就绪不会提前放行下行。
- 使用非阻塞 socket/pipe splice 配合 Go netpoll。每次成功搬运更新统计和活动计时，取消可以打断等待中的读或写；不再将空闲超时强行设成 24 小时。pipe 在所有退出路径关闭，不支持的内核/来源可在尚未消费字节时退回普通读写。
- 移除节点、用户、自动限速的令牌桶、等待及转发包装器。保留 XrayR/面板字段解析、设备数限制、在线上报及流量统计。仅修改速度字段不再重建节点或用户，避免干扰认证身份和 XUDP 关联；凭据、设备策略及监听参数变更仍正常生效。
- XUDP/Mux 的已有 UDP 批次按约 32 KiB 或 32 帧分组写出，保留每包元数据和长度，不等待额外包。单个较大帧保持完整，独立提交。同步 VLESS 写锁继续保护完整写入，UDP 本身不使用 splice，也不绕过外层 TLS。
- 保留 Fragment、安全封装及显式 splice 禁令对应的处理。Trojan TCP/TLS 继续通过必要的 TLS 读写路径。

## 回归结果

- 主模块与集成核心均通过完整 `go test ./...` 和 `go vet ./...`。
- race 检查覆盖 `proxy`、`common/mux`、`common/buf`、`proxy/freedom`、`proxy/trojan` 以及主模块的 dispatcher、设备限制和 controller。
- splice/真实 Vision 切换测试通过重复 race 运行；Windows 交叉编译验证普通读写回退路径可以编译。
- 真实 TLS 1.3 Application Data 密文共 2,099,968 字节，分别经上行和下行切换后逐字节一致。上行以 997 字节分批发送，强制跨多次写入完成首个大 TLS 记录。切换后的上行缓冲原始读取次数、下行缓冲原始写入次数均为 0；用户统计与实际载荷一致。
- Linux `strace -f -e trace=splice` 分别跟踪两个方向，均观察到成功的 socket → pipe → socket 内核调用，排除仅根据接口名称判断启用。
- 连接不关闭时流量统计已经更新；持续活动不会触发空闲回收，停止活动后按配置取消。上传 EOF 后反向下载仍可继续；目标写阻塞时取消可唤醒；不支持的来源回退前不消费数据。
- 嗅探缓存和超时后仍在进行的读取必须排空后才暴露原始 socket，且用户计数正确。
- 100 个 1200 字节 UDP 数据报由 100 次外层写入降至 4 次。与逐包提交相比，完整编码字节流一致；通过每次最多读取 3 字节的接收器验证会话 ID、GlobalID、目的地址、包内容与顺序。测试包括 QUIC 形态的二进制载荷、失败后的 buffer 释放和小包帧数上限；现有真实 TLS 上的 Vision UDP/XUDP/UDP443 回归也通过。
- 非零速度字段不会增加转发包装器、禁止 splice 或停止统计；设备限制在添加和更新速度参数后仍有效。

## 性能检查

`BenchmarkSpliceAccounting` 将原来的 `TCPConn.ReadFrom` 与新路径放在相同的回环 TCP 生产/消费链路中比较。新路径额外执行实时计数、活动更新和取消处理。基准按每 1 MiB 计量，最终三次新路径结果约为 2.43–2.57 GB/s，报告 0 allocs/op；原路径约为 1.92–2.82 GB/s。回环吞吐受调度影响，以上数字不代表公网或所有连接场景的速度保证。新路径回调按连接复用，避免随传输批次产生小对象分配；每条连接仍有少量固定资源和分配。

## 重现主要检查

```sh
GOTOOLCHAIN=go1.26.11 go test -mod=readonly -count=1 -timeout=180s ./...
GOTOOLCHAIN=go1.26.11 go vet -mod=readonly ./...
GOTOOLCHAIN=go1.26.11 go test -race ./app/mydispatcher ./common/limiter ./service/controller
cd xray-core
GOTOOLCHAIN=go1.26.11 go test -mod=readonly -count=1 -timeout=180s ./...
GOTOOLCHAIN=go1.26.11 go vet -mod=readonly ./...
GOTOOLCHAIN=go1.26.11 go test -race ./proxy ./common/buf ./common/mux ./proxy/freedom ./proxy/trojan
GOTOOLCHAIN=go1.26.11 go test -race -count=10 ./proxy -run '^(TestSplice.*|TestVisionTCPSpliceHandoff)$'
GOTOOLCHAIN=go1.26.11 go test ./common/mux -run '^TestPacketBatchWireEquivalentAndBounded$' -v
GOTOOLCHAIN=go1.26.11 go test ./proxy -run '^$' -bench '^BenchmarkSpliceAccounting$' -benchmem
```

这些检查覆盖本机及项目自动化回归，未连接生产面板或替换正在运行的服务。新二进制与 SHA-256、VCS/工具链元数据放在仓库外的 `/root/code/Xray/dist/`，上一版保存在 `dist/archive/`。
