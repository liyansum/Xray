# Trojan TCP、面板同步和 Go 1.27.4 验证

## 行为变化

- 普通 Trojan TCP 使用 `DispatchLink`，直接连接 TLS 应用数据读写端与出站。移除原先的两条中间 pipe 和入站双向复制任务；保留鉴权、设备限制、流量统计、嗅探和分流。Trojan 仍执行 TLS 加解密，不能像 Vision 一样将加密连接绕过到原始 socket。
- 活动读写端保留连接空闲和单向结束后的超时。取消连接会设置 socket deadline 唤醒阻塞读写；正常结束允许连接所有者发送 TLS `close_notify`。重复关闭出站写端不会关闭仍在上传的客户端连接。
- 控制器只有在用户认证和设备策略更新全部成功后才提交本地用户、节点快照。待应用列表独立于 API 的 ETag 缓存，下一轮收到 NotModified 时继续重试。逐用户记录成功的增删，支持部分失败、新列表覆盖旧失败批次、空列表撤销全部用户，以及节点重建失败后重试或回滚配置。未变更用户不会因重试而重建身份，速度字段仍仅作兼容。部分成功添加的在线用户在整批同步完成前也参与流量统计上报。
- 主模块和集成核心的 Go 要求及发布编译工具链更新为 1.27.4。安全依赖保持上一版更新后的版本；默认 `multipathtcp=0,tlsmlkem=1,tlssecpmlkem=1`。

## 回归验证

- 主模块全部测试通过（6 个含测试包），集成核心全部测试通过（60 个含测试包）。
- 主模块实际依赖组合下的 dispatcher、limiter、controller、proxy、buf、mux、freedom、trojan 和 TLS 共 9 个包通过 race 检查。最终修改后的 controller、Trojan 再次通过 race，新同步和 TCP 生命周期用例重复 10 次通过 race。
- 真实 TCP + TLS 1.2/1.3 验证 Trojan 鉴权、目标和用户元数据、557056 字节双向数据完整性、客户端上传 EOF、正常 TLS close_notify；另测下载 EOF 后继续上传、空闲/单向超时、取消阻塞读写。
- 真实 dispatcher 验证 route-only HTTP 嗅探保留原拨号目标，同时使用嗅探域名分流；缓存数据不丢失/重复，上下行计数正确，跨协议设备限制仍生效。
- 注入用户添加/移除、设备策略和入站创建错误，验证快照不提前提交、NotModified 重试、身份稳定、失败批次被新列表替代、全部撤销、删除后策略失败再回滚用户，以及节点重建失败后重试或恢复原配置。
- 两个模块的 vet、模块校验和 `go mod tidy -diff` 通过。govulncheck v1.10.0 的两个模块源码及最终二进制扫描均为 0 条 finding（数据库更新时间 2026-11-11T02:51:11Z）。扫描工具本身也以 Go 1.27.4 编译，并将该工具链 bin 置于 PATH 首位，避免扫描子进程回退到旧工具链。

## pipe 开销基准

相同默认 buffer policy，每连接传输 1 MiB，32 KiB 应用批次，五次运行中位数：

| 方向 | 中间 pipe | 直接连接 | 每连接分配次数 |
|---|---:|---:|---:|
| 上传 | 43.777 µs | 21.348 µs | 172 → 128 |
| 下载 | 48.456 µs | 21.693 µs | 175 → 131 |

该基准隔离转发调度和 buffer 成本，不包含 TLS 加密和公网链路，不代表 Speedtest 吞吐会按同一比例提高。复现：

```sh
cd xray-core
go test ./proxy/trojan -run '^$' -bench '^BenchmarkTrojanTCPRelay$' -benchmem -benchtime=500ms -count=5
```

本机验证日志位于 `/root/code/Xray/audit/trojan-sync-go127-20261118/`。发布文件位于 `/root/code/Xray/dist/`，构建元数据记录准确提交号、Go 版本和 SHA-256。旧版二进制保存在 `dist/archive/`。本次未登录或部署远程机器。
