# 安全依赖更新验证（2026-11-18）

此前构建中的独立 HTTP/2、加密和压缩依赖存在已登记的安全告警。本次在主模块及集成核心的模块清单中同步更新，确保主程序构建和核心独立构建使用相同的安全版本。

| 依赖 | 主模块原版本 | 核心原版本 | 更新版本 |
|---|---|---|---|
| golang.org/x/net | v0.57.0 | v0.57.0 | v0.63.0 |
| golang.org/x/crypto | v0.55.0 | v0.54.0 | v0.59.0 |
| github.com/klauspost/compress | v1.19.2 | v1.17.4 | v1.20.4 |
| github.com/andybalholm/brotli | v1.2.2 | v1.0.6 | v1.3.0 |

依赖约束同时要求 x/mod v0.42.0、x/sync v0.25.0、x/sys v0.50.0、x/text v0.44.0、x/tools v0.52.0。两份 go.sum 均重新整理并通过校验。编译工具链继续使用 Go 1.26.11，静态 Linux amd64-v3 构建默认保持 `multipathtcp=0,tlsmlkem=1,tlssecpmlkem=1`。

相关安全条目：[HTTP/2](https://pkg.go.dev/vuln/GO-2026-6603)、[SSH](https://pkg.go.dev/vuln/GO-2026-6354)、[压缩数据 panic](https://pkg.go.dev/vuln/GO-2026-6865)、[Brotli 内存分配](https://pkg.go.dev/vuln/GO-2026-6888)。告警涉及的模块、功能及可达性不同，不能直接等同为 Trojan 入站可利用漏洞。

## 发布前检查

- 主模块完整测试通过：6 个含测试的包。
- 集成核心完整测试通过：60 个含测试的包，包括真实 Vision TLS 交接、TCP 双向 splice、Trojan、UDP/XUDP、DNS、路由及场景测试。
- 在主模块实际解析出的依赖组合下，dispatcher、limiter、controller、核心 proxy、buf、mux、freedom、trojan 和 TLS 共 9 个包的 race 检查通过。
- 主模块和核心分别通过 `go vet ./...`、`go mod verify` 和 `go mod tidy -diff`。
- `govulncheck v1.10.0 -json ./...` 分别检查主模块和核心，均报告 0 条 finding。本次数据库元数据更新时间为 `2026-11-11T02:51:11Z`；该结果不覆盖所有自定义协议问题或 fork 中未登记的问题。
- 正式二进制在提交后的干净工作树构建，并校验 VCS 提交号、Go 版本、四项依赖版本、静态链接、amd64-v3 和默认 GODEBUG。二进制漏洞扫描和 SHA-256 校验在替换 dist 中的最终文件前执行。

主要检查命令（工具链均为 Go 1.26.11）：

```sh
go test -mod=readonly -count=1 -timeout=180s ./...
go vet -mod=readonly ./...
go mod verify
go mod tidy -diff
govulncheck -json ./...
# 上述命令分别在主模块和 xray-core 目录运行。

# 在主模块目录，按正式二进制的依赖组合检查关键并发路径：
go test -race -mod=readonly -count=1 -timeout=180s \
  ./app/mydispatcher ./common/limiter ./service/controller \
  github.com/xtls/xray-core/proxy github.com/xtls/xray-core/common/buf \
  github.com/xtls/xray-core/common/mux github.com/xtls/xray-core/proxy/freedom \
  github.com/xtls/xray-core/proxy/trojan github.com/xtls/xray-core/transport/internet/tls
```

本机检查日志保存在 `/root/code/Xray/audit/security-deps-release-20261118-212027/`。最终二进制、SHA-256 和构建元数据位于 `/root/code/Xray/dist/`；上版提交 `3522bf1` 的二进制已归档至 `dist/archive/`。
