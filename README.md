# Xray

This repository is the integrated source project for the dedicated XrayR
service and its reduced Xray core. The service source lives at the repository
root and the core source is versioned in [`xray-core/`](xray-core/). Builds use
that local source directly; they do not download a separate Xray core fork.

The project preserves panel synchronization, user updates, traffic accounting,
limits and reporting while exposing a small, explicitly supported proxy
surface.

## Repository layout

- `/`: XrayR service, panel integrations and the executable entry point.
- `/xray-core`: the dedicated core, retained as its own Go module so its
  canonical `github.com/xtls/xray-core` package imports remain compatible.
- `go.mod`: maps `github.com/xtls/xray-core` to the local `./xray-core` source.

The exact upstream commits used to assemble this repository are recorded in
[`SOURCE_VERSIONS.md`](SOURCE_VERSIONS.md).

## Supported scope

- Managed node protocols: Trojan, Shadowsocks and Shadowsocks 2022.
- Custom inbound protocols: Trojan, Shadowsocks and Shadowsocks 2022, SOCKS,
  HTTP and mixed HTTP/SOCKS.
- Outbound protocols: Shadowsocks and Shadowsocks 2022, SOCKS, direct and block.
- Networking: TCP, UDP, TLS, routing, DNS, DoH and DoQ.

VMess, VLESS, REALITY, WebSocket, gRPC, mKCP/KCP, HTTPUpgrade,
XHTTP/SplitHTTP, TUN, WireGuard, Hysteria, FinalMask, SS-Plugin and automatic
ACME certificate management are not included.

Unsupported legacy node and custom-proxy entries are logged and skipped so
that stale configuration does not prevent the retained nodes from starting.

## TLS behavior

- File-based certificates can be reloaded without restarting the process.
- TLS session resumption is enabled by default. Set
  `DisableSessionResumption: true` to disable it.
- With the expected ECDSA certificate, TLS 1.2 uses only ECDHE-ECDSA AES-GCM or
  ChaCha20-Poly1305. The two legacy ECDSA CBC suites are excluded.
- TLS 1.3 and Go 1.26 hybrid ML-KEM key exchanges remain enabled.

Certificate issuance and renewal must be handled outside XrayR. Configure a
certificate and key with `CertMode: file`; use `CertMode: none` when local TLS
termination is not required.

## Production build

```bash
./build.sh
```

The default build is a static Linux amd64 binary compiled with:

- `CGO_ENABLED=0`
- `GOAMD64=v3`
- `-trimpath`
- `-ldflags="-s -w"`

An x86-64-v3 capable processor is required. For an older processor, build with
`GOAMD64=v1 ./build.sh`.

To compile every service package and test source without running tests that may
contact panel endpoints:

```bash
go test -run '^$' ./...
```

To verify the retained core runtime:

```bash
cd xray-core
go test ./proxy/trojan ./proxy/shadowsocks ./proxy/socks ./infra/conf
go test ./transport/internet/tls \
  -run '^(TestCertificateIssuing|TestExpiredCertificate|TestInsecureCertificates)$'
```

## Release workflow

The `Release integrated Xray` workflow is manual-only. It accepts a release tag,
builds `XrayR-linux-amd64-v3`, generates a SHA-256 checksum and creates the
corresponding GitHub release. Re-running it with an existing tag fails instead
of replacing an existing release.

## Operational notes

- Freedom/direct outbound permits local and public IPv6 destinations. Apply
  destination restrictions with routing rules or the host firewall when needed.
- Existing routing blocks remain effective.
- Production configuration and panel credentials must not be committed.
- The Xray core source is committed in `xray-core/`; the local `replace`
  directive in `go.mod` prevents fallback to a remote core module.

## License

This repository is distributed under the Mozilla Public License 2.0. See
[LICENSE](LICENSE).
