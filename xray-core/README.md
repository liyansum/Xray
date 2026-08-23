# Xray Core for XrayR

This directory contains the reduced Xray core built specifically for the XrayR
service in the parent repository. It remains a separate Go module only to keep
the canonical core import path compatible. It is not intended to be a
general-purpose Xray distribution.

## Runtime scope

- Inbound protocols: Trojan, Shadowsocks and Shadowsocks 2022, SOCKS, HTTP and
  mixed HTTP/SOCKS.
- Outbound protocols: Shadowsocks and Shadowsocks 2022, SOCKS, direct and block.
- Networking: TCP, UDP, TLS, routing, DNS, DoH, DoQ, FakeDNS, policy, statistics
  and the observatory components required by XrayR.
- Traffic sniffing and the protocol sniffers required by the retained runtime.

The build intentionally excludes VMess, VLESS, REALITY, WebSocket, gRPC,
mKCP/KCP, HTTPUpgrade, XHTTP/SplitHTTP, TUN, WireGuard, Hysteria, FinalMask,
reverse proxy, SS-Plugin and unused command services.

Freedom outbound does not apply the upstream private-address final-rule policy.
Local addresses and public IPv6 destinations are therefore handled by normal
routing rules. Operators are responsible for applying any required destination
restrictions in their own routing configuration or firewall.

## TLS policy

When a server certificate is configured and `cipherSuites` is not explicitly
set, TLS 1.2 is limited to these ECDSA AEAD suites:

- `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`
- `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384`
- `TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256`

The legacy ECDSA CBC suites are excluded. TLS 1.3 cipher suites are controlled
by Go and are unaffected.

Go 1.26 enables hybrid post-quantum key exchange by default. Unless explicitly
overridden, the supported-group preference is X25519MLKEM768,
SecP256r1MLKEM768, SecP384r1MLKEM1024, X25519, P-256, P-384 and P-521.

TLS session resumption is enabled by default. Set
`disableSessionResumption: true` to disable it.

## Build and verification

```bash
go test ./proxy/trojan ./proxy/shadowsocks ./proxy/socks ./infra/conf
go test ./transport/internet/tls \
  -run '^(TestCertificateIssuing|TestExpiredCertificate|TestInsecureCertificates)$'

CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOAMD64=v3 \
  go build -trimpath -ldflags="-s -w" -o xray ./main
```

The parent repository's workflow runs these checks. The service consumes this
module directly through a local `replace`; this core is not released as a
standalone repository or binary.

## Compatibility

Configuration fields removed with unsupported protocols are ignored by the
paired XrayR compatibility layer. The legacy Freedom `finalRules` schema remains
parseable, but it has no runtime enforcement behavior in this fork.

## License

The retained source is distributed under the Mozilla Public License 2.0. See
[LICENSE](LICENSE).
