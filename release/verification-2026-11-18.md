# Vision / XUDP verification, 2026-11-18

Baseline: `d252ea9741eff0b76dd6583429a6788d457c3380`.
Toolchain: Go **1.26.11**, Linux amd64. The panel user-snapshot update logic is unchanged.

## Confirmed behavior

- A 16,406-byte TLS record split into 8,192-byte reads switches to direct copy at its actual boundary, including when the next record has already started in the same batch.
- Real TLS 1.3 ServerHello fragments, including fragments of the selected cipher and supported_versions extension, are recognized across reads and handshake records.
- A real nested-TLS transport test reconstructs the complete inner stream byte for byte. All **2,099,968 bytes** of application ciphertext bypass the outer TLS writer after switching; encrypted handshake records can provide an earlier valid switch point.
- Vision UUID/header fragments decode correctly. Concurrent reader/writer recognition passes the race detector. TLS 1.2, unsupported ciphers, malformed ServerHello and UDP/Mux do not force direct copy.
- A connection limited to 1 byte/second cannot splice around its limiter. It still supports Vision direct copy, and partial raw writes count only the bytes written.
- XUDP IDs are isolated by inbound, authenticated user object and source IP. Same-user reconnects preserve reuse; different users/nodes/devices and replaced user objects create separate associations. The old response pump exits before a new one takes over.
- TCP dialing/listening remains plain TCP even with `GODEBUG=multipathtcp=3`; explicit socket-level MPTCP opt-in remains available. Built-in defaults use `multipathtcp=0`.

## Checks

Both the root module and embedded core passed full `go test -mod=readonly -count=1 -timeout=180s ./...` and `go vet -mod=readonly ./...` runs.

Race checks passed for the affected code:

```sh
go test -race -mod=readonly -count=1 -timeout=120s \
  github.com/xtls/xray-core/proxy \
  github.com/xtls/xray-core/common/mux \
  github.com/xtls/xray-core/proxy/trojan \
  ./app/mydispatcher ./common/limiter
go test -race -mod=readonly -count=1 \
  github.com/xtls/xray-core/transport/internet
```

The record-boundary parser benchmark reports **0 B/op, 0 allocs/op**. The old isolated record check allocated about 18 KiB per 16 KiB record; the new compatibility check also allocates zero bytes. These are local parser measurements, not production throughput guarantees.

Tests use loopback connections or in-memory pipes and do not call a production panel. The manual release workflow now includes the Vision/XUDP regression and race checks.
