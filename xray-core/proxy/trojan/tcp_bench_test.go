package trojan

import (
	"context"
	"io"
	stdnet "net"
	"testing"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

const tcpBenchBytes = 1024 * 1024

type tcpBenchReader struct{ remaining int }

func (r *tcpBenchReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	if r.remaining == 0 {
		return nil, io.EOF
	}
	n := min(r.remaining, 32*1024)
	r.remaining -= n
	b := buf.NewWithSize(32 * 1024)
	b.Extend(int32(n))
	return buf.MultiBuffer{b}, nil
}

type tcpBenchDispatcher struct {
	routing.Dispatcher
	download bool
}

func (d tcpBenchDispatcher) relay(link *transport.Link) error {
	if err := buf.Copy(link.Reader, buf.Discard); err != nil {
		return err
	}
	if d.download {
		if err := buf.Copy(&tcpBenchReader{remaining: tcpBenchBytes}, link.Writer); err != nil {
			return err
		}
	}
	return common.Close(link.Writer)
}
func (d tcpBenchDispatcher) DispatchLink(_ context.Context, _ net.Destination, link *transport.Link) error {
	return d.relay(link)
}
func (d tcpBenchDispatcher) Dispatch(ctx context.Context, _ net.Destination) (*transport.Link, error) {
	opts := pipe.OptionsFromContext(ctx)
	upReader, upWriter := pipe.New(opts...)
	downReader, downWriter := pipe.New(opts...)
	go func() { _ = d.relay(&transport.Link{Reader: upReader, Writer: downWriter}) }()
	return &transport.Link{Reader: downReader, Writer: upWriter}, nil
}

// Compare forwarding machinery with identical 32 KiB application batches and
// buffer policy. This isolates pipe/task cost; it does not measure TLS or WAN
// throughput and should not be interpreted as a production speedup percentage.
func BenchmarkTrojanTCPRelay(b *testing.B) {
	for _, direction := range []string{"upload", "download"} {
		for _, direct := range []bool{false, true} {
			name := direction + "/pipes"
			if direct {
				name = direction + "/direct"
			}
			b.Run(name, func(b *testing.B) {
				conn, peer := stdnet.Pipe()
				defer conn.Close()
				defer peer.Close()
				d := tcpBenchDispatcher{download: direction == "download"}
				s := new(Server)
				plcy := policy.SessionDefault()
				dest := net.TCPDestination(net.LocalHostIP, 80)
				b.ReportAllocs()
				b.SetBytes(tcpBenchBytes)
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					r := &tcpBenchReader{}
					if !d.download {
						r.remaining = tcpBenchBytes
					}
					var err error
					if direct {
						err = s.handleTCPConnection(context.Background(), plcy, dest, r, buf.Discard, conn, d)
					} else {
						err = s.handleConnection(context.Background(), plcy, dest, r, buf.Discard, d)
					}
					if err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}
