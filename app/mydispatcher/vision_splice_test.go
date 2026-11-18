package mydispatcher

import (
	"bytes"
	"context"
	"io"
	stdnet "net"
	"testing"
	"time"

	"github.com/liyansum/Xray/api"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/transport"
)

func visionTCPPair(t *testing.T) (*stdnet.TCPConn, *stdnet.TCPConn) {
	t.Helper()
	l, err := stdnet.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	c, err := stdnet.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	s, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close(); _ = s.Close() })
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	_ = s.SetDeadline(time.Now().Add(3 * time.Second))
	return s.(*stdnet.TCPConn), c.(*stdnet.TCPConn)
}

type visionWriterCounter struct {
	buf.Writer
	calls int
}

func (w *visionWriterCounter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	w.calls++
	return w.Writer.WriteMultiBuffer(mb)
}

func TestVisionSplicePreservesRateLimit(t *testing.T) {
	const email = "node|limited@example.com|1"
	d := newDispatchLinkTestDispatcher(t, []api.UserInfo{{UID: 1, Email: "limited@example.com", SpeedLimit: 1}})
	base := dispatchLinkTestContext("vless", email, "192.0.2.1")
	in := session.InboundFromContext(base)
	in.CanSpliceCopy = 2
	base = session.ContextWithOutbounds(base, []*session.Outbound{{CanSpliceCopy: 1, Target: net.TCPDestination(net.ParseAddress("192.0.2.10"), 443)}})
	ctx, cancel := context.WithTimeout(base, 2*time.Second)
	defer cancel()
	source, sourceClient := visionTCPPair(t)
	sink, sinkClient := visionTCPPair(t)
	link, err := d.wrapLink(ctx, &transport.Link{Reader: buf.NewReader(bytes.NewReader(nil)), Writer: buf.NewWriter(sink)})
	if err != nil {
		t.Fatal(err)
	}
	if in.CanSpliceCopy != 3 {
		t.Fatalf("splice not blocked by limiter: %d", in.CanSpliceCopy)
	}
	bucket, limited, reject := d.Limiter.GetUserBucket("node", email, "192.0.2.1", true)
	if !limited || reject {
		t.Fatal("rate limiter not active")
	}
	before := bucket.Tokens()
	// VisionWriter must preserve the limiter veto while switching to raw TCP.
	w := &visionWriterCounter{Writer: link.Writer}
	payload := bytes.Repeat([]byte{0x5a}, 4096)
	if _, err := sourceClient.Write(payload); err != nil {
		t.Fatal(err)
	}
	_ = sourceClient.CloseWrite()
	timer := signal.CancelAfterInactivity(ctx, cancel, 3*time.Second)
	defer timer.SetTimeout(0)
	start := time.Now()
	if err := proxy.CopyRawConnIfExist(ctx, source, sink, w, timer, nil); err == nil {
		t.Fatal("4096 bytes passed a 1 B/s limiter before the context deadline")
	}
	elapsed := time.Since(start)
	got := make([]byte, 1)
	if _, err := io.ReadFull(sinkClient, got); err != nil {
		t.Fatal(err)
	}
	if got[0] != payload[0] || w.calls == 0 || bucket.Tokens() >= before {
		t.Fatalf("limiter bypassed: calls=%d tokens=%.2f", w.calls, bucket.Tokens())
	}

	t.Logf("configured rate=%.0f B/s burst=%d; transferred=%d bytes in %v; limiter wrapper calls=%d tokens_before=%.2f tokens_after=%.2f", bucket.Limit(), bucket.Burst(), len(got), elapsed, w.calls, before, bucket.Tokens())
}
