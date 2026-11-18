package mydispatcher

import (
	"bytes"
	"context"
	"io"
	stdnet "net"
	"runtime"
	"testing"
	"time"

	"github.com/liyansum/Xray/api"
	"github.com/xtls/xray-core/app/dispatcher"
	corestats "github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/features/policy"
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

type visionStatsPolicy struct{ dispatchLinkTestPolicy }

func (visionStatsPolicy) ForLevel(uint32) policy.Session {
	p := policy.SessionDefault()
	p.Stats.UserUplink, p.Stats.UserDownlink = true, true
	return p
}

func TestVisionSpliceIgnoresSpeedParameters(t *testing.T) {
	const email = "node|limited@example.com|1"
	d := newDispatchLinkTestDispatcher(t, []api.UserInfo{{UID: 1, Email: "limited@example.com", SpeedLimit: 1}})
	manager, err := corestats.NewManager(context.Background(), new(corestats.Config))
	if err != nil {
		t.Fatal(err)
	}
	d.policy, d.stats = visionStatsPolicy{}, manager
	base := dispatchLinkTestContext("vless", email, "192.0.2.1")
	in := session.InboundFromContext(base)
	in.CanSpliceCopy = 1
	base = session.ContextWithOutbounds(base, []*session.Outbound{{CanSpliceCopy: 1}})
	ctx, cancel := context.WithTimeout(base, 2*time.Second)
	defer cancel()
	source, sourceClient := visionTCPPair(t)
	sink, sinkClient := visionTCPPair(t)
	link, err := d.wrapLink(ctx, &transport.Link{Reader: buf.NewReader(bytes.NewReader(nil)), Writer: buf.NewWriter(sink)})
	if err != nil {
		t.Fatal(err)
	}
	if in.CanSpliceCopy != 1 {
		t.Fatalf("speed field vetoed splice: %d", in.CanSpliceCopy)
	}
	sw := link.Writer.(*dispatcher.SizeStatWriter)
	w := &visionWriterCounter{Writer: sw.Writer}
	sw.Writer = w
	payload := bytes.Repeat([]byte{0x5a}, 4096)
	if _, err := sourceClient.Write(payload); err != nil {
		t.Fatal(err)
	}
	_ = sourceClient.CloseWrite()
	timer := signal.CancelAfterInactivity(ctx, cancel, 3*time.Second)
	defer timer.SetTimeout(0)
	if err := proxy.CopyRawConnIfExist(ctx, source, sink, link.Writer, timer, nil); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(sinkClient, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("forwarded payload changed")
	}
	if got := manager.GetCounter("user>>>" + email + ">>>traffic>>>downlink").Value(); got != int64(len(payload)) {
		t.Fatalf("user counter=%d, want %d", got, len(payload))
	}
	if runtime.GOOS == "linux" && w.calls != 0 {
		t.Fatalf("eligible copy used %d buffered writes", w.calls)
	}
}
