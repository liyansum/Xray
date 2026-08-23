package singbridge

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	B "github.com/sagernet/sing/common/buf"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/signal"
)

type packetReadResult struct {
	mb  buf.MultiBuffer
	err error
}

type packetTestReader struct {
	results []packetReadResult
	calls   int
}

func (r *packetTestReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	if r.calls >= len(r.results) {
		r.calls++
		return nil, io.EOF
	}
	result := r.results[r.calls]
	r.calls++
	return result.mb, result.err
}

func newPacketTestWrapper(reader buf.Reader) *PacketConnWrapper {
	return &PacketConnWrapper{
		Reader: reader,
		Dest:   net.UDPDestination(net.DomainAddress("example.com"), 53),
		T:      signal.CancelAfterInactivity(context.Background(), func() {}, time.Hour),
	}
}

func TestPacketConnWrapperReadPacketPropagatesError(t *testing.T) {
	reader := &packetTestReader{results: []packetReadResult{{err: io.EOF}}}
	wrapper := newPacketTestWrapper(reader)
	defer wrapper.Close()

	packet := B.New()
	defer packet.Release()
	if _, err := wrapper.ReadPacket(packet); !errors.Is(err, io.EOF) {
		t.Fatalf("ReadPacket() error = %v, want EOF", err)
	}
}

func TestPacketConnWrapperReadPacketRejectsNoProgress(t *testing.T) {
	reader := &packetTestReader{results: []packetReadResult{{}}}
	wrapper := newPacketTestWrapper(reader)
	defer wrapper.Close()

	packet := B.New()
	defer packet.Release()
	if _, err := wrapper.ReadPacket(packet); !errors.Is(err, io.ErrNoProgress) {
		t.Fatalf("ReadPacket() error = %v, want ErrNoProgress", err)
	}
}

func TestPacketConnWrapperDefersErrorUntilBufferedPacketsAreRead(t *testing.T) {
	first := buf.New()
	second := buf.New()
	_, _ = first.Write([]byte("first"))
	_, _ = second.Write([]byte("second"))
	reader := &packetTestReader{results: []packetReadResult{{
		mb:  buf.MultiBuffer{first, second},
		err: io.EOF,
	}}}
	wrapper := newPacketTestWrapper(reader)
	defer wrapper.Close()

	for _, want := range []string{"first", "second"} {
		packet := B.New()
		if _, err := wrapper.ReadPacket(packet); err != nil {
			packet.Release()
			t.Fatalf("ReadPacket() error while draining data = %v", err)
		}
		if got := string(packet.Bytes()); got != want {
			packet.Release()
			t.Fatalf("ReadPacket() payload = %q, want %q", got, want)
		}
		packet.Release()
	}

	packet := B.New()
	defer packet.Release()
	if _, err := wrapper.ReadPacket(packet); !errors.Is(err, io.EOF) {
		t.Fatalf("ReadPacket() trailing error = %v, want EOF", err)
	}
	if reader.calls != 1 {
		t.Fatalf("ReadMultiBuffer() calls = %d, want 1", reader.calls)
	}
}

func TestPacketConnWrapperCloseStopsTimer(t *testing.T) {
	timedOut := make(chan struct{})
	wrapper := &PacketConnWrapper{
		T: signal.CancelAfterInactivity(context.Background(), func() {
			close(timedOut)
		}, time.Hour),
	}

	if err := wrapper.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	select {
	case <-timedOut:
	default:
		t.Fatal("Close() did not stop the activity timer")
	}
}
