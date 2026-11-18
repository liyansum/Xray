package mux_test

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/mux"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
)

type packetBatchSink struct {
	bytes.Buffer
	calls    int
	maxBytes int32
	failAt   int
}

func (s *packetBatchSink) WriteMultiBuffer(mb buf.MultiBuffer) error {
	defer buf.ReleaseMulti(mb)
	s.calls++
	s.maxBytes = max(s.maxBytes, mb.Len())
	if s.calls == s.failAt {
		return io.ErrClosedPipe
	}
	for _, b := range mb {
		s.Write(b.Bytes())
	}
	return nil
}

func batchPackets(n int) buf.MultiBuffer {
	mb := make(buf.MultiBuffer, 0, n)
	for i := range n {
		// Include opaque QUIC-like payloads and a changing per-packet target.
		payload := bytes.Repeat([]byte{0xc0, byte(i), 0, 1}, 300)
		b := buf.New()
		b.Write(payload)
		dest := net.UDPDestination(net.ParseAddress("2001:db8::1"), net.Port(4000+i))
		b.UDP = &dest
		mb = append(mb, b)
	}
	return mb
}

func TestPacketBatchWireEquivalentAndBounded(t *testing.T) {
	const count = 100
	dest := net.UDPDestination(net.DomainAddress("example.com"), 443)
	id := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	separate, batched := new(packetBatchSink), new(packetBatchSink)
	a := mux.NewWriter(42, dest, separate, protocol.TransferTypePacket, id, nil)
	b := mux.NewWriter(42, dest, batched, protocol.TransferTypePacket, id, nil)
	for _, packet := range batchPackets(count) {
		if err := a.WriteMultiBuffer(buf.MultiBuffer{packet}); err != nil {
			t.Fatal(err)
		}
	}
	if err := b.WriteMultiBuffer(batchPackets(count)); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(separate.Bytes(), batched.Bytes()) {
		t.Fatal("batching changed Mux/XUDP wire bytes")
	}
	if batched.calls >= 10 || batched.maxBytes > 32768 {
		t.Fatalf("writes=%d max=%d", batched.calls, batched.maxBytes)
	}
	// Decode through deliberately tiny reads to exercise transport fragmentation.
	reader := &shortPacketReader{reader: bytes.NewReader(batched.Bytes())}
	for i := range count {
		var meta mux.FrameMetadata
		if err := meta.Unmarshal(reader, false); err != nil {
			t.Fatal(err)
		}
		if meta.SessionID != 42 || !meta.Option.Has(mux.OptionData) {
			t.Fatalf("frame %d: %+v", i, meta)
		}
		if i == 0 {
			if meta.SessionStatus != mux.SessionStatusNew || meta.GlobalID != id || meta.Target != dest {
				t.Fatalf("initial metadata: %+v", meta)
			}
		} else if meta.SessionStatus != mux.SessionStatusKeep || meta.Target.Port != net.Port(4000+i) {
			t.Fatalf("packet %d lost its destination: %+v", i, meta)
		}
		mb, err := mux.NewPacketReader(reader, &meta.Target).ReadMultiBuffer()
		if err != nil {
			t.Fatal(err)
		}
		want := bytes.Repeat([]byte{0xc0, byte(i), 0, 1}, 300)
		if len(mb) != 1 || !bytes.Equal(mb[0].Bytes(), want) {
			t.Fatalf("packet %d boundary/payload changed", i)
		}
		buf.ReleaseMulti(mb)
	}
	var meta mux.FrameMetadata
	if err := meta.Unmarshal(reader, false); !errors.Is(err, io.EOF) {
		t.Fatalf("extra frame: %v", err)
	}
	t.Logf("100 UDP packets: %d -> %d outer writes, largest batch %d bytes", separate.calls, batched.calls, batched.maxBytes)
}

type shortPacketReader struct{ reader io.Reader }

func (r *shortPacketReader) Read(p []byte) (int, error) { return r.reader.Read(p[:min(len(p), 3)]) }

func TestPacketBatchWriteFailureReleasesUnsentBuffers(t *testing.T) {
	packets := batchPackets(100)
	refs := append(buf.MultiBuffer(nil), packets...)
	sink := &packetBatchSink{failAt: 2}
	w := mux.NewResponseWriter(7, sink, protocol.TransferTypePacket)
	if err := w.WriteMultiBuffer(packets); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("write error: %v", err)
	}
	for i, b := range refs {
		if b.Bytes() != nil {
			t.Fatalf("packet %d leaked after error", i)
		}
	}
}

func TestSmallPacketBatchBoundsFrameCount(t *testing.T) {
	mb := make(buf.MultiBuffer, 1024)
	for i := range mb {
		mb[i] = buf.FromBytes([]byte{byte(i)})
	}
	sink := new(packetBatchSink)
	w := mux.NewResponseWriter(1, sink, protocol.TransferTypePacket)
	if err := w.WriteMultiBuffer(mb); err != nil {
		t.Fatal(err)
	}
	if sink.calls != 32 {
		t.Fatalf("writes=%d, want bounded groups of 32 frames", sink.calls)
	}
}

func BenchmarkPacketBatch(b *testing.B) {
	for b.Loop() {
		w := mux.NewResponseWriter(1, buf.Discard, protocol.TransferTypePacket)
		if err := w.WriteMultiBuffer(batchPackets(100)); err != nil {
			b.Fatal(err)
		}
	}
}
