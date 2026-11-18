package mux

import (
	"bytes"
	"context"
	"io"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
)

type muxFinalReader struct{}

func (muxFinalReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	return buf.MultiBuffer{buf.FromBytes([]byte("final-payload"))}, io.EOF
}
func (r muxFinalReader) ReadMultiBufferTimeout(time.Duration) (buf.MultiBuffer, error) {
	return r.ReadMultiBuffer()
}

func TestFetchInputFinalPayloadClosesWithoutErrorFlag(t *testing.T) {
	manager := NewSessionManager()
	s := manager.Allocate(&ClientStrategy{})
	s.input = muxFinalReader{}
	s.output = buf.Discard
	var wire bytes.Buffer
	destination := net.TCPDestination(net.DomainAddress("example.com"), 443)
	ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{Target: destination}})
	fetchInput(ctx, s, buf.NewWriter(&wire))
	reader := bytes.NewReader(wire.Bytes())
	var first FrameMetadata
	if err := first.Unmarshal(reader, false); err != nil {
		t.Fatal(err)
	}
	if first.SessionStatus != SessionStatusNew || !first.Option.Has(OptionData) || first.Option.Has(OptionError) || first.Target != destination {
		t.Fatalf("incorrect first frame: %+v", first)
	}
	var size [2]byte
	if _, err := io.ReadFull(reader, size[:]); err != nil {
		t.Fatal(err)
	}
	length := int(size[0])<<8 | int(size[1])
	data := make([]byte, length)
	if _, err := io.ReadFull(reader, data); err != nil || string(data) != "final-payload" {
		t.Fatalf("lost final frame: %q / %v", data, err)
	}
	var end FrameMetadata
	if err := end.Unmarshal(reader, false); err != nil {
		t.Fatal(err)
	}
	if end.SessionStatus != SessionStatusEnd || end.Option.Has(OptionError) {
		t.Fatalf("EOF marked as failed Mux session: %+v", end)
	}
}

type firstWriteEOF struct {
	wire  bytes.Buffer
	calls int
}

func (w *firstWriteEOF) WriteMultiBuffer(mb buf.MultiBuffer) error {
	w.calls++
	if w.calls == 1 {
		buf.ReleaseMulti(mb)
		return io.EOF
	}
	return buf.NewWriter(&w.wire).WriteMultiBuffer(mb)
}

func TestFetchInputWriteEOFStillSetsErrorFlag(t *testing.T) {
	manager := NewSessionManager()
	s := manager.Allocate(&ClientStrategy{})
	s.input = muxFinalReader{}
	s.output = buf.Discard
	output := new(firstWriteEOF)
	ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{Target: net.TCPDestination(net.DomainAddress("example.com"), 443)}})
	fetchInput(ctx, s, output)
	var end FrameMetadata
	if err := end.Unmarshal(bytes.NewReader(output.wire.Bytes()), false); err != nil {
		t.Fatal(err)
	}
	if end.SessionStatus != SessionStatusEnd || !end.Option.Has(OptionError) {
		t.Fatalf("write EOF was treated as normal read EOF: %+v", end)
	}
}
