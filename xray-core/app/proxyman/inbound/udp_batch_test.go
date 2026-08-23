package inbound

import (
	"errors"
	"sync/atomic"
	"testing"

	"github.com/xtls/xray-core/common/buf"
)

type udpTestCounter struct {
	value atomic.Int64
}

func (c *udpTestCounter) Value() int64      { return c.value.Load() }
func (c *udpTestCounter) Set(v int64) int64 { return c.value.Swap(v) }
func (c *udpTestCounter) Add(v int64) int64 { return c.value.Add(v) - v }

func TestUDPConnBatchWritePreservesStats(t *testing.T) {
	counter := new(udpTestCounter)
	conn := &udpConn{
		downlink: counter,
		outputMulti: func(mb buf.MultiBuffer) (int64, error) {
			return int64(mb.Len()), nil
		},
	}
	mb := make(buf.MultiBuffer, 3)
	for i := range mb {
		mb[i] = buf.New()
		_, _ = mb[i].Write([]byte{1, 2, 3, 4})
	}
	if err := conn.WriteMultiBuffer(mb); err != nil {
		t.Fatal(err)
	}
	if got := counter.Value(); got != 12 {
		t.Fatalf("counter is %d, want 12", got)
	}
	for i, b := range mb {
		if b != nil {
			t.Fatalf("buffer %d was not released", i)
		}
	}
}

func TestUDPConnBatchWriteCountsPartialSuccess(t *testing.T) {
	counter := new(udpTestCounter)
	wantErr := errors.New("partial batch write")
	conn := &udpConn{
		downlink: counter,
		outputMulti: func(buf.MultiBuffer) (int64, error) {
			return 5, wantErr
		},
	}
	b := buf.New()
	_, _ = b.Write([]byte("payload"))
	if err := conn.WriteMultiBuffer(buf.MultiBuffer{b}); !errors.Is(err, wantErr) {
		t.Fatalf("error is %v, want %v", err, wantErr)
	}
	if got := counter.Value(); got != 5 {
		t.Fatalf("counter is %d, want 5", got)
	}
}
