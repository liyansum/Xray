package mydispatcher

import (
	"io"
	"net"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common/buf"
	statsFeature "github.com/xtls/xray-core/features/stats"
)

type pendingDirectReader struct {
	result chan buf.MultiBuffer
	conn   net.Conn
	probes int
}

func (r *pendingDirectReader) ReadMultiBuffer() (buf.MultiBuffer, error) { return <-r.result, nil }
func (r *pendingDirectReader) DirectReadConn() (net.Conn, statsFeature.Counter) {
	r.probes++
	return r.conn, nil
}

func TestDirectReaderDrainsSniffCacheAndPendingRead(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	underlying := &pendingDirectReader{result: make(chan buf.MultiBuffer, 1), conn: a}
	counter := new(stats.Counter)
	wrapper := &buf.TimeoutWrapperReader{Reader: underlying, Counter: counter}
	reader := &cachedReader{reader: wrapper, cache: buf.MultiBuffer{buf.FromBytes([]byte("cached"))}}
	if conn, _ := reader.DirectReadConn(); conn != nil {
		t.Fatal("bypassed sniff cache")
	}
	mb, err := reader.ReadMultiBuffer()
	if err != nil || string(mb[0].Bytes()) != "cached" {
		t.Fatal("lost cached payload")
	}
	buf.ReleaseMulti(mb)
	if _, err := reader.ReadMultiBufferTimeout(time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if conn, _ := reader.DirectReadConn(); conn != nil || underlying.probes != 0 {
		t.Fatal("bypassed outstanding sniff read")
	}
	underlying.result <- buf.MultiBuffer{buf.FromBytes([]byte("pending"))}
	mb, err = reader.ReadMultiBuffer()
	if err != nil || string(mb[0].Bytes()) != "pending" {
		t.Fatal("lost pending payload")
	}
	buf.ReleaseMulti(mb)
	conn, c := reader.DirectReadConn()
	if conn != a || c != counter || counter.Value() != 7 {
		t.Fatal("direct readiness or accounting was lost")
	}
}

func TestDirectReaderCannotBypassPendingTerminalError(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	source := &cacheEOFReader{conn: a, err: io.EOF}
	reader := &cachedReader{reader: source}
	preview := buf.New()
	defer preview.Release()
	if err := reader.Cache(preview, time.Second); err != io.EOF {
		t.Fatal(err)
	}
	if conn, _ := reader.DirectReadConn(); conn != nil {
		t.Fatal("raw copy bypassed pending EOF")
	}
	reader.Interrupt()
	if conn, _ := reader.DirectReadConn(); conn != nil {
		t.Fatal("raw copy bypassed interruption")
	}
}
