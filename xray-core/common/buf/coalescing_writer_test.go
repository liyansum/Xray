package buf

import (
	"bytes"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/xtls/xray-core/transport/internet/stat"
)

type testCounter int64

func (c *testCounter) Value() int64      { return int64(*c) }
func (c *testCounter) Set(v int64) int64 { old := *c; *c = testCounter(v); return int64(old) }
func (c *testCounter) Add(v int64) int64 { old := *c; *c += testCounter(v); return int64(old) }

type testBatchConn struct {
	bytes.Buffer
	batchSize int32
	maxWrite  int
	failAfter int
	written   int
	writes    []int
}

func (c *testBatchConn) Write(p []byte) (int, error) {
	if c.failAfter > 0 && c.written >= c.failAfter {
		return 0, errors.New("forced write failure")
	}
	if c.maxWrite > 0 && len(p) > c.maxWrite {
		p = p[:c.maxWrite]
	}
	n, err := c.Buffer.Write(p)
	c.written += n
	c.writes = append(c.writes, n)
	return n, err
}

func (c *testBatchConn) WriteMultiBuffer(mb MultiBuffer) error {
	return WriteMultiBufferCoalesced(c, mb, c.batchSize)
}

func (c *testBatchConn) MultiBufferBatchSize() int32      { return c.batchSize }
func (c *testBatchConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (c *testBatchConn) Close() error                     { return nil }
func (c *testBatchConn) LocalAddr() net.Addr              { return testAddr("local") }
func (c *testBatchConn) RemoteAddr() net.Addr             { return testAddr("remote") }
func (c *testBatchConn) SetDeadline(time.Time) error      { return nil }
func (c *testBatchConn) SetReadDeadline(time.Time) error  { return nil }
func (c *testBatchConn) SetWriteDeadline(time.Time) error { return nil }

type testAddr string

func (a testAddr) Network() string { return string(a) }
func (a testAddr) String() string  { return string(a) }

func testMultiBuffer(t *testing.T, sizes ...int) (MultiBuffer, []byte) {
	t.Helper()
	var mb MultiBuffer
	var want []byte
	value := byte(0)
	for _, size := range sizes {
		b := NewWithSize(int32(size))
		payload := b.Extend(int32(size))
		for i := range payload {
			payload[i] = value
			value++
		}
		mb = append(mb, b)
		want = append(want, payload...)
	}
	return mb, want
}

func TestWriteMultiBufferCoalesced(t *testing.T) {
	mb, want := testMultiBuffer(t, Size, Size, Size, Size, Size)
	owned := append(MultiBuffer(nil), mb...)
	conn := &testBatchConn{batchSize: 32 * 1024}

	if err := WriteMultiBufferCoalesced(conn, mb, conn.batchSize); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(conn.Bytes(), want) {
		t.Fatal("coalesced payload differs from input")
	}
	if got, wantWrites := conn.writes, []int{32 * 1024, 8 * 1024}; !slicesEqual(got, wantWrites) {
		t.Fatalf("unexpected writes: got %v, want %v", got, wantWrites)
	}
	for _, b := range owned {
		if b.v != nil {
			t.Fatal("input buffer was not released")
		}
	}
}

func TestCoalescingWriterPreservesCounterAndPartialWrites(t *testing.T) {
	conn := &testBatchConn{batchSize: 32 * 1024, maxWrite: 3000}
	var counter testCounter
	statConn := &stat.CounterConnection{Connection: conn, WriteCounter: &counter}
	writer := NewWriter(statConn)
	if _, ok := writer.(*coalescingWriter); !ok {
		t.Fatalf("unexpected writer type %T", writer)
	}

	mb, want := testMultiBuffer(t, Size, Size, Size, Size)
	if err := writer.WriteMultiBuffer(mb); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(conn.Bytes(), want) {
		t.Fatal("partial-write payload differs from input")
	}
	if got := counter.Value(); got != int64(len(want)) {
		t.Fatalf("counter = %d, want %d", got, len(want))
	}
	if len(conn.writes) <= 1 {
		t.Fatal("partial-write test did not perform multiple writes")
	}
}

func TestWriteMultiBufferCoalescedReleasesOnError(t *testing.T) {
	conn := &testBatchConn{batchSize: 16 * 1024, maxWrite: 4096, failAfter: 4096}
	mb, _ := testMultiBuffer(t, Size, Size, Size)
	owned := append(MultiBuffer(nil), mb...)

	if err := WriteMultiBufferCoalesced(conn, mb, conn.batchSize); err == nil {
		t.Fatal("expected write error")
	}
	for _, b := range owned {
		if b.v != nil {
			t.Fatal("input buffer was not released after error")
		}
	}
}

func slicesEqual(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

type discardBatchWriter struct{}

func (discardBatchWriter) Write(p []byte) (int, error) { return len(p), nil }

func BenchmarkWriteMultiBufferCoalesced32K(b *testing.B) {
	payloads := make([]*Buffer, 8)
	for i := range payloads {
		payloads[i] = FromBytes(make([]byte, Size))
	}
	w := discardBatchWriter{}
	b.SetBytes(8 * Size)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		mb := MultiBuffer{payloads[0], payloads[1], payloads[2], payloads[3], payloads[4], payloads[5], payloads[6], payloads[7]}
		if err := WriteMultiBufferCoalesced(w, mb, 32*1024); err != nil {
			b.Fatal(err)
		}
	}
}
