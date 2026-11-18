package mydispatcher

import (
	"context"
	stderrors "errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/stats"
)

type cacheEOFReader struct {
	mb    buf.MultiBuffer
	err   error
	calls int
	conn  net.Conn
}

func (r *cacheEOFReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	return r.ReadMultiBufferTimeout(0)
}
func (r *cacheEOFReader) ReadMultiBufferTimeout(time.Duration) (buf.MultiBuffer, error) {
	r.calls++
	if r.calls > 1 {
		return nil, io.EOF
	}
	return r.mb, r.err
}
func (r *cacheEOFReader) DirectReadConn() (net.Conn, stats.Counter) { return r.conn, nil }

func TestSniffCacheRetainsDataAndReadError(t *testing.T) {
	for _, terminal := range []error{io.EOF, io.ErrUnexpectedEOF, stderrors.New("read failure")} {
		t.Run(terminal.Error(), func(t *testing.T) {
			const payload = "HEAD / HTTP/1.1\r\nHost: example.com\r\n\r\n"
			source := &cacheEOFReader{mb: buf.MultiBuffer{buf.FromBytes([]byte(payload))}, err: terminal}
			reader := &cachedReader{reader: source}
			defer reader.Interrupt()
			preview := buf.New()
			defer preview.Release()
			if err := reader.Cache(preview, time.Second); err != nil {
				t.Fatalf("discarded data before sniffing: %v", err)
			}
			if string(preview.Bytes()) != payload {
				t.Fatal("incomplete sniff preview")
			}
			// No extra underlying read is allowed after the terminal error was seen.
			if err := reader.Cache(preview, time.Second); !stderrors.Is(err, terminal) || source.calls != 1 {
				t.Fatalf("lost pending error or reread source: %v / %d", err, source.calls)
			}
			mb, err := reader.ReadMultiBufferTimeout(time.Second)
			defer buf.ReleaseMulti(mb)
			if mb.String() != payload || !stderrors.Is(err, terminal) {
				t.Fatalf("forwarded (%q,%v)", mb.String(), err)
			}
		})
	}
}

func TestSnifferRecognizesFinalRequestBeforeEOF(t *testing.T) {
	const payload = "HEAD / HTTP/1.1\r\nHost: example.com\r\n\r\n"
	source := &cacheEOFReader{mb: buf.MultiBuffer{buf.FromBytes([]byte(payload))}, err: io.EOF}
	reader := &cachedReader{reader: source}
	defer reader.Interrupt()
	ctx := context.WithValue(context.Background(), core.XrayKey(1), new(core.Instance))
	ctx = session.ContextWithContent(ctx, new(session.Content))
	result, err := sniffer(ctx, reader, false, xnet.Network_TCP)
	if err != nil || result.Domain() != "example.com" {
		t.Fatalf("lost final request routing: %v / %v", result, err)
	}
	mb, err := reader.ReadMultiBuffer()
	defer buf.ReleaseMulti(mb)
	if mb.String() != payload || err != io.EOF {
		t.Fatal("lost payload or EOF after successful sniff")
	}
}

func TestSniffCacheErrorWithoutData(t *testing.T) {
	source := &cacheEOFReader{err: io.EOF}
	reader := &cachedReader{reader: source}
	preview := buf.New()
	defer preview.Release()
	if err := reader.Cache(preview, time.Second); err != io.EOF {
		t.Fatal(err)
	}
	if _, err := reader.ReadMultiBuffer(); err != io.EOF || source.calls != 1 {
		t.Fatal("lost EOF or reread failed source")
	}
}

type cacheBlockingEOFReader struct {
	started chan struct{}
	resume  chan struct{}
	batch   *buf.Buffer
}

func (r *cacheBlockingEOFReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	return r.ReadMultiBufferTimeout(0)
}
func (r *cacheBlockingEOFReader) ReadMultiBufferTimeout(time.Duration) (buf.MultiBuffer, error) {
	close(r.started)
	<-r.resume
	return buf.MultiBuffer{r.batch}, io.EOF
}

func TestSniffCacheInterruptReleasesLateFinalBatch(t *testing.T) {
	source := &cacheBlockingEOFReader{started: make(chan struct{}), resume: make(chan struct{}), batch: buf.New()}
	_, _ = source.batch.WriteString("late final data")
	reader := &cachedReader{reader: source}
	preview := buf.New()
	defer preview.Release()
	done := make(chan error, 1)
	go func() { done <- reader.Cache(preview, time.Second) }()
	<-source.started
	reader.Interrupt()
	close(source.resume)
	if err := <-done; err != io.ErrClosedPipe {
		t.Fatalf("read survived interruption: %v", err)
	}
	if !source.batch.IsEmpty() {
		t.Fatal("late batch was not released")
	}
	if _, err := reader.ReadMultiBuffer(); err != io.ErrClosedPipe {
		t.Fatal("cache resumed after interruption")
	}
}
