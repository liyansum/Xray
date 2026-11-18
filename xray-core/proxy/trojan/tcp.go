package trojan

import (
	"context"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
)

// Ordinary Trojan must retain TLS processing, but does not need an intermediate
// pair of pipes and copy tasks between the TLS connection and the outbound.
func (s *Server) handleTCPConnection(ctx context.Context, plcy policy.Session, destination net.Destination, reader buf.Reader, writer buf.Writer, conn net.Conn, dispatcher routing.Dispatcher) error {
	ctx, cancel := context.WithCancel(ctx)
	timer := signal.CancelAfterInactivity(ctx, cancel, plcy.Timeouts.ConnectionIdle)
	// DispatchLink may be blocked in a TLS read when cancellation arrives. Wake
	// socket I/O as well as outbound tasks; join the callback before returning.
	interrupted := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		_ = conn.SetDeadline(time.Now())
		close(interrupted)
	})
	defer func() {
		if stop() {
			// Normal completion must leave writes usable for the TLS owner's
			// close_notify. Only a pending sniff/read needs waking here.
			_ = conn.SetReadDeadline(time.Now())
		} else {
			<-interrupted
		}
		cancel()
		timer.SetTimeout(0)
	}()
	ctx = policy.ContextWithBufferPolicy(ctx, plcy.Buffer)
	return dispatcher.DispatchLink(ctx, destination, &transport.Link{
		Reader: &tcpActivityReader{Reader: reader, timer: timer, timeout: plcy.Timeouts.DownlinkOnly, conn: conn},
		Writer: &tcpActivityWriter{Writer: writer, timer: timer, timeout: plcy.Timeouts.UplinkOnly, cancel: cancel},
	})
}

type tcpActivityReader struct {
	buf.Reader
	timer   *signal.ActivityTimer
	timeout time.Duration
	conn    net.Conn
	ended   bool
}

func (r *tcpActivityReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	mb, err := r.Reader.ReadMultiBuffer()
	if !mb.IsEmpty() {
		r.timer.Update()
	}
	if err != nil && !r.ended {
		r.ended = true
		r.timer.SetTimeout(r.timeout)
	}
	return mb, err
}

func (r *tcpActivityReader) Interrupt() {
	// Outbound handlers also interrupt the reader after successful completion.
	// Wake reads without expiring TLS writes needed for normal close_notify.
	_ = r.conn.SetReadDeadline(time.Now())
}

type tcpActivityWriter struct {
	buf.Writer
	timer   *signal.ActivityTimer
	timeout time.Duration
	cancel  context.CancelFunc
	once    sync.Once
}

func (w *tcpActivityWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	if !mb.IsEmpty() {
		w.timer.Update()
	}
	return w.Writer.WriteMultiBuffer(mb)
}

// An outbound EOF changes the remaining-direction timeout. It must not close
// the TLS socket while the client may still be uploading, just as the old pipe
// EOF left the underlying socket open until the entire inbound returned.
func (w *tcpActivityWriter) Close() error {
	w.once.Do(func() { w.timer.SetTimeout(w.timeout) })
	return nil
}

func (w *tcpActivityWriter) Interrupt() { w.cancel() }
