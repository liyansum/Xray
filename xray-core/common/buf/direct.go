package buf

import (
	"net"

	"github.com/xtls/xray-core/features/stats"
)

// DirectReader exposes a raw stream only after all protocol and prefetched
// bytes have been returned by ReadMultiBuffer. Call it from the reading goroutine,
// after forwarding the previous MultiBuffer. The counter accounts for user data.
type DirectReader interface {
	DirectReadConn() (net.Conn, stats.Counter)
}

// DirectWriter exposes a raw stream after its protocol transition was flushed.
// Call it only from the writing goroutine, between WriteMultiBuffer calls.
type DirectWriter interface {
	DirectWriteConn() (net.Conn, stats.Counter)
}

func (r *TimeoutWrapperReader) DirectReadConn() (net.Conn, stats.Counter) {
	// A timed-out sniff can still own an outstanding asynchronous read. Even
	// when it has completed, its result must be delivered before bypassing it.
	if r.done != nil {
		return nil, nil
	}
	if direct, ok := r.Reader.(DirectReader); ok {
		conn, counter := direct.DirectReadConn()
		if r.Counter != nil {
			counter = r.Counter
		}
		return conn, counter
	}
	return nil, nil
}
