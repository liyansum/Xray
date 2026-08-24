// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package trojan

import (
	"io"
	"os"
	"sync"
	"time"
)

// anyTLSSyncPipe is the single-direction, zero-queue pipe used by the official
// AnyTLS implementation. It avoids the second unused direction and redundant
// deadlines allocated by net.Pipe while preserving synchronous backpressure.
type anyTLSSyncPipe struct {
	writeMu sync.Mutex
	writeCh chan []byte
	readCh  chan int
	done    chan struct{}
	once    sync.Once

	readDeadline anyTLSDeadline
}

type anyTLSSyncPipeReader struct{ pipe *anyTLSSyncPipe }
type anyTLSSyncPipeWriter struct{ pipe *anyTLSSyncPipe }

func newAnyTLSSyncPipe() (*anyTLSSyncPipeReader, *anyTLSSyncPipeWriter) {
	pipe := &anyTLSSyncPipe{
		writeCh:      make(chan []byte),
		readCh:       make(chan int),
		done:         make(chan struct{}),
		readDeadline: newAnyTLSDeadline(),
	}
	return &anyTLSSyncPipeReader{pipe: pipe}, &anyTLSSyncPipeWriter{pipe: pipe}
}

func (r *anyTLSSyncPipeReader) Read(payload []byte) (int, error) {
	select {
	case <-r.pipe.done:
		return 0, io.ErrClosedPipe
	case <-r.pipe.readDeadline.wait():
		return 0, os.ErrDeadlineExceeded
	default:
	}

	select {
	case source := <-r.pipe.writeCh:
		read := copy(payload, source)
		r.pipe.readCh <- read
		return read, nil
	case <-r.pipe.done:
		return 0, io.ErrClosedPipe
	case <-r.pipe.readDeadline.wait():
		return 0, os.ErrDeadlineExceeded
	}
}

func (r *anyTLSSyncPipeReader) Close() error {
	r.pipe.once.Do(func() { close(r.pipe.done) })
	return nil
}

func (r *anyTLSSyncPipeReader) SetReadDeadline(deadline time.Time) error {
	if channelClosed(r.pipe.done) {
		return io.ErrClosedPipe
	}
	r.pipe.readDeadline.set(deadline)
	return nil
}

func (w *anyTLSSyncPipeWriter) Write(payload []byte) (int, error) {
	select {
	case <-w.pipe.done:
		return 0, io.ErrClosedPipe
	default:
	}

	w.pipe.writeMu.Lock()
	defer w.pipe.writeMu.Unlock()
	written := 0
	for first := true; first || len(payload) > 0; first = false {
		select {
		case w.pipe.writeCh <- payload:
			read := <-w.pipe.readCh
			payload = payload[read:]
			written += read
		case <-w.pipe.done:
			return written, io.ErrClosedPipe
		}
	}
	return written, nil
}
