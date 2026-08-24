package limiter

import (
	"context"
	"fmt"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"golang.org/x/time/rate"
)

type Writer struct {
	writer  buf.Writer
	limiter *rate.Limiter
	ctx     context.Context
}

type Reader struct {
	reader     buf.Reader
	limiter    *rate.Limiter
	ctx        context.Context
	pending    buf.MultiBuffer
	pendingErr error
}

type PacketReader struct {
	reader  buf.Reader
	limiter *rate.Limiter
	ctx     context.Context
}

type PacketWriter struct {
	writer  buf.Writer
	limiter *rate.Limiter
	ctx     context.Context
}

func limiterChunkSize(limiter *rate.Limiter) (int32, error) {
	burst := limiter.Burst()
	if burst <= 0 {
		return 0, fmt.Errorf("rate limiter burst must be positive")
	}
	if burst > int(^uint32(0)>>1) {
		return int32(^uint32(0) >> 1), nil
	}
	return int32(burst), nil
}

func (l *Limiter) RateWriter(ctx context.Context, writer buf.Writer, limiter *rate.Limiter) buf.Writer {
	if ctx == nil {
		ctx = context.Background()
	}
	return &Writer{
		writer:  writer,
		limiter: limiter,
		ctx:     ctx,
	}
}

func (l *Limiter) RateReader(ctx context.Context, reader buf.Reader, limiter *rate.Limiter) buf.Reader {
	if ctx == nil {
		ctx = context.Background()
	}
	return &Reader{
		reader:  reader,
		limiter: limiter,
		ctx:     ctx,
	}
}

// RatePacketReader limits bytes while preserving the invariant that every
// Buffer is one UDP datagram. A datagram may be larger than the limiter burst;
// tokens are then acquired in chunks before the intact packet is returned.
func (l *Limiter) RatePacketReader(ctx context.Context, reader buf.Reader, limiter *rate.Limiter) buf.Reader {
	if ctx == nil {
		ctx = context.Background()
	}
	return &PacketReader{reader: reader, limiter: limiter, ctx: ctx}
}

// RatePacketWriter is the packet-preserving counterpart of RateWriter.
func (l *Limiter) RatePacketWriter(ctx context.Context, writer buf.Writer, limiter *rate.Limiter) buf.Writer {
	if ctx == nil {
		ctx = context.Background()
	}
	return &PacketWriter{writer: writer, limiter: limiter, ctx: ctx}
}

func waitBytes(ctx context.Context, limiter *rate.Limiter, size int32) error {
	chunkSize, err := limiterChunkSize(limiter)
	if err != nil {
		return err
	}
	for size > 0 {
		chunk := min(size, chunkSize)
		if err := limiter.WaitN(ctx, int(chunk)); err != nil {
			return err
		}
		size -= chunk
	}
	return nil
}

func (r *PacketReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	mb, err := r.reader.ReadMultiBuffer()
	if mb.IsEmpty() {
		return mb, err
	}
	if waitErr := waitBytes(r.ctx, r.limiter, mb.Len()); waitErr != nil {
		buf.ReleaseMulti(mb)
		return nil, waitErr
	}
	return mb, err
}

func (r *PacketReader) Close() error { return common.Close(r.reader) }

func (r *PacketReader) Interrupt() { common.Interrupt(r.reader) }

func (w *PacketWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	if waitErr := waitBytes(w.ctx, w.limiter, mb.Len()); waitErr != nil {
		buf.ReleaseMulti(mb)
		return waitErr
	}
	return w.writer.WriteMultiBuffer(mb)
}

func (w *PacketWriter) Close() error { return common.Close(w.writer) }

func (r *Reader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	mb := r.pending
	err := r.pendingErr
	r.pending = nil
	r.pendingErr = nil
	if mb.IsEmpty() {
		mb, err = r.reader.ReadMultiBuffer()
	}
	if mb.IsEmpty() {
		return mb, err
	}

	chunkSize, chunkErr := limiterChunkSize(r.limiter)
	if chunkErr != nil {
		buf.ReleaseMulti(mb)
		return nil, chunkErr
	}
	remaining, chunk := buf.SplitSize(mb, chunkSize)
	if !remaining.IsEmpty() {
		r.pending = remaining
		r.pendingErr = err
		err = nil
	}
	if waitErr := r.limiter.WaitN(r.ctx, int(chunk.Len())); waitErr != nil {
		buf.ReleaseMulti(chunk)
		buf.ReleaseMulti(r.pending)
		r.pending = nil
		r.pendingErr = nil
		return nil, waitErr
	}
	return chunk, err
}

func (r *Reader) Close() error {
	buf.ReleaseMulti(r.pending)
	r.pending = nil
	r.pendingErr = nil
	return common.Close(r.reader)
}

func (r *Reader) Interrupt() {
	buf.ReleaseMulti(r.pending)
	r.pending = nil
	r.pendingErr = nil
	common.Interrupt(r.reader)
}

func (w *Writer) Close() error {
	return common.Close(w.writer)
}

func (w *Writer) WriteMultiBuffer(mb buf.MultiBuffer) error {
	for !mb.IsEmpty() {
		chunkSize, err := limiterChunkSize(w.limiter)
		if err != nil {
			buf.ReleaseMulti(mb)
			return err
		}
		remaining, chunk := buf.SplitSize(mb, chunkSize)
		mb = remaining
		if err := w.limiter.WaitN(w.ctx, int(chunk.Len())); err != nil {
			buf.ReleaseMulti(chunk)
			buf.ReleaseMulti(mb)
			return err
		}
		if err := w.writer.WriteMultiBuffer(chunk); err != nil {
			buf.ReleaseMulti(mb)
			return err
		}
	}
	return nil
}
