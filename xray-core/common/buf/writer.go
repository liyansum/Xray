package buf

import (
	"io"
	"net"
	"sync"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/bytespool"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/features/stats"
)

const coalescedWritePoolSize = 32 * 1024

var coalescedWritePool = sync.Pool{New: func() any { return new([coalescedWritePoolSize]byte) }}

// BufferToBytesWriter is a Writer that writes alloc.Buffer into underlying writer.
type BufferToBytesWriter struct {
	io.Writer

	counter stats.Counter
	cache   [][]byte
}

// WriteMultiBufferCoalesced writes stream data in contiguous batches. It takes
// ownership of mb. The temporary batch buffer is borrowed only for the duration
// of this call, so idle connections do not retain per-connection memory.
func WriteMultiBufferCoalesced(writer io.Writer, mb MultiBuffer, batchSize int32) error {
	defer ReleaseMulti(mb)

	if mb.IsEmpty() {
		return nil
	}
	if batchSize <= 0 {
		return errors.New("invalid coalesced write batch size: ", batchSize)
	}

	// Avoid borrowing a larger scratch buffer when there is nothing to merge.
	if len(mb) == 1 {
		return WriteAllBytes(writer, mb[0].Bytes(), nil)
	}

	var pooledBatch *[coalescedWritePoolSize]byte
	var batch []byte
	if batchSize == coalescedWritePoolSize {
		pooledBatch = coalescedWritePool.Get().(*[coalescedWritePoolSize]byte)
		batch = pooledBatch[:]
	} else {
		batch = bytespool.Alloc(batchSize)[:batchSize]
	}
	defer func() {
		if pooledBatch != nil {
			coalescedWritePool.Put(pooledBatch)
		} else {
			bytespool.Free(batch)
		}
	}()

	used := 0
	for _, b := range mb {
		payload := b.Bytes()
		for len(payload) > 0 {
			n := min(len(payload), len(batch)-used)
			copy(batch[used:], payload[:n])
			used += n
			payload = payload[n:]
			if used == len(batch) {
				if err := WriteAllBytes(writer, batch, nil); err != nil {
					return err
				}
				used = 0
			}
		}
	}

	if used != 0 {
		return WriteAllBytes(writer, batch[:used], nil)
	}
	return nil
}

// WriteMultiBuffer implements Writer. This method takes ownership of the given buffer.
func (w *BufferToBytesWriter) WriteMultiBuffer(mb MultiBuffer) error {
	defer ReleaseMulti(mb)

	size := mb.Len()
	if size == 0 {
		return nil
	}

	if len(mb) == 1 {
		return WriteAllBytes(w.Writer, mb[0].Bytes(), w.counter)
	}

	if cap(w.cache) < len(mb) {
		w.cache = make([][]byte, 0, len(mb))
	}

	bs := w.cache
	for _, b := range mb {
		bs = append(bs, b.Bytes())
	}

	defer func() {
		for idx := range bs {
			bs[idx] = nil
		}
	}()

	nb := net.Buffers(bs)
	wc := int64(0)
	defer func() {
		if w.counter != nil {
			w.counter.Add(wc)
		}
	}()
	for size > 0 {
		n, err := nb.WriteTo(w.Writer)
		wc += n
		if err != nil {
			return err
		}
		size -= int32(n)
	}

	return nil
}

// ReadFrom implements io.ReaderFrom.
func (w *BufferToBytesWriter) ReadFrom(reader io.Reader) (int64, error) {
	var sc SizeCounter
	err := Copy(NewReader(reader), w, CountSize(&sc))
	return sc.Size, err
}

// BufferedWriter is a Writer with internal buffer.
type BufferedWriter struct {
	sync.Mutex
	writer    Writer
	buffer    *Buffer
	buffered  bool
	flushNext bool
}

// NewBufferedWriter creates a new BufferedWriter.
func NewBufferedWriter(writer Writer) *BufferedWriter {
	return &BufferedWriter{
		writer:   writer,
		buffer:   New(),
		buffered: true,
	}
}

// WriteByte implements io.ByteWriter.
func (w *BufferedWriter) WriteByte(c byte) error {
	return common.Error2(w.Write([]byte{c}))
}

// Write implements io.Writer.
func (w *BufferedWriter) Write(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}

	w.Lock()
	defer w.Unlock()

	if !w.buffered {
		if writer, ok := w.writer.(io.Writer); ok {
			return writer.Write(b)
		}
	}

	totalBytes := 0
	for len(b) > 0 {
		if w.buffer == nil {
			w.buffer = New()
		}

		nBytes, err := w.buffer.Write(b)
		totalBytes += nBytes
		if err != nil {
			return totalBytes, err
		}
		if !w.buffered || w.buffer.IsFull() {
			if err := w.flushInternal(); err != nil {
				return totalBytes, err
			}
		}
		b = b[nBytes:]
	}

	return totalBytes, nil
}

// WriteMultiBuffer implements Writer. It takes ownership of the given MultiBuffer.
func (w *BufferedWriter) WriteMultiBuffer(b MultiBuffer) error {
	if b.IsEmpty() {
		return nil
	}

	w.Lock()
	defer w.Unlock()

	if !w.buffered {
		return w.writer.WriteMultiBuffer(b)
	}

	reader := MultiBufferContainer{
		MultiBuffer: b,
	}
	defer reader.Close()

	for !reader.MultiBuffer.IsEmpty() {
		if w.buffer == nil {
			w.buffer = New()
		}
		common.Must2(w.buffer.ReadFrom(&reader))
		if w.buffer.IsFull() {
			if err := w.flushInternal(); err != nil {
				return err
			}
		}
	}

	if w.flushNext {
		w.buffered = false
		w.flushNext = false
		return w.flushInternal()
	}

	return nil
}

// Flush flushes buffered content into underlying writer.
func (w *BufferedWriter) Flush() error {
	w.Lock()
	defer w.Unlock()

	return w.flushInternal()
}

func (w *BufferedWriter) flushInternal() error {
	if w.buffer.IsEmpty() {
		return nil
	}

	b := w.buffer
	w.buffer = nil

	if writer, ok := w.writer.(io.Writer); ok {
		err := WriteAllBytes(writer, b.Bytes(), nil)
		b.Release()
		return err
	}

	return w.writer.WriteMultiBuffer(MultiBuffer{b})
}

// SetBuffered sets whether the internal buffer is used. If set to false, Flush() will be called to clear the buffer.
func (w *BufferedWriter) SetBuffered(f bool) error {
	w.Lock()
	defer w.Unlock()

	w.buffered = f
	if !f {
		return w.flushInternal()
	}
	return nil
}

// SetFlushNext will wait the next WriteMultiBuffer to flush and set buffered = false
func (w *BufferedWriter) SetFlushNext() {
	w.Lock()
	defer w.Unlock()
	w.flushNext = true
}

// ReadFrom implements io.ReaderFrom.
func (w *BufferedWriter) ReadFrom(reader io.Reader) (int64, error) {
	if err := w.SetBuffered(false); err != nil {
		return 0, err
	}

	var sc SizeCounter
	err := Copy(NewReader(reader), w, CountSize(&sc))
	return sc.Size, err
}

// Close implements io.Closable.
func (w *BufferedWriter) Close() error {
	if err := w.Flush(); err != nil {
		return err
	}
	return common.Close(w.writer)
}

// SequentialWriter is a Writer that writes MultiBuffer sequentially into the underlying io.Writer.
type SequentialWriter struct {
	io.Writer
}

// multiBufferBatchWriter marks stream writers that benefit from contiguous
// MultiBuffer writes. Wrapped writers, such as traffic counters, use the batch
// size while keeping writes on the outer wrapper.
type multiBufferBatchWriter interface {
	Writer
	MultiBufferBatchSize() int32
}

type coalescingWriter struct {
	io.Writer
	batchSize int32
}

func (w *coalescingWriter) WriteMultiBuffer(mb MultiBuffer) error {
	return WriteMultiBufferCoalesced(w.Writer, mb, w.batchSize)
}

// WriteMultiBuffer implements Writer.
func (w *SequentialWriter) WriteMultiBuffer(mb MultiBuffer) error {
	mb, err := WriteMultiBuffer(w.Writer, mb)
	ReleaseMulti(mb)
	return err
}

type noOpWriter byte

func (noOpWriter) WriteMultiBuffer(b MultiBuffer) error {
	ReleaseMulti(b)
	return nil
}

func (noOpWriter) Write(b []byte) (int, error) {
	return len(b), nil
}

func (noOpWriter) ReadFrom(reader io.Reader) (int64, error) {
	b := New()
	defer b.Release()

	totalBytes := int64(0)
	for {
		b.Clear()
		_, err := b.ReadFrom(reader)
		totalBytes += int64(b.Len())
		if err != nil {
			if errors.Cause(err) == io.EOF {
				return totalBytes, nil
			}
			return totalBytes, err
		}
	}
}

var (
	// Discard is a Writer that swallows all contents written in.
	Discard Writer = noOpWriter(0)

	// DiscardBytes is an io.Writer that swallows all contents written in.
	DiscardBytes io.Writer = noOpWriter(0)
)
