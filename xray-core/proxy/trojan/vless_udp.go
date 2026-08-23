package trojan

import (
	"io"
	"sync"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
)

// synchronizedVLESSWriter protects Vision's per-connection padding state when
// multiple Mux/XUDP sessions produce response frames concurrently.
type synchronizedVLESSWriter struct {
	mu     sync.Mutex
	writer buf.Writer
}

func (w *synchronizedVLESSWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.writer.WriteMultiBuffer(mb)
}

// vlessLengthPacketReader decodes the standard VLESS UDP body: one uint16
// big-endian payload length followed by one datagram. Large datagrams may span
// several internal buffers but remain one MultiBuffer packet for dispatch.
type vlessLengthPacketReader struct {
	reader io.Reader
	header [2]byte
}

func newVLESSLengthPacketReader(reader io.Reader) *vlessLengthPacketReader {
	return &vlessLengthPacketReader{reader: reader}
}

func (r *vlessLengthPacketReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	if _, err := io.ReadFull(r.reader, r.header[:]); err != nil {
		return nil, errors.New("failed to read VLESS UDP packet length").Base(err)
	}
	remaining := int32(r.header[0])<<8 | int32(r.header[1])
	if remaining == 0 {
		return nil, errors.New("empty VLESS UDP packet")
	}
	mb := make(buf.MultiBuffer, 0, remaining/buf.Size+1)
	for remaining > 0 {
		size := min(remaining, buf.Size)
		b := buf.New()
		if _, err := b.ReadFullFrom(r.reader, size); err != nil {
			b.Release()
			buf.ReleaseMulti(mb)
			return nil, errors.New("failed to read VLESS UDP packet payload").Base(err)
		}
		mb = append(mb, b)
		remaining -= size
	}
	return mb, nil
}

// vlessMultiLengthPacketWriter preserves packet boundaries and prefixes every
// outgoing datagram exactly as required by standard VLESS UDP clients.
type vlessMultiLengthPacketWriter struct {
	writer buf.Writer
}

func newVLESSMultiLengthPacketWriter(writer buf.Writer) *vlessMultiLengthPacketWriter {
	return &vlessMultiLengthPacketWriter{writer: writer}
}

func (w *vlessMultiLengthPacketWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	defer buf.ReleaseMulti(mb)
	framed := make(buf.MultiBuffer, 0, len(mb))
	for _, packet := range mb {
		length := packet.Len()
		if length == 0 || length+2 > buf.Size {
			continue
		}
		frame := buf.New()
		_ = frame.WriteByte(byte(length >> 8))
		_ = frame.WriteByte(byte(length))
		_, _ = frame.Write(packet.Bytes())
		framed = append(framed, frame)
	}
	if framed.IsEmpty() {
		return nil
	}
	if err := w.writer.WriteMultiBuffer(framed); err != nil {
		return errors.New("failed to write VLESS UDP packet").Base(err)
	}
	return nil
}
