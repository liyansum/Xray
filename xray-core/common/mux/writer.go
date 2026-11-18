package mux

import (
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
)

type Writer struct {
	dest         net.Destination
	writer       buf.Writer
	id           uint16
	followup     bool
	hasError     bool
	transferType protocol.TransferType
	globalID     [8]byte
	inbound      *session.Inbound
}

func NewWriter(id uint16, dest net.Destination, writer buf.Writer, transferType protocol.TransferType, globalID [8]byte, inbound *session.Inbound) *Writer {
	return &Writer{
		id:           id,
		dest:         dest,
		writer:       writer,
		followup:     false,
		transferType: transferType,
		globalID:     globalID,
		inbound:      inbound,
	}
}

func NewResponseWriter(id uint16, writer buf.Writer, transferType protocol.TransferType) *Writer {
	return &Writer{
		id:           id,
		writer:       writer,
		followup:     true,
		transferType: transferType,
	}
}

func (w *Writer) getNextFrameMeta() FrameMetadata {
	meta := FrameMetadata{
		SessionID: w.id,
		Target:    w.dest,
		GlobalID:  w.globalID,
		Inbound:   w.inbound,
	}

	if w.followup {
		meta.SessionStatus = SessionStatusKeep
	} else {
		w.followup = true
		meta.SessionStatus = SessionStatusNew
	}

	return meta
}

func (w *Writer) writeMetaOnly() error {
	meta := w.getNextFrameMeta()
	b := buf.New()
	if err := meta.WriteTo(b); err != nil {
		b.Release()
		return err
	}
	return w.writer.WriteMultiBuffer(buf.MultiBuffer{b})
}

func frameHeader(meta FrameMetadata, data buf.MultiBuffer) (*buf.Buffer, error) {
	frame := buf.New()
	if len(data) == 1 {
		frame.UDP = data[0].UDP
	}
	if err := meta.WriteTo(frame); err != nil {
		frame.Release()
		return nil, err
	}
	if _, err := serial.WriteUint16(frame, uint16(data.Len())); err != nil {
		frame.Release()
		return nil, err
	}
	return frame, nil
}

func writeMetaWithFrame(writer buf.Writer, meta FrameMetadata, data buf.MultiBuffer) error {
	frame, err := frameHeader(meta, data)
	if err != nil {
		buf.ReleaseMulti(data)
		return err
	}
	mb2 := make(buf.MultiBuffer, 0, len(data)+1)
	mb2 = append(mb2, frame)
	mb2 = append(mb2, data...)
	return writer.WriteMultiBuffer(mb2)
}

func (w *Writer) writeData(mb buf.MultiBuffer) error {
	meta := w.getNextFrameMeta()
	meta.Option.Set(OptionData)

	return writeMetaWithFrame(w.writer, meta, mb)
}

// WriteMultiBuffer implements buf.Writer.
func (w *Writer) WriteMultiBuffer(mb buf.MultiBuffer) error {
	defer func() { buf.ReleaseMulti(mb) }()
	if mb.IsEmpty() {
		return w.writeMetaOnly()
	}
	if w.transferType == protocol.TransferTypePacket {
		return w.writePackets(mb)
	}
	for !mb.IsEmpty() {
		var chunk buf.MultiBuffer
		mb, chunk = buf.SplitSize(mb, 8*1024)
		if err := w.writeData(chunk); err != nil {
			return err
		}
	}
	return nil
}

// Bound both bytes and frame count. Only packets already supplied by the caller
// are grouped; each packet retains its own complete Mux metadata and length.
const packetBatchBytes = 32 * 1024
const packetBatchFrames = 32

func (w *Writer) writePackets(mb buf.MultiBuffer) error {
	batch := make(buf.MultiBuffer, 0, min(len(mb), packetBatchFrames)*2)
	var size int32
	defer func() {
		buf.ReleaseMulti(batch)
		buf.ReleaseMulti(mb)
	}()
	flush := func() error {
		pending := batch
		batch = nil // the underlying writer owns every submitted buffer
		size = 0
		return w.writer.WriteMultiBuffer(pending)
	}
	for !mb.IsEmpty() {
		var packet *buf.Buffer
		mb, packet = buf.SplitFirst(mb)
		meta := w.getNextFrameMeta()
		meta.Option.Set(OptionData)
		frame, err := frameHeader(meta, buf.MultiBuffer{packet})
		if err != nil {
			packet.Release()
			return err
		}
		frameSize := frame.Len() + packet.Len()
		if len(batch) > 0 && (size+frameSize > packetBatchBytes || len(batch)/2 >= packetBatchFrames) {
			if err := flush(); err != nil {
				frame.Release()
				packet.Release()
				return err
			}
		}
		batch = append(batch, frame, packet)
		size += frameSize
	}
	return flush()
}

// Close implements common.Closable.
func (w *Writer) Close() error {
	meta := FrameMetadata{
		SessionID:     w.id,
		SessionStatus: SessionStatusEnd,
	}
	if w.hasError {
		meta.Option.Set(OptionError)
	}

	frame := buf.New()
	common.Must(meta.WriteTo(frame))

	w.writer.WriteMultiBuffer(buf.MultiBuffer{frame})
	return nil
}
