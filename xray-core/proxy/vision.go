// Code in this file is derived from Xray-core Vision (MPL-2.0).
package proxy

import (
	"bytes"
	"context"
	"crypto/rand"
	"math/big"
	"sync"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/transport/internet/stat"
)

var (
	Tls13SupportedVersions  = []byte{0x00, 0x2b, 0x00, 0x02, 0x03, 0x04}
	TlsClientHandShakeStart = []byte{0x16, 0x03}
	TlsServerHandShakeStart = []byte{0x16, 0x03, 0x03}
	TlsApplicationDataStart = []byte{0x17, 0x03, 0x03}

	Tls13CipherSuiteDic = map[uint16]string{
		0x1301: "TLS_AES_128_GCM_SHA256",
		0x1302: "TLS_AES_256_GCM_SHA384",
		0x1303: "TLS_CHACHA20_POLY1305_SHA256",
		0x1304: "TLS_AES_128_CCM_SHA256",
		0x1305: "TLS_AES_128_CCM_8_SHA256",
	}
)

const (
	TlsHandshakeTypeClientHello byte = 0x01
	TlsHandshakeTypeServerHello byte = 0x02

	CommandPaddingContinue byte = 0x00
	CommandPaddingEnd      byte = 0x01
	CommandPaddingDirect   byte = 0x02
)

type TrafficState struct {
	mu            sync.Mutex
	tls           [2]visionTLSParser
	tlsNegotiated bool
	// Set before starting either direction; UDP/Mux never bypass outer TLS.
	DisableDirectCopy      bool
	UserUUID               []byte
	NumberOfPacketToFilter int
	EnableXtls             bool
	IsTLS12orAbove         bool
	IsTLS                  bool
	Cipher                 uint16
	RemainingServerHello   int32
	Inbound                InboundState
	Outbound               OutboundState
}

type InboundState struct {
	padding visionUnpadding
	// reader link state
	WithinPaddingBuffers   bool
	UplinkReaderDirectCopy bool
	RemainingCommand       int32
	RemainingContent       int32
	RemainingPadding       int32
	CurrentCommand         int
	// write link state
	IsPadding                bool
	DownlinkWriterDirectCopy bool
}

type OutboundState struct {
	padding visionUnpadding
	// reader link state
	WithinPaddingBuffers     bool
	DownlinkReaderDirectCopy bool
	RemainingCommand         int32
	RemainingContent         int32
	RemainingPadding         int32
	CurrentCommand           int
	// write link state
	IsPadding              bool
	UplinkWriterDirectCopy bool
}

func NewTrafficState(userUUID []byte) *TrafficState {
	return &TrafficState{
		UserUUID:               bytes.Clone(userUUID),
		NumberOfPacketToFilter: 8,
		EnableXtls:             false,
		IsTLS12orAbove:         false,
		IsTLS:                  false,
		Cipher:                 0,
		RemainingServerHello:   -1,
		Inbound: InboundState{
			WithinPaddingBuffers:     true,
			UplinkReaderDirectCopy:   false,
			RemainingCommand:         -1,
			RemainingContent:         -1,
			RemainingPadding:         -1,
			CurrentCommand:           0,
			IsPadding:                true,
			DownlinkWriterDirectCopy: false,
		},
		Outbound: OutboundState{
			WithinPaddingBuffers:     true,
			DownlinkReaderDirectCopy: false,
			RemainingCommand:         -1,
			RemainingContent:         -1,
			RemainingPadding:         -1,
			CurrentCommand:           0,
			IsPadding:                true,
			UplinkWriterDirectCopy:   false,
		},
	}
}

// VisionReader is used to read xtls vision protocol
// Note Vision probably only make sense as the inner most layer of reader, since it need assess traffic state from origin proxy traffic
type VisionReader struct {
	buf.Reader
	trafficState *TrafficState
	ctx          context.Context
	isUplink     bool
	conn         net.Conn
	input        *bytes.Reader
	rawInput     *bytes.Buffer
	ob           *session.Outbound

	// internal
	directReadCounter stats.Counter
	filterDone        bool
}

func NewVisionReader(reader buf.Reader, trafficState *TrafficState, isUplink bool, ctx context.Context, conn net.Conn, input *bytes.Reader, rawInput *bytes.Buffer, ob *session.Outbound) *VisionReader {
	return &VisionReader{
		Reader:       reader,
		trafficState: trafficState,
		ctx:          ctx,
		isUplink:     isUplink,
		conn:         conn,
		input:        input,
		rawInput:     rawInput,
		ob:           ob,
	}
}

func (w *VisionReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	buffer, err := w.Reader.ReadMultiBuffer()
	if buffer.IsEmpty() {
		return buffer, err
	}

	var withinPaddingBuffers *bool
	var currentCommand *int
	var switchToDirectCopy *bool
	if w.isUplink {
		withinPaddingBuffers = &w.trafficState.Inbound.WithinPaddingBuffers
		currentCommand = &w.trafficState.Inbound.CurrentCommand
		switchToDirectCopy = &w.trafficState.Inbound.UplinkReaderDirectCopy
	} else {
		withinPaddingBuffers = &w.trafficState.Outbound.WithinPaddingBuffers
		currentCommand = &w.trafficState.Outbound.CurrentCommand
		switchToDirectCopy = &w.trafficState.Outbound.DownlinkReaderDirectCopy
	}

	if *switchToDirectCopy {
		if w.directReadCounter != nil {
			w.directReadCounter.Add(int64(buffer.Len()))
		}
		return buffer, err
	}

	if *withinPaddingBuffers {
		mb2 := make(buf.MultiBuffer, 0, len(buffer))
		for i, b := range buffer {
			newbuffer, decodeErr := xtlsUnpadding(b, w.trafficState, w.isUplink)
			if decodeErr != nil {
				buf.ReleaseMulti(mb2)
				buf.ReleaseMulti(buffer[i+1:])
				return nil, decodeErr
			}
			if newbuffer.Len() > 0 {
				mb2 = append(mb2, newbuffer)
			} else {
				newbuffer.Release()
			}
		}
		buffer = mb2
		var decoder *visionUnpadding
		if w.isUplink {
			decoder = &w.trafficState.Inbound.padding
		} else {
			decoder = &w.trafficState.Outbound.padding
		}
		*withinPaddingBuffers = !decoder.done
		if decoder.done && *currentCommand == int(CommandPaddingDirect) {
			if w.trafficState.DisableDirectCopy {
				buf.ReleaseMulti(buffer)
				return nil, errors.New("Vision direct copy is unavailable for UDP/Mux")
			}
			*switchToDirectCopy = true
		}
	}
	if !w.filterDone {
		status, _ := w.trafficState.filterTLS(buffer, w.isUplink)
		w.filterDone = status.done
	}

	if *switchToDirectCopy {
		// XTLS Vision processes TLS-like conn's input and rawInput
		if w.input != nil {
			if inputBuffer, err := buf.ReadFrom(w.input); err == nil && !inputBuffer.IsEmpty() {
				buffer, _ = buf.MergeMulti(buffer, inputBuffer)
			}
		}
		if w.rawInput != nil {
			if rawInputBuffer, err := buf.ReadFrom(w.rawInput); err == nil && !rawInputBuffer.IsEmpty() {
				buffer, _ = buf.MergeMulti(buffer, rawInputBuffer)
			}
		}
		if w.input != nil {
			*w.input = bytes.Reader{}
			w.input = nil
		}
		if w.rawInput != nil {
			*w.rawInput = bytes.Buffer{}
			w.rawInput = nil
		}

		if inbound := session.InboundFromContext(w.ctx); inbound != nil && inbound.Conn != nil {
			// if w.isUplink && inbound.CanSpliceCopy == 2 { // TODO: enable uplink splice
			// 	inbound.CanSpliceCopy = 1
			// }
			if !w.isUplink && w.ob != nil && w.ob.CanSpliceCopy == 2 { // ob need to be passed in due to context can have more than one ob
				w.ob.CanSpliceCopy = 1
			}
		}
		readerConn, readCounter, _ := UnwrapRawConn(w.conn)
		w.directReadCounter = readCounter
		if readerConn == nil {
			buf.ReleaseMulti(buffer)
			return nil, errors.New("missing Vision raw connection")
		}
		w.Reader = buf.NewReader(readerConn)
	}
	return buffer, err
}

// VisionWriter is used to write xtls vision protocol
// Note Vision probably only make sense as the inner most layer of writer, since it need assess traffic state from origin proxy traffic
type VisionWriter struct {
	buf.Writer
	trafficState *TrafficState
	ctx          context.Context
	isUplink     bool
	conn         net.Conn
	ob           *session.Outbound

	// internal
	writeOnceUserUUID []byte
	direct            bool

	testseed []uint32
}

func NewVisionWriter(writer buf.Writer, trafficState *TrafficState, isUplink bool, ctx context.Context, conn net.Conn, ob *session.Outbound, testseed []uint32) *VisionWriter {
	w := make([]byte, len(trafficState.UserUUID))
	copy(w, trafficState.UserUUID)
	if len(testseed) < 4 {
		testseed = []uint32{900, 500, 900, 256}
	}
	return &VisionWriter{
		Writer:            writer,
		trafficState:      trafficState,
		ctx:               ctx,
		writeOnceUserUUID: w,
		isUplink:          isUplink,
		conn:              conn,
		ob:                ob,
		testseed:          testseed,
	}
}

func (w *VisionWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	var isPadding *bool
	if w.isUplink {
		isPadding = &w.trafficState.Outbound.IsPadding
	} else {
		isPadding = &w.trafficState.Inbound.IsPadding
	}
	if !*isPadding {
		return w.Writer.WriteMultiBuffer(mb)
	}
	if len(mb) == 1 && mb[0] == nil {
		mb[0] = XtlsPadding(nil, CommandPaddingContinue, &w.writeOnceUserUUID, true, w.ctx, w.testseed)
		return w.Writer.WriteMultiBuffer(mb)
	}
	if mb.IsEmpty() {
		return w.Writer.WriteMultiBuffer(mb)
	}
	status, end := w.trafficState.filterTLS(mb, w.isUplink)
	if status.isTLS && end > 0 {
		prefix, tail := splitVisionBuffer(mb, end)
		command := CommandPaddingEnd
		if status.enableXtls {
			command = CommandPaddingDirect
		}
		if err := w.writePadding(prefix, command, true); err != nil {
			buf.ReleaseMulti(tail)
			return err
		}
		if command == CommandPaddingDirect {
			if err := w.startDirect(); err != nil {
				buf.ReleaseMulti(tail)
				return err
			}
		}
		*isPadding = false
		if !tail.IsEmpty() {
			if err := w.Writer.WriteMultiBuffer(tail); err != nil {
				return err
			}
		}
		// All old TLS writes and any raw suffix are complete before splice can
		// bypass this writer. A limiter marks the connection ineligible (3).
		if w.direct && !w.isUplink {
			if inbound := session.InboundFromContext(w.ctx); inbound != nil && inbound.CanSpliceCopy == 2 {
				inbound.CanSpliceCopy = 1
			}
		}
		return nil
	}
	command := CommandPaddingContinue
	if status.stopPadding {
		command = CommandPaddingEnd
	}
	if err := w.writePadding(mb, command, status.isTLS); err != nil {
		return err
	}
	if command == CommandPaddingEnd {
		*isPadding = false
	}
	return nil
}

func (w *VisionWriter) startDirect() error {
	if flusher, ok := w.Writer.(interface{ Flush() error }); ok {
		if err := flusher.Flush(); err != nil {
			return err
		}
	}
	raw, _, counter := UnwrapRawConn(w.conn)
	if raw == nil {
		return errors.New("missing Vision raw connection")
	}
	if counter != nil {
		raw = &stat.CounterConnection{Connection: raw, WriteCounter: counter}
	}
	w.Writer = buf.NewWriter(raw)
	w.direct = true
	if w.isUplink {
		w.trafficState.Outbound.UplinkWriterDirectCopy = true
	} else {
		w.trafficState.Inbound.DownlinkWriterDirectCopy = true
	}
	return nil
}

func (w *VisionWriter) writePadding(mb buf.MultiBuffer, command byte, long bool) error {
	mb = ReshapeMultiBuffer(w.ctx, mb)
	for i, b := range mb {
		c := CommandPaddingContinue
		if i == len(mb)-1 {
			c = command
		}
		mb[i] = XtlsPadding(b, c, &w.writeOnceUserUUID, long, w.ctx, w.testseed)
	}
	return w.Writer.WriteMultiBuffer(mb)
}

// splitVisionBuffer splits at an exact stream offset, including inside a Buffer.
// Only the boundary fragment is copied; all other buffers transfer ownership.
func splitVisionBuffer(mb buf.MultiBuffer, size int32) (buf.MultiBuffer, buf.MultiBuffer) {
	prefix := make(buf.MultiBuffer, 0, len(mb))
	for i, b := range mb {
		if b.Len() <= size {
			prefix = append(prefix, b)
			mb[i] = nil
			size -= b.Len()
			if size == 0 {
				return prefix, mb[i+1:]
			}
			continue
		}
		part := buf.NewWithSize(size)
		_, _ = part.Write(b.BytesTo(size))
		b.Advance(size)
		return append(prefix, part), mb[i:]
	}
	return prefix, nil
}

// IsCompleteRecord checks an isolated batch without copying it. Streaming Vision
// switching uses the per-direction parser instead of this compatibility helper.
func IsCompleteRecord(mb buf.MultiBuffer) bool {
	var header [5]byte
	used, remaining := 0, 0
	for _, b := range mb {
		data := b.Bytes()
		for len(data) > 0 {
			if used < 5 {
				n := copy(header[used:], data)
				used += n
				data = data[n:]
				if used < 5 {
					continue
				}
				if header[0] != 23 || header[1] != 3 || header[2] != 3 {
					return false
				}
				remaining = int(header[3])<<8 | int(header[4])
			}
			n := min(remaining, len(data))
			remaining -= n
			data = data[n:]
			if remaining == 0 {
				used = 0
			}
		}
	}
	return used == 0 && remaining == 0
}

// ReshapeMultiBuffer leaves room for a Vision header, including on large UDP
// buffers. It never searches ciphertext or truncates an oversized remainder.
func ReshapeMultiBuffer(_ context.Context, mb buf.MultiBuffer) buf.MultiBuffer {
	const maxContent = buf.Size - 21
	needsSplit := false
	for _, b := range mb {
		if b.Len() > maxContent {
			needsSplit = true
			break
		}
	}
	if !needsSplit {
		return mb
	}
	out := make(buf.MultiBuffer, 0, len(mb)+1)
	for i, b := range mb {
		mb[i] = nil
		for b.Len() > maxContent {
			part := buf.New()
			_, _ = part.Write(b.BytesTo(maxContent))
			b.Advance(maxContent)
			out = append(out, part)
		}
		out = append(out, b)
	}
	return out
}

// XtlsPadding add padding to eliminate length signature during tls handshake
func XtlsPadding(b *buf.Buffer, command byte, userUUID *[]byte, longPadding bool, ctx context.Context, testseed []uint32) *buf.Buffer {
	var contentLen int32 = 0
	var paddingLen int32 = 0
	if b != nil {
		contentLen = b.Len()
	}
	if contentLen < int32(testseed[0]) && longPadding {
		l, err := rand.Int(rand.Reader, big.NewInt(int64(testseed[1])))
		if err != nil {
			errors.LogDebugInner(ctx, err, "failed to generate padding")
		}
		paddingLen = int32(l.Int64()) + int32(testseed[2]) - contentLen
	} else {
		l, err := rand.Int(rand.Reader, big.NewInt(int64(testseed[3])))
		if err != nil {
			errors.LogDebugInner(ctx, err, "failed to generate padding")
		}
		paddingLen = int32(l.Int64())
	}
	if paddingLen > buf.Size-21-contentLen {
		paddingLen = buf.Size - 21 - contentLen
	}
	newbuffer := buf.New()
	if userUUID != nil {
		newbuffer.Write(*userUUID)
		*userUUID = nil
	}
	newbuffer.Write([]byte{command, byte(contentLen >> 8), byte(contentLen), byte(paddingLen >> 8), byte(paddingLen)})
	if b != nil {
		newbuffer.Write(b.Bytes())
		b.Release()
		b = nil
	}
	newbuffer.Extend(paddingLen)
	errors.LogDebug(ctx, "XtlsPadding ", contentLen, " ", paddingLen, " ", command)
	return newbuffer
}

// XtlsUnpadding is retained for callers decoding a single Vision buffer.
// VisionReader uses the error-returning decoder to reject malformed framing.
func XtlsUnpadding(b *buf.Buffer, s *TrafficState, uplink bool, _ context.Context) *buf.Buffer {
	out, err := xtlsUnpadding(b, s, uplink)
	if err != nil {
		return buf.New()
	}
	return out
}

// XtlsFilterTls retains the downlink inspection entry point. Live readers and
// writers supply their direction and use one consistent, locked TLS snapshot.
func XtlsFilterTls(mb buf.MultiBuffer, s *TrafficState, _ context.Context) { s.filterTLS(mb, false) }
