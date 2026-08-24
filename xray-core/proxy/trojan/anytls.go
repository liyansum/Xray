package trojan

import (
	"context"
	"crypto/md5"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"io"
	stdnet "net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	udp_proto "github.com/xtls/xray-core/common/protocol/udp"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/internet/udp"
)

const (
	anyTLSCmdWaste         byte = 0
	anyTLSCmdSYN           byte = 1
	anyTLSCmdPSH           byte = 2
	anyTLSCmdFIN           byte = 3
	anyTLSCmdSettings      byte = 4
	anyTLSCmdAlert         byte = 5
	anyTLSCmdUpdatePadding byte = 6
	anyTLSCmdSYNACK        byte = 7
	anyTLSCmdHeartRequest  byte = 8
	anyTLSCmdHeartResponse byte = 9
	anyTLSCmdServerSetting byte = 10

	anyTLSFrameHeaderSize  = 7
	anyTLSFrameBufferSize  = 32 * 1024
	anyTLSFramePayloadSize = anyTLSFrameBufferSize - anyTLSFrameHeaderSize
	anyTLSLargeFrameSize   = 64 * 1024
	anyTLSUoTMagic         = "sp.v2.udp-over-tcp.arpa"
	anyTLSReadBatchSize    = 32 * 1024
	anyTLSControlTimeout   = 5 * time.Second
)

var (
	anyTLSPaddingScheme = []byte("stop=8\n0=30-30\n1=100-400\n2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000\n3=9-9,500-1000\n4=500-1000\n5=500-1000\n6=500-1000\n7=500-1000")
	anyTLSPaddingMD5    = func() string {
		sum := md5.Sum(anyTLSPaddingScheme)
		return hex.EncodeToString(sum[:])
	}()
	anyTLSAddressParser = protocol.NewAddressParser(
		protocol.AddressFamilyByte(0x01, net.AddressFamilyIPv4),
		protocol.AddressFamilyByte(0x04, net.AddressFamilyIPv6),
		protocol.AddressFamilyByte(0x03, net.AddressFamilyDomain),
	)
	anyTLSUoTAddressParser = protocol.NewAddressParser(
		protocol.AddressFamilyByte(0x00, net.AddressFamilyIPv4),
		protocol.AddressFamilyByte(0x01, net.AddressFamilyIPv6),
		protocol.AddressFamilyByte(0x02, net.AddressFamilyDomain),
	)
)

func (s *Server) processAnyTLS(ctx context.Context, conn stat.Connection, reader *buf.BufferedReader, user *protocol.MemoryUser, dispatcher routing.Dispatcher) error {
	var authentication [sha256.Size + 2]byte
	if _, err := io.ReadFull(reader, authentication[:]); err != nil {
		return errors.New("failed to read AnyTLS authentication").Base(err)
	}
	_, expectedHash, err := userProtocolKeys(user)
	if err != nil || subtle.ConstantTimeCompare(authentication[:sha256.Size], expectedHash[:]) != 1 {
		return errors.New("invalid AnyTLS authentication")
	}
	paddingLength := binary.BigEndian.Uint16(authentication[sha256.Size:])
	if paddingLength > 0 {
		if _, err := io.CopyN(io.Discard, reader, int64(paddingLength)); err != nil {
			return errors.New("failed to read AnyTLS authentication padding").Base(err)
		}
	}
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		return errors.New("unable to clear AnyTLS handshake deadline").Base(err)
	}

	inbound := session.InboundFromContext(ctx)
	if inbound == nil {
		return errors.New("missing inbound metadata")
	}
	inbound.Name = "anytls"
	inbound.User = user
	inbound.CanSpliceCopy = 3

	sessionPolicy := s.policyManager.ForLevel(user.Level)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	timer := signal.CancelAfterInactivity(ctx, cancel, sessionPolicy.Timeouts.ConnectionIdle)
	defer timer.SetTimeout(0)
	ctx = policy.ContextWithBufferPolicy(ctx, sessionPolicy.Buffer)

	anySession := newAnyTLSServerSession(ctx, conn, reader, timer, func(stream *anyTLSStream) {
		s.handleAnyTLSStream(ctx, stream, user, sessionPolicy, dispatcher)
	})
	go func() {
		<-ctx.Done()
		anySession.close()
	}()
	return anySession.run()
}

type anyTLSServerSession struct {
	conn     stat.Connection
	reader   io.Reader
	activity signal.ActivityUpdater
	onStream func(*anyTLSStream)

	controlMu sync.Mutex
	writeMu   sync.Mutex
	mu        sync.RWMutex
	streams   map[uint32]*anyTLSStream
	closed    chan struct{}
	once      sync.Once
	wg        sync.WaitGroup

	receivedSettings bool
	peerVersion      int
}

func newAnyTLSServerSession(_ context.Context, conn stat.Connection, reader io.Reader, activity signal.ActivityUpdater, onStream func(*anyTLSStream)) *anyTLSServerSession {
	return &anyTLSServerSession{
		conn: conn, reader: reader, activity: activity, onStream: onStream,
		streams: make(map[uint32]*anyTLSStream), closed: make(chan struct{}),
	}
}

func readAnyTLSFramePayload(reader io.Reader, length int) ([]byte, []byte, error) {
	storage := getAnyTLSBufferStorage(length)
	payload := storage[:length]
	if _, err := io.ReadFull(reader, payload); err != nil {
		putAnyTLSBufferStorage(storage)
		return nil, nil, err
	}
	return payload, storage, nil
}

func (s *anyTLSServerSession) run() error {
	defer func() {
		s.close()
		s.wg.Wait()
	}()
	var header [anyTLSFrameHeaderSize]byte
	for {
		if _, err := io.ReadFull(s.reader, header[:]); err != nil {
			if errors.Cause(err) == io.EOF {
				return nil
			}
			return errors.New("failed to read AnyTLS frame header").Base(err)
		}
		s.activity.Update()
		command := header[0]
		streamID := binary.BigEndian.Uint32(header[1:5])
		length := int(binary.BigEndian.Uint16(header[5:7]))
		var frameData []byte
		var frameStorage []byte
		var data []byte
		if length != 0 {
			var err error
			frameData, frameStorage, err = readAnyTLSFramePayload(s.reader, length)
			if err != nil {
				return errors.New("failed to read AnyTLS frame payload").Base(err)
			}
			data = frameData
		}

		frameErr := func() error {
			switch command {
			case anyTLSCmdWaste:
				// Intentionally discarded.
			case anyTLSCmdSettings:
				if err := s.handleSettings(data); err != nil {
					_ = s.writeControlFrame(anyTLSCmdAlert, 0, []byte(err.Error()))
					return err
				}
			case anyTLSCmdSYN:
				if !s.receivedSettings {
					_ = s.writeControlFrame(anyTLSCmdAlert, 0, []byte("client did not send its settings"))
					return errors.New("AnyTLS client did not send settings before SYN")
				}
				if length != 0 || streamID == 0 {
					return errors.New("invalid AnyTLS SYN frame")
				}
				s.openStream(streamID)
			case anyTLSCmdPSH:
				stream := s.getStream(streamID)
				if stream != nil && len(frameData) != 0 {
					if err := stream.deliver(frameData); err != nil {
						_ = stream.Close()
					}
				}
			case anyTLSCmdFIN:
				if stream := s.removeStream(streamID); stream != nil {
					stream.closeRemote()
				}
			case anyTLSCmdHeartRequest:
				if s.peerVersion >= 2 {
					if err := s.writeControlFrame(anyTLSCmdHeartResponse, streamID, nil); err != nil {
						return err
					}
				}
			case anyTLSCmdHeartResponse:
				// Receiving it is itself activity; no further state is needed server-side.
			default:
				// Unknown server-only/control commands are ignored after consuming data.
			}
			return nil
		}()
		if frameData != nil {
			putAnyTLSBufferStorage(frameStorage)
		}
		if frameErr != nil {
			return frameErr
		}
	}
}

func parseAnyTLSSettings(data []byte) map[string]string {
	settings := make(map[string]string)
	for _, line := range strings.Split(string(data), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if ok {
			settings[key] = value
		}
	}
	return settings
}

func (s *anyTLSServerSession) handleSettings(data []byte) error {
	if s.receivedSettings {
		return errors.New("duplicate AnyTLS settings")
	}
	settings := parseAnyTLSSettings(data)
	version, err := strconv.Atoi(settings["v"])
	if err != nil || version < 1 {
		return errors.New("invalid AnyTLS protocol version")
	}
	s.peerVersion = version
	s.receivedSettings = true
	if settings["padding-md5"] != anyTLSPaddingMD5 {
		if err := s.writeControlFrame(anyTLSCmdUpdatePadding, 0, anyTLSPaddingScheme); err != nil {
			return err
		}
	}
	if version >= 2 {
		return s.writeControlFrame(anyTLSCmdServerSetting, 0, []byte("v=2"))
	}
	return nil
}

func (s *anyTLSServerSession) openStream(id uint32) {
	s.mu.Lock()
	if _, exists := s.streams[id]; exists {
		s.mu.Unlock()
		return
	}
	stream := newAnyTLSStream(id, s)
	s.streams[id] = stream
	s.wg.Add(1)
	s.mu.Unlock()
	go func() {
		defer s.wg.Done()
		defer stream.Close()
		s.onStream(stream)
	}()
}

func (s *anyTLSServerSession) getStream(id uint32) *anyTLSStream {
	s.mu.RLock()
	stream := s.streams[id]
	s.mu.RUnlock()
	return stream
}

func (s *anyTLSServerSession) removeStream(id uint32) *anyTLSStream {
	s.mu.Lock()
	stream := s.streams[id]
	delete(s.streams, id)
	s.mu.Unlock()
	return stream
}

func (s *anyTLSServerSession) writePreparedFrameLocked(frame []byte) error {
	select {
	case <-s.closed:
		return io.ErrClosedPipe
	default:
	}
	if err := buf.WriteAllBytes(s.conn, frame, nil); err != nil {
		return errors.New("failed to write AnyTLS frame").Base(err)
	}
	s.activity.Update()
	return nil
}

func (s *anyTLSServerSession) writeFrameLocked(command byte, streamID uint32, data []byte) error {
	if len(data) > 65535 {
		return errors.New("AnyTLS frame payload is too large")
	}
	frameSize := anyTLSFrameHeaderSize + len(data)
	storage := getAnyTLSBufferStorage(frameSize)
	defer putAnyTLSBufferStorage(storage)
	frame := storage[:frameSize]
	frame[0] = command
	binary.BigEndian.PutUint32(frame[1:5], streamID)
	binary.BigEndian.PutUint16(frame[5:7], uint16(len(data)))
	copy(frame[anyTLSFrameHeaderSize:], data)
	return s.writePreparedFrameLocked(frame)
}

// writeControlFrame bounds control-plane writes so an unresponsive peer cannot
// leave session management blocked until the much longer idle timeout. Control
// writes are serialized separately, and the connection deadline is installed
// before waiting for writeMu so a data write stuck behind an unresponsive peer
// is also interrupted after the official five-second bound.
func (s *anyTLSServerSession) writeControlFrame(command byte, streamID uint32, data []byte) error {
	err := s.writeControlFrameBounded(command, streamID, data)
	if err != nil {
		// Close only after all write locks have been released. Stream.Close uses
		// sync.Once, and closing the session while holding these locks can
		// otherwise deadlock with another stream concurrently sending FIN.
		s.close()
	}
	return err
}

func (s *anyTLSServerSession) writeControlFrameBounded(command byte, streamID uint32, data []byte) error {
	s.controlMu.Lock()
	defer s.controlMu.Unlock()
	select {
	case <-s.closed:
		return io.ErrClosedPipe
	default:
	}
	if err := s.conn.SetWriteDeadline(time.Now().Add(anyTLSControlTimeout)); err != nil {
		return errors.New("failed to set AnyTLS control write deadline").Base(err)
	}
	defer s.conn.SetWriteDeadline(time.Time{})
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	return s.writeFrameLocked(command, streamID, data)
}

// writeDataFrames serializes the complete Stream.Write operation. Payloads
// larger than the pool-aligned frame capacity are split into multiple PSH
// frames without allowing another stream or control frame between chunks.
func (s *anyTLSServerSession) writeDataFrames(streamID uint32, data []byte) (int, error) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	written := 0
	for len(data) > 0 {
		length := min(len(data), anyTLSFramePayloadSize)
		if err := s.writeFrameLocked(anyTLSCmdPSH, streamID, data[:length]); err != nil {
			return written, err
		}
		written += length
		data = data[length:]
	}
	return written, nil
}

// writeMultiBufferFrames builds AnyTLS PSH frames directly from Xray buffers.
// The framed buffer is allocated only after acquiring the session write lock
// and reused for the complete call, avoiding both the 32 KiB coalescing scratch
// and the 128 KiB pool jump caused by a 32 KiB payload plus its 7-byte header.
func (s *anyTLSServerSession) writeMultiBufferFrames(stream *anyTLSStream, payload buf.MultiBuffer) error {
	defer func() { buf.ReleaseMulti(payload) }()
	if payload.IsEmpty() {
		return nil
	}

	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	requestedSize := min(anyTLSFrameBufferSize, int(payload.Len())+anyTLSFrameHeaderSize)
	storage := getAnyTLSBufferStorage(requestedSize)
	defer putAnyTLSBufferStorage(storage)
	frame := storage[:requestedSize]
	for !payload.IsEmpty() {
		// WriteMultiBufferCoalesced used to call stream.Write once per batch,
		// so preserve its per-frame deadline and stream-close checks.
		if err := stream.checkWritable(); err != nil {
			return err
		}
		payloadCapacity := min(len(frame)-anyTLSFrameHeaderSize, anyTLSFramePayloadSize)
		var copied int
		payload, copied = buf.SplitBytes(payload, frame[anyTLSFrameHeaderSize:anyTLSFrameHeaderSize+payloadCapacity])
		if copied == 0 {
			return io.ErrNoProgress
		}
		frame[0] = anyTLSCmdPSH
		binary.BigEndian.PutUint32(frame[1:5], stream.id)
		binary.BigEndian.PutUint16(frame[5:7], uint16(copied))
		if err := s.writePreparedFrameLocked(frame[:anyTLSFrameHeaderSize+copied]); err != nil {
			return err
		}
	}
	return nil
}

func (s *anyTLSServerSession) close() {
	s.once.Do(func() {
		close(s.closed)
		_ = s.conn.SetDeadline(time.Now())
		s.mu.Lock()
		streams := s.streams
		s.streams = make(map[uint32]*anyTLSStream)
		s.mu.Unlock()
		for _, stream := range streams {
			stream.abortRemote()
		}
	})
}

type anyTLSStream struct {
	id      uint32
	session *anyTLSServerSession
	once    sync.Once
	report  sync.Once

	pipeReader *anyTLSSyncPipeReader
	pipeWriter *anyTLSSyncPipeWriter

	errMu  sync.RWMutex
	dieErr error

	writeDeadline anyTLSDeadline
}

func newAnyTLSStream(id uint32, session *anyTLSServerSession) *anyTLSStream {
	pipeReader, pipeWriter := newAnyTLSSyncPipe()
	stream := &anyTLSStream{
		id: id, session: session,
		pipeReader: pipeReader, pipeWriter: pipeWriter,
		writeDeadline: newAnyTLSDeadline(),
	}
	return stream
}

func (s *anyTLSStream) Read(payload []byte) (int, error) {
	n, err := s.pipeReader.Read(payload)
	if n == 0 {
		if dieErr := s.loadError(); dieErr != nil {
			err = dieErr
		}
	}
	return n, err
}

// ReadMultiBuffer lets Xray consume AnyTLS uplink data in the same 32 KiB
// batches used by the downlink writer. Without this implementation,
// buf.NewReader wraps the stream in SingleReader and splits every peer PSH
// into 8 KiB reads, multiplying pipe rendezvous, copies and accounting work.
// Reading through the synchronous pipe still blocks the session until the
// complete PSH has been consumed, preserving the official backpressure model.
func (s *anyTLSStream) ReadMultiBuffer() (buf.MultiBuffer, error) {
	payload := buf.NewWithSize(anyTLSReadBatchSize)
	read, err := payload.ReadFrom(s)
	if read == 0 {
		payload.Release()
		return nil, err
	}
	return buf.MultiBuffer{payload}, err
}

func (s *anyTLSStream) Write(payload []byte) (int, error) {
	if err := s.checkWritable(); err != nil {
		return 0, err
	}
	return s.session.writeDataFrames(s.id, payload)
}

func (s *anyTLSStream) checkWritable() error {
	select {
	case <-s.writeDeadline.wait():
		return os.ErrDeadlineExceeded
	default:
	}
	if dieErr := s.loadError(); dieErr != nil {
		return dieErr
	}
	return nil
}

// WriteMultiBuffer packs Xray buffers directly into pool-aligned AnyTLS frames.
func (s *anyTLSStream) WriteMultiBuffer(payload buf.MultiBuffer) error {
	if err := s.checkWritable(); err != nil {
		buf.ReleaseMulti(payload)
		return err
	}
	return s.session.writeMultiBufferFrames(s, payload)
}

// deliver follows the official AnyTLS/sing-box stream model: each stream has
// one synchronous pipe and a PSH is fully consumed before the session reads
// another frame. The pipe has no internal queue or project-specific budget.
func (s *anyTLSStream) deliver(payload []byte) error {
	written, err := s.pipeWriter.Write(payload)
	if err != nil {
		return err
	}
	if written != len(payload) {
		return io.ErrShortWrite
	}
	return nil
}

func (s *anyTLSStream) Close() error {
	return s.closeWithError(io.ErrClosedPipe, true)
}

func (s *anyTLSStream) closeWithError(err error, notifyPeer bool) error {
	var closeErr error = err
	var sendFIN bool
	s.once.Do(func() {
		s.storeError(err)
		_ = s.pipeReader.Close()
		s.session.removeStream(s.id)
		sendFIN = notifyPeer
	})
	// Never perform a session-level write while holding the stream's sync.Once.
	// A failed FIN closes the whole session, which in turn closes every stream;
	// keeping the Once locked here would create a cross-stream shutdown cycle.
	if sendFIN {
		closeErr = s.session.writeControlFrame(anyTLSCmdFIN, s.id, nil)
	}
	return closeErr
}

func (s *anyTLSStream) closeRemote() {
	_ = s.closeWithError(stdnet.ErrClosed, false)
}

func (s *anyTLSStream) abortRemote() {
	_ = s.closeWithError(stdnet.ErrClosed, false)
}

func (s *anyTLSStream) storeError(err error) {
	s.errMu.Lock()
	s.dieErr = err
	s.errMu.Unlock()
}

func (s *anyTLSStream) loadError() error {
	s.errMu.RLock()
	err := s.dieErr
	s.errMu.RUnlock()
	return err
}

func (s *anyTLSStream) handshakeSuccess() error {
	var reportErr error
	s.report.Do(func() {
		if s.session.peerVersion >= 2 {
			reportErr = s.session.writeControlFrame(anyTLSCmdSYNACK, s.id, nil)
		}
	})
	return reportErr
}

func (s *anyTLSStream) handshakeFailure(err error) error {
	var reportErr error
	s.report.Do(func() {
		if s.session.peerVersion >= 2 {
			reportErr = s.session.writeControlFrame(anyTLSCmdSYNACK, s.id, []byte(err.Error()))
		}
	})
	return reportErr
}

func (s *anyTLSStream) LocalAddr() net.Addr  { return s.session.conn.LocalAddr() }
func (s *anyTLSStream) RemoteAddr() net.Addr { return s.session.conn.RemoteAddr() }
func (s *anyTLSStream) SetDeadline(deadline time.Time) error {
	s.writeDeadline.set(deadline)
	return s.pipeReader.SetReadDeadline(deadline)
}

func (s *anyTLSStream) SetReadDeadline(deadline time.Time) error {
	return s.pipeReader.SetReadDeadline(deadline)
}

func (s *anyTLSStream) SetWriteDeadline(deadline time.Time) error {
	s.writeDeadline.set(deadline)
	return nil
}

// anyTLSDeadline mirrors the official AnyTLS per-stream write-deadline model.
// It deliberately does not set a deadline on the shared TLS connection, which
// would also interrupt unrelated streams in the same session.
type anyTLSDeadline struct {
	mu      sync.Mutex
	timer   *time.Timer
	expired chan struct{}
}

func newAnyTLSDeadline() anyTLSDeadline {
	return anyTLSDeadline{expired: make(chan struct{})}
}

func (d *anyTLSDeadline) set(deadline time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.timer != nil {
		if !d.timer.Stop() {
			<-d.expired
		}
		d.timer = nil
	}
	closed := channelClosed(d.expired)
	if deadline.IsZero() {
		if closed {
			d.expired = make(chan struct{})
		}
		return
	}
	if delay := time.Until(deadline); delay > 0 {
		if closed {
			d.expired = make(chan struct{})
		}
		expired := d.expired
		d.timer = time.AfterFunc(delay, func() { close(expired) })
		return
	}
	if !closed {
		close(d.expired)
	}
}

func (d *anyTLSDeadline) wait() <-chan struct{} {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.expired
}

func channelClosed(channel <-chan struct{}) bool {
	select {
	case <-channel:
		return true
	default:
		return false
	}
}

func anyTLSStreamContext(ctx context.Context, user *protocol.MemoryUser) context.Context {
	ctx = session.SubContextFromMuxInbound(ctx)
	parentInbound := session.InboundFromContext(ctx)
	if parentInbound == nil {
		return ctx
	}
	streamInbound := *parentInbound
	streamInbound.Name = "anytls"
	streamInbound.User = user
	streamInbound.CanSpliceCopy = 3
	streamInbound.Conn = nil
	streamInbound.Timer = nil
	return session.ContextWithInbound(ctx, &streamInbound)
}

func (s *Server) handleAnyTLSStream(parent context.Context, stream *anyTLSStream, user *protocol.MemoryUser, sessionPolicy policy.Session, dispatcher routing.Dispatcher) {
	ctx := anyTLSStreamContext(parent, user)
	address, port, err := anyTLSAddressParser.ReadAddressPort(nil, stream)
	if err != nil {
		_ = stream.handshakeFailure(err)
		return
	}
	if address.Family().IsDomain() && strings.EqualFold(address.Domain(), anyTLSUoTMagic) {
		if err := s.handleAnyTLSUoT(ctx, stream, user, dispatcher); err != nil {
			_ = stream.handshakeFailure(err)
		}
		return
	}

	destination := net.TCPDestination(address, port)
	ctx = log.ContextWithAccessMessage(ctx, &log.AccessMessage{
		From: stream.RemoteAddr(), To: destination, Status: log.AccessAccepted, Email: user.Email,
	})
	afterDispatch := func(dispatchErr error) error {
		if dispatchErr != nil {
			return stream.handshakeFailure(dispatchErr)
		}
		return stream.handshakeSuccess()
	}
	if err := s.handleConnectionAfterDispatch(ctx, sessionPolicy, destination, buf.NewReader(stream), buf.NewWriter(stream), dispatcher, afterDispatch); err != nil {
		errors.LogInfoInner(ctx, err, "AnyTLS stream ended")
	}
}

func readAnyTLSUoTRequest(reader io.Reader) (bool, net.Destination, error) {
	var connect [1]byte
	if _, err := io.ReadFull(reader, connect[:]); err != nil {
		return false, net.Destination{}, err
	}
	if connect[0] > 1 {
		return false, net.Destination{}, errors.New("invalid UoT connect flag")
	}
	// The UoT v2 request destination uses the regular SOCKS address format
	// (01/03/04). Only per-packet addresses use UoT's 00/01/02 format.
	address, port, err := anyTLSAddressParser.ReadAddressPort(nil, reader)
	if err != nil {
		return false, net.Destination{}, err
	}
	return connect[0] == 1, net.UDPDestination(address, port), nil
}

func (s *Server) handleAnyTLSUoT(ctx context.Context, stream *anyTLSStream, user *protocol.MemoryUser, dispatcher routing.Dispatcher) error {
	isConnect, fixedDestination, err := readAnyTLSUoTRequest(stream)
	if err != nil {
		return errors.New("failed to read AnyTLS UoT v2 request").Base(err)
	}
	if err := stream.handshakeSuccess(); err != nil {
		return err
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	udpServer := udp.NewDispatcher(dispatcher, func(callbackCtx context.Context, packet *udp_proto.Packet) {
		payload := packet.Payload
		defer payload.Release()
		destination := packet.Source
		if payload.UDP != nil {
			destination = *payload.UDP
		}
		if err := writeAnyTLSUoTPacket(stream, isConnect, destination, payload.Bytes()); err != nil {
			errors.LogInfoInner(callbackCtx, err, "failed to write AnyTLS UoT response")
			cancel()
		}
	})
	defer udpServer.RemoveRay()

	var coneDestination *net.Destination
	for {
		destination := fixedDestination
		if !isConnect {
			address, port, err := anyTLSUoTAddressParser.ReadAddressPort(nil, stream)
			if err != nil {
				if errors.Cause(err) == io.EOF {
					return nil
				}
				return errors.New("failed to read AnyTLS UoT packet destination").Base(err)
			}
			destination = net.UDPDestination(address, port)
		}
		var lengthBytes [2]byte
		if _, err := io.ReadFull(stream, lengthBytes[:]); err != nil {
			return errors.New("failed to read AnyTLS UoT packet length").Base(err)
		}
		length := int32(binary.BigEndian.Uint16(lengthBytes[:]))
		payload := buf.NewWithSize(length)
		if _, err := payload.ReadFullFrom(stream, length); err != nil {
			payload.Release()
			return errors.New("failed to read AnyTLS UoT packet").Base(err)
		}
		payload.UDP = &destination
		packetCtx := log.ContextWithAccessMessage(ctx, &log.AccessMessage{
			From: stream.RemoteAddr(), To: destination, Status: log.AccessAccepted, Email: user.Email,
		})
		if !s.cone || coneDestination == nil {
			copyDestination := destination
			coneDestination = &copyDestination
		}
		udpServer.Dispatch(packetCtx, *coneDestination, payload)
	}
}

func writeAnyTLSUoTPacket(writer io.Writer, isConnect bool, destination net.Destination, payload []byte) error {
	if len(payload) > 65535 {
		return errors.New("AnyTLS UoT packet is too large")
	}
	buffer := buf.NewWithSize(int32(len(payload) + 260))
	defer buffer.Release()
	if !isConnect {
		if err := anyTLSUoTAddressParser.WriteAddressPort(buffer, destination.Address, destination.Port); err != nil {
			return err
		}
	}
	length := buffer.Extend(2)
	binary.BigEndian.PutUint16(length, uint16(len(payload)))
	if _, err := buffer.Write(payload); err != nil {
		return err
	}
	return buf.WriteAllBytes(writer, buffer.Bytes(), nil)
}
