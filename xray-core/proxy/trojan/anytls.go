package trojan

import (
	"context"
	"crypto/md5"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"io"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
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

	anyTLSFrameHeaderSize = 7
	anyTLSUoTMagic        = "sp.v2.udp-over-tcp.arpa"
	anyTLSStreamIDError   = "AnyTLS stream ID is not strictly increasing"

	// Receive queues decouple independent streams without allowing a slow or
	// malicious peer to grow memory without bound. These are buffering limits,
	// not limits on the number of active streams.
	anyTLSStreamQueuedBytes   int64 = 8 * 1024 * 1024
	anyTLSStreamQueuedFrames  int64 = 2048
	anyTLSSessionQueuedBytes  int64 = 16 * 1024 * 1024
	anyTLSSessionQueuedFrames int64 = 4096
	anyTLSGlobalQueuedBytes   int64 = 64 * 1024 * 1024
	anyTLSGlobalQueuedFrames  int64 = 16384
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
	}, s.anyTLSBudget)
	go func() {
		<-ctx.Done()
		anySession.close()
	}()
	return anySession.run()
}

type anyTLSServerSession struct {
	ctx      context.Context
	conn     stat.Connection
	reader   io.Reader
	activity signal.ActivityUpdater
	onStream func(*anyTLSStream)

	writeMu sync.Mutex
	mu      sync.RWMutex
	streams map[uint32]*anyTLSStream
	closed  chan struct{}
	once    sync.Once
	wg      sync.WaitGroup
	budget  *anyTLSBufferBudget
	global  *anyTLSBufferBudget

	receivedSettings bool
	peerVersion      int
	lastPeerStreamID uint32
}

type anyTLSBufferBudget struct {
	queuedBytes  atomic.Int64
	queuedFrames atomic.Int64
	maxBytes     int64
	maxFrames    int64

	mu      sync.Mutex
	waitFor chan struct{}
}

func newAnyTLSBufferBudget(maxBytes, maxFrames int64) *anyTLSBufferBudget {
	return &anyTLSBufferBudget{maxBytes: maxBytes, maxFrames: maxFrames}
}

// reserve either accounts one frame or returns a notification that is closed
// when capacity may be available. Checking the limit and registering the
// notification under the same lock prevents a release from being missed.
func (b *anyTLSBufferBudget) reserve(size int64) (bool, <-chan struct{}) {
	if b == nil {
		return true, nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.queuedFrames.Load()+1 > b.maxFrames || b.queuedBytes.Load()+size > b.maxBytes {
		if b.waitFor == nil {
			b.waitFor = make(chan struct{})
		}
		return false, b.waitFor
	}
	b.queuedFrames.Add(1)
	b.queuedBytes.Add(size)
	return true, nil
}

func (b *anyTLSBufferBudget) release(size int64) {
	if b == nil {
		return
	}
	b.mu.Lock()
	b.queuedBytes.Add(-size)
	b.queuedFrames.Add(-1)
	if b.waitFor != nil {
		close(b.waitFor)
		b.waitFor = nil
	}
	b.mu.Unlock()
}

func newAnyTLSServerSession(ctx context.Context, conn stat.Connection, reader io.Reader, activity signal.ActivityUpdater, onStream func(*anyTLSStream), global ...*anyTLSBufferBudget) *anyTLSServerSession {
	s := &anyTLSServerSession{
		ctx: ctx, conn: conn, reader: reader, activity: activity, onStream: onStream,
		streams: make(map[uint32]*anyTLSStream), closed: make(chan struct{}),
		budget: newAnyTLSBufferBudget(anyTLSSessionQueuedBytes, anyTLSSessionQueuedFrames),
	}
	if len(global) != 0 {
		s.global = global[0]
	}
	return s
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
		var frameData *buf.Buffer
		var data []byte
		if length != 0 {
			frameData = buf.NewWithSize(int32(length))
			if _, err := frameData.ReadFullFrom(s.reader, int32(length)); err != nil {
				frameData.Release()
				return errors.New("failed to read AnyTLS frame payload").Base(err)
			}
			data = frameData.Bytes()
		}

		frameErr := func() error {
			switch command {
			case anyTLSCmdWaste:
				// Intentionally discarded.
			case anyTLSCmdSettings:
				if err := s.handleSettings(data); err != nil {
					_ = s.writeFrame(anyTLSCmdAlert, 0, []byte(err.Error()))
					return err
				}
			case anyTLSCmdSYN:
				if !s.receivedSettings {
					_ = s.writeFrame(anyTLSCmdAlert, 0, []byte("client did not send its settings"))
					return errors.New("AnyTLS client did not send settings before SYN")
				}
				if length != 0 || streamID == 0 {
					return errors.New("invalid AnyTLS SYN frame")
				}
				if err := s.openStream(streamID); err != nil {
					_ = s.writeFrame(anyTLSCmdAlert, 0, []byte(anyTLSStreamIDError))
					return err
				}
			case anyTLSCmdPSH:
				stream := s.getStream(streamID)
				if stream != nil && frameData != nil {
					if err := stream.deliver(frameData); err != nil {
						_ = stream.Close()
					} else {
						// The stream queue owns the pooled payload now.
						frameData = nil
					}
				}
			case anyTLSCmdFIN:
				if stream := s.removeStream(streamID); stream != nil {
					stream.closeRemote()
				}
			case anyTLSCmdHeartRequest:
				if s.peerVersion >= 2 {
					if err := s.writeFrame(anyTLSCmdHeartResponse, streamID, nil); err != nil {
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
			frameData.Release()
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
		if err := s.writeFrame(anyTLSCmdUpdatePadding, 0, anyTLSPaddingScheme); err != nil {
			return err
		}
	}
	if version >= 2 {
		return s.writeFrame(anyTLSCmdServerSetting, 0, []byte("v=2"))
	}
	return nil
}

func (s *anyTLSServerSession) openStream(id uint32) error {
	s.mu.Lock()
	if id <= s.lastPeerStreamID {
		s.mu.Unlock()
		return errors.New(anyTLSStreamIDError)
	}
	s.lastPeerStreamID = id
	stream := newAnyTLSStream(id, s)
	s.streams[id] = stream
	s.wg.Add(1)
	s.mu.Unlock()
	go func() {
		defer s.wg.Done()
		defer stream.Close()
		s.onStream(stream)
	}()
	return nil
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

func (s *anyTLSServerSession) writeFrame(command byte, streamID uint32, data []byte) error {
	if len(data) > 65535 {
		return errors.New("AnyTLS frame payload is too large")
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	select {
	case <-s.closed:
		return io.ErrClosedPipe
	default:
	}
	frame := buf.NewWithSize(int32(anyTLSFrameHeaderSize + len(data)))
	defer frame.Release()
	header := frame.Extend(anyTLSFrameHeaderSize)
	header[0] = command
	binary.BigEndian.PutUint32(header[1:5], streamID)
	binary.BigEndian.PutUint16(header[5:7], uint16(len(data)))
	if _, err := frame.Write(data); err != nil {
		return err
	}
	if err := buf.WriteAllBytes(s.conn, frame.Bytes(), nil); err != nil {
		return errors.New("failed to write AnyTLS frame").Base(err)
	}
	s.activity.Update()
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

	mu           sync.Mutex
	ready        *sync.Cond
	space        *sync.Cond
	queue        []*buf.Buffer
	queueHead    int
	queuedBytes  int64
	queuedFrames int64
	readClosed   bool
	readErr      error
}

func newAnyTLSStream(id uint32, session *anyTLSServerSession) *anyTLSStream {
	stream := &anyTLSStream{id: id, session: session}
	stream.ready = sync.NewCond(&stream.mu)
	stream.space = sync.NewCond(&stream.mu)
	return stream
}

func (s *anyTLSStream) Read(payload []byte) (int, error) {
	if len(payload) == 0 {
		return 0, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for s.queueHead == len(s.queue) && !s.readClosed {
		s.ready.Wait()
	}
	if s.queueHead == len(s.queue) {
		if s.readErr != nil {
			return 0, s.readErr
		}
		return 0, io.EOF
	}

	queued := s.queue[s.queueHead]
	n, _ := queued.Read(payload)
	if queued.IsEmpty() {
		memory := int64(queued.Cap())
		queued.Release()
		s.queue[s.queueHead] = nil
		s.queueHead++
		s.queuedBytes -= memory
		s.queuedFrames--
		s.session.release(memory)
		s.space.Signal()
		if s.queueHead == len(s.queue) {
			s.queue = s.queue[:0]
			s.queueHead = 0
		}
	}
	return n, nil
}

func (s *anyTLSStream) Write(payload []byte) (int, error) {
	written := 0
	for len(payload) > 0 {
		length := min(len(payload), 65535)
		if err := s.session.writeFrame(anyTLSCmdPSH, s.id, payload[:length]); err != nil {
			return written, err
		}
		written += length
		payload = payload[length:]
	}
	return written, nil
}

// deliver transfers ownership of payload to the stream on success. The queue
// absorbs ordinary scheduling bursts. At its memory boundary, delivery waits
// for the consumer instead of dropping a reliable byte stream; stopping the
// session read loop then lets the underlying TCP receive window apply
// backpressure to an unmodified AnyTLS client.
func (s *anyTLSStream) deliver(payload *buf.Buffer) error {
	// Account the backing allocation rather than only logical payload bytes;
	// bytespool rounds capacities up and the memory bound must remain real.
	size := int64(payload.Cap())
	for {
		s.mu.Lock()
		for !s.readClosed && (s.queuedFrames >= anyTLSStreamQueuedFrames || s.queuedBytes+size > anyTLSStreamQueuedBytes) {
			s.space.Wait()
		}
		if s.readClosed {
			s.mu.Unlock()
			return io.ErrClosedPipe
		}
		s.mu.Unlock()

		if err := s.session.reserve(size); err != nil {
			return err
		}

		s.mu.Lock()
		if s.readClosed {
			s.mu.Unlock()
			s.session.release(size)
			return io.ErrClosedPipe
		}
		// The frame loop normally has a single producer. Recheck the local
		// limit so deliver remains correct if another producer is introduced.
		if s.queuedFrames >= anyTLSStreamQueuedFrames || s.queuedBytes+size > anyTLSStreamQueuedBytes {
			s.mu.Unlock()
			s.session.release(size)
			continue
		}
		if s.queueHead > 0 && s.queueHead*2 >= len(s.queue) {
			copy(s.queue, s.queue[s.queueHead:])
			s.queue = s.queue[:len(s.queue)-s.queueHead]
			s.queueHead = 0
		}
		s.queue = append(s.queue, payload)
		s.queuedBytes += size
		s.queuedFrames++
		s.ready.Signal()
		s.mu.Unlock()
		return nil
	}
}

func (s *anyTLSStream) Close() error {
	var closeErr error
	closedLocally := false
	s.once.Do(func() {
		closedLocally = true
		s.session.removeStream(s.id)
		s.closeRead(io.ErrClosedPipe, true)
		closeErr = s.session.writeFrame(anyTLSCmdFIN, s.id, nil)
	})
	if !closedLocally {
		// A remote FIN owns the protocol close, but the local handler still owns
		// cleanup of any queued bytes it chose not to consume.
		s.closeRead(io.ErrClosedPipe, true)
	}
	return closeErr
}

func (s *anyTLSStream) closeRemote() {
	s.once.Do(func() {
		s.closeRead(io.EOF, false)
	})
}

func (s *anyTLSStream) abortRemote() {
	s.once.Do(func() {
		s.closeRead(io.ErrClosedPipe, true)
	})
}

func (s *anyTLSStream) closeRead(err error, discard bool) {
	s.mu.Lock()
	s.readClosed = true
	s.readErr = err
	if discard {
		for s.queueHead < len(s.queue) {
			queued := s.queue[s.queueHead]
			s.session.release(int64(queued.Cap()))
			queued.Release()
			s.queue[s.queueHead] = nil
			s.queueHead++
		}
		s.queue = nil
		s.queueHead = 0
		s.queuedBytes = 0
		s.queuedFrames = 0
	}
	s.ready.Broadcast()
	s.space.Broadcast()
	s.mu.Unlock()
}

func (s *anyTLSServerSession) reserve(size int64) error {
	for {
		reserved, waitForSession := s.budget.reserve(size)
		if !reserved {
			select {
			case <-waitForSession:
				continue
			case <-s.closed:
				return io.ErrClosedPipe
			case <-s.ctx.Done():
				return s.ctx.Err()
			}
		}

		reserved, waitForGlobal := s.global.reserve(size)
		if reserved {
			return nil
		}
		s.budget.release(size)
		select {
		case <-waitForGlobal:
			continue
		case <-s.closed:
			return io.ErrClosedPipe
		case <-s.ctx.Done():
			return s.ctx.Err()
		}
	}
}

func (s *anyTLSServerSession) release(size int64) {
	s.budget.release(size)
	s.global.release(size)
}

func (s *anyTLSStream) handshakeSuccess() error {
	var reportErr error
	s.report.Do(func() {
		if s.session.peerVersion >= 2 {
			reportErr = s.session.writeFrame(anyTLSCmdSYNACK, s.id, nil)
		}
	})
	return reportErr
}

func (s *anyTLSStream) handshakeFailure(err error) error {
	var reportErr error
	s.report.Do(func() {
		if s.session.peerVersion >= 2 {
			reportErr = s.session.writeFrame(anyTLSCmdSYNACK, s.id, []byte(err.Error()))
		}
	})
	return reportErr
}

func (s *anyTLSStream) LocalAddr() net.Addr              { return s.session.conn.LocalAddr() }
func (s *anyTLSStream) RemoteAddr() net.Addr             { return s.session.conn.RemoteAddr() }
func (s *anyTLSStream) SetDeadline(time.Time) error      { return nil }
func (s *anyTLSStream) SetReadDeadline(time.Time) error  { return nil }
func (s *anyTLSStream) SetWriteDeadline(time.Time) error { return nil }

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
