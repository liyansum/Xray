package trojan

import (
	"bytes"
	"context"
	"crypto/sha256"
	gotls "crypto/tls"
	"io"
	"reflect"
	"sync"
	"time"
	"unsafe"

	"google.golang.org/protobuf/encoding/protowire"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/internet/tls"
)

type inboundProtocol byte

const (
	inboundUnknown inboundProtocol = iota
	inboundTrojan
	inboundVLESS
	inboundAnyTLS
)

var errNeedMoreData = errors.New("need more protocol authentication data")

type multiUserRegistry struct {
	mu     sync.RWMutex
	vless  map[[16]byte]*protocol.MemoryUser
	anytls map[[32]byte]*protocol.MemoryUser
}

func newMultiUserRegistry() multiUserRegistry {
	return multiUserRegistry{
		vless:  make(map[[16]byte]*protocol.MemoryUser),
		anytls: make(map[[32]byte]*protocol.MemoryUser),
	}
}

func userProtocolKeys(user *protocol.MemoryUser) ([16]byte, [32]byte, error) {
	var vlessKey [16]byte
	var anyTLSKey [32]byte
	account, ok := user.Account.(*MemoryAccount)
	if !ok {
		return vlessKey, anyTLSKey, errors.New("multi-protocol inbound requires a trojan account")
	}
	id, err := uuid.ParseString(account.Password)
	if err != nil {
		return vlessKey, anyTLSKey, errors.New("multi-protocol inbound password is not a UUID").Base(err)
	}
	copy(vlessKey[:], id[:])
	anyTLSKey = sha256.Sum256([]byte(account.Password))
	return vlessKey, anyTLSKey, nil
}

func (s *Server) addUser(user *protocol.MemoryUser) error {
	vlessKey, anyTLSKey, err := userProtocolKeys(user)
	if err != nil {
		return err
	}
	if err := s.validator.Add(user); err != nil {
		return err
	}
	s.multi.mu.Lock()
	s.multi.vless[vlessKey] = user
	s.multi.anytls[anyTLSKey] = user
	s.multi.mu.Unlock()
	return nil
}

func (s *Server) removeUser(email string) error {
	user := s.validator.GetByEmail(email)
	if user == nil {
		return s.validator.Del(email)
	}
	vlessKey, anyTLSKey, err := userProtocolKeys(user)
	if err != nil {
		return err
	}
	if err := s.validator.Del(email); err != nil {
		return err
	}
	s.multi.mu.Lock()
	delete(s.multi.vless, vlessKey)
	delete(s.multi.anytls, anyTLSKey)
	s.multi.mu.Unlock()
	return nil
}

func (s *Server) detectProtocol(data []byte) (inboundProtocol, *protocol.MemoryUser, error) {
	s.multi.mu.RLock()
	defer s.multi.mu.RUnlock()

	if len(data) >= sha256.Size {
		var key [sha256.Size]byte
		copy(key[:], data[:sha256.Size])
		if user := s.multi.anytls[key]; user != nil {
			return inboundAnyTLS, user, nil
		}
	}
	if len(data) >= userHashCRLF && data[userHashSize] == '\r' && data[userHashSize+1] == '\n' {
		if user := s.validator.Get(string(data[:userHashSize])); user != nil {
			return inboundTrojan, user, nil
		}
	}
	if len(data) >= 17 && data[0] == 0 {
		var key [16]byte
		copy(key[:], data[1:17])
		if user := s.multi.vless[key]; user != nil {
			return inboundVLESS, user, nil
		}
	}

	if len(data) < userHashCRLF && isTrojanUserHashPrefix(data) {
		return inboundUnknown, nil, errNeedMoreData
	}
	// Do not wait based on a registered VLESS or AnyTLS credential prefix. Apart
	// from exposing a user-specific timing oracle, doing so would make arbitrary
	// active probes behave differently from the original Trojan fallback. Both
	// binary protocols send their complete authentication discriminator in the
	// initial TLS application write.
	return inboundUnknown, nil, errors.New("not trojan, VLESS, or AnyTLS")
}

func (s *Server) processTrojan(ctx context.Context, conn stat.Connection, reader *buf.BufferedReader, user *protocol.MemoryUser, dispatcher routing.Dispatcher) error {
	clientReader := &ConnReader{Reader: reader}
	if err := clientReader.ParseHeader(); err != nil {
		log.Record(&log.AccessMessage{From: conn.RemoteAddr(), Status: log.AccessRejected, Reason: err})
		return errors.New("failed to create trojan request from: ", conn.RemoteAddr()).Base(err)
	}
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		return errors.New("unable to clear trojan handshake deadline").Base(err)
	}

	destination := clientReader.Target
	inbound := session.InboundFromContext(ctx)
	if inbound == nil {
		return errors.New("missing inbound metadata")
	}
	inbound.Name = "trojan"
	inbound.CanSpliceCopy = 3
	inbound.User = user
	sessionPolicy := s.policyManager.ForLevel(user.Level)

	if destination.Network == net.Network_UDP {
		return s.handleUDPPayload(ctx, sessionPolicy, &PacketReader{Reader: clientReader}, &PacketWriter{Writer: conn}, dispatcher)
	}

	ctx = log.ContextWithAccessMessage(ctx, &log.AccessMessage{
		From: conn.RemoteAddr(), To: destination, Status: log.AccessAccepted, Email: user.Email,
	})
	return s.handleConnection(ctx, sessionPolicy, destination, clientReader, buf.NewWriter(conn), dispatcher)
}

var vlessAddressParser = protocol.NewAddressParser(
	protocol.AddressFamilyByte(0x01, net.AddressFamilyIPv4),
	protocol.AddressFamilyByte(0x02, net.AddressFamilyDomain),
	protocol.AddressFamilyByte(0x03, net.AddressFamilyIPv6),
	protocol.PortThenAddress(),
)

func decodeVLESSFlow(addons []byte) (string, error) {
	var flow string
	for len(addons) > 0 {
		number, typ, n := protowire.ConsumeTag(addons)
		if n < 0 {
			return "", errors.New("invalid VLESS addons tag")
		}
		addons = addons[n:]
		if number == 1 && typ == protowire.BytesType {
			value, n := protowire.ConsumeBytes(addons)
			if n < 0 {
				return "", errors.New("invalid VLESS flow addon")
			}
			flow = string(value)
			addons = addons[n:]
			continue
		}
		n = protowire.ConsumeFieldValue(number, typ, addons)
		if n < 0 {
			return "", errors.New("invalid VLESS addons value")
		}
		addons = addons[n:]
	}
	return flow, nil
}

func readVLESSRequest(reader io.Reader, expectedUser *protocol.MemoryUser) ([]byte, net.Destination, string, error) {
	var fixed [17]byte
	if _, err := io.ReadFull(reader, fixed[:]); err != nil {
		return nil, net.Destination{}, "", errors.New("failed to read VLESS authentication").Base(err)
	}
	if fixed[0] != 0 {
		return nil, net.Destination{}, "", errors.New("unsupported VLESS version")
	}
	expectedID, _, err := userProtocolKeys(expectedUser)
	if err != nil || !bytes.Equal(fixed[1:], expectedID[:]) {
		return nil, net.Destination{}, "", errors.New("VLESS user changed during authentication")
	}

	var addonLength [1]byte
	if _, err := io.ReadFull(reader, addonLength[:]); err != nil {
		return nil, net.Destination{}, "", errors.New("failed to read VLESS addons length").Base(err)
	}
	addons := make([]byte, int(addonLength[0]))
	if _, err := io.ReadFull(reader, addons); err != nil {
		return nil, net.Destination{}, "", errors.New("failed to read VLESS addons").Base(err)
	}
	flow, err := decodeVLESSFlow(addons)
	if err != nil {
		return nil, net.Destination{}, "", err
	}
	if flow != "" && flow != "xtls-rprx-vision" {
		return nil, net.Destination{}, "", errors.New("unsupported VLESS flow: ", flow)
	}

	var command [1]byte
	if _, err := io.ReadFull(reader, command[:]); err != nil {
		return nil, net.Destination{}, "", errors.New("failed to read VLESS command").Base(err)
	}
	if protocol.RequestCommand(command[0]) != protocol.RequestCommandTCP {
		return nil, net.Destination{}, "", errors.New("VLESS inbound only accepts TCP")
	}
	address, port, err := vlessAddressParser.ReadAddressPort(nil, reader)
	if err != nil {
		return nil, net.Destination{}, "", errors.New("failed to read VLESS destination").Base(err)
	}
	return append([]byte(nil), fixed[1:]...), net.TCPDestination(address, port), flow, nil
}

func visionTLSBuffers(iConn stat.Connection) (*bytes.Reader, *bytes.Buffer, error) {
	tlsConn, ok := iConn.(*tls.Conn)
	if !ok {
		return nil, nil, errors.New("VLESS Vision requires the existing TLS transport directly")
	}
	if tlsConn.ConnectionState().Version != gotls.VersionTLS13 {
		return nil, nil, errors.New("VLESS Vision requires outer TLS 1.3")
	}
	t := reflect.TypeOf(tlsConn.Conn).Elem()
	inputField, okInput := t.FieldByName("input")
	rawInputField, okRawInput := t.FieldByName("rawInput")
	if !okInput || !okRawInput {
		return nil, nil, errors.New("TLS implementation does not expose Vision input buffers")
	}
	p := unsafe.Pointer(tlsConn.Conn)
	input := (*bytes.Reader)(unsafe.Add(p, inputField.Offset))
	rawInput := (*bytes.Buffer)(unsafe.Add(p, rawInputField.Offset))
	return input, rawInput, nil
}

func (s *Server) processVLESS(ctx context.Context, conn stat.Connection, iConn stat.Connection, reader *buf.BufferedReader, user *protocol.MemoryUser, dispatcher routing.Dispatcher) error {
	userID, destination, flow, err := readVLESSRequest(reader, user)
	if err != nil {
		return err
	}
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		return errors.New("unable to clear VLESS handshake deadline").Base(err)
	}
	var input *bytes.Reader
	var rawInput *bytes.Buffer
	if flow == "xtls-rprx-vision" {
		input, rawInput, err = visionTLSBuffers(iConn)
		if err != nil {
			return err
		}
	}
	inbound := session.InboundFromContext(ctx)
	if inbound == nil {
		return errors.New("missing inbound metadata")
	}
	inbound.Name = "vless"
	inbound.User = user
	if flow == "xtls-rprx-vision" {
		inbound.CanSpliceCopy = 2
	} else {
		inbound.CanSpliceCopy = 3
	}

	ctx = log.ContextWithAccessMessage(ctx, &log.AccessMessage{
		From: conn.RemoteAddr(), To: destination, Status: log.AccessAccepted, Email: user.Email,
	})
	ctx = policy.ContextWithBufferPolicy(ctx, s.policyManager.ForLevel(user.Level).Buffer)

	bufferedWriter := buf.NewBufferedWriter(buf.NewWriter(conn))
	if _, err := bufferedWriter.Write([]byte{0, 0}); err != nil {
		return errors.New("failed to encode VLESS response header").Base(err)
	}
	var clientReader buf.Reader = reader
	var clientWriter buf.Writer = bufferedWriter
	if flow == "xtls-rprx-vision" {
		trafficState := proxy.NewTrafficState(userID)
		clientReader = proxy.NewVisionReader(reader, trafficState, true, ctx, conn, input, rawInput, nil)
		clientWriter = proxy.NewVisionWriter(bufferedWriter, trafficState, false, ctx, conn, nil, nil)
	}
	bufferedWriter.SetFlushNext()

	if err := dispatcher.DispatchLink(ctx, destination, &transport.Link{Reader: clientReader, Writer: clientWriter}); err != nil {
		return errors.New("failed to dispatch VLESS request").Base(err)
	}
	return nil
}
