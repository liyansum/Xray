package trojan

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"io"
	stdnet "net"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protowire"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
)

const testUUID = "550e8400-e29b-41d4-a716-446655440000"

const secondTestUUID = "7d9e5f26-75e4-4f7e-9c49-2b8d619cdb93"

func testMultiUser(t testing.TB) *protocol.MemoryUser {
	t.Helper()
	return testMultiUserWithCredentials(t, testUUID, "multi@example.com")
}

func testMultiUserWithCredentials(t testing.TB, password, email string) *protocol.MemoryUser {
	t.Helper()
	account, err := (&Account{Password: password}).AsAccount()
	if err != nil {
		t.Fatal(err)
	}
	return &protocol.MemoryUser{Email: email, Level: 1, Account: account}
}

func testMultiServer(t testing.TB) (*Server, *protocol.MemoryUser) {
	t.Helper()
	server := &Server{validator: new(Validator), multi: newMultiUserRegistry()}
	user := testMultiUser(t)
	if err := server.addUser(user); err != nil {
		t.Fatal(err)
	}
	return server, user
}

func TestMultiProtocolAuthentication(t *testing.T) {
	server, user := testMultiServer(t)

	trojanCredential := append(append([]byte(nil), user.Account.(*MemoryAccount).Key...), '\r', '\n')
	anyTLSCredential := sha256.Sum256([]byte(testUUID))
	vlessID, _, err := userProtocolKeys(user)
	if err != nil {
		t.Fatal(err)
	}
	vlessCredential := append([]byte{0}, vlessID[:]...)

	tests := []struct {
		name       string
		credential []byte
		kind       inboundProtocol
	}{
		{name: "trojan", credential: trojanCredential, kind: inboundTrojan},
		{name: "vless", credential: vlessCredential, kind: inboundVLESS},
		{name: "anytls-v2", credential: anyTLSCredential[:], kind: inboundAnyTLS},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			kind, gotUser, err := server.detectProtocol(test.credential)
			if err != nil || kind != test.kind || gotUser != user {
				t.Fatalf("kind=%d user=%v err=%v", kind, gotUser, err)
			}
		})
	}
	for split := 1; split < len(trojanCredential); split++ {
		kind, gotUser, err := server.detectProtocol(trojanCredential[:split])
		if err != errNeedMoreData {
			t.Fatalf("fragmented Trojan split %d: expected more data, got kind=%d user=%v err=%v", split, kind, gotUser, err)
		}
	}

	for name, probe := range map[string][]byte{
		"matching AnyTLS hash prefix": anyTLSCredential[:16],
		"unrelated binary prefix":     {0xff, 0x7f, 0x10, 0x80},
		"VLESS-looking prefix":        vlessCredential[:16],
	} {
		if _, gotUser, err := server.detectProtocol(probe); err == nil || err == errNeedMoreData || gotUser != nil {
			t.Fatalf("%s exposed a credential-dependent wait: user=%v err=%v", name, gotUser, err)
		}
	}

	if _, _, err := server.detectProtocol([]byte("GET / HTTP/1.1\r\n")); err == nil || err == errNeedMoreData {
		t.Fatalf("HTTP probe should be sent to fallback, got %v", err)
	}
}

func TestMultiProtocolDynamicUserUpdate(t *testing.T) {
	server, user := testMultiServer(t)
	credential := sha256.Sum256([]byte(testUUID))
	if err := server.removeUser(user.Email); err != nil {
		t.Fatal(err)
	}
	if _, gotUser, err := server.detectProtocol(credential[:]); err == nil || gotUser != nil {
		t.Fatalf("removed AnyTLS user was accepted: user=%v err=%v", gotUser, err)
	}
	if err := server.addUser(user); err != nil {
		t.Fatal(err)
	}
	if kind, gotUser, err := server.detectProtocol(credential[:]); err != nil || kind != inboundAnyTLS || gotUser != user {
		t.Fatalf("re-added AnyTLS user was not accepted: kind=%d user=%v err=%v", kind, gotUser, err)
	}
}

func TestMultiProtocolAuthenticationSeparatesUsers(t *testing.T) {
	server := &Server{validator: new(Validator), multi: newMultiUserRegistry()}
	users := []*protocol.MemoryUser{
		testMultiUserWithCredentials(t, testUUID, "first@example.com"),
		testMultiUserWithCredentials(t, secondTestUUID, "second@example.com"),
	}
	for _, user := range users {
		if err := server.addUser(user); err != nil {
			t.Fatal(err)
		}
	}

	for _, user := range users {
		vlessID, anyTLSHash, err := userProtocolKeys(user)
		if err != nil {
			t.Fatal(err)
		}
		credentials := []struct {
			kind inboundProtocol
			data []byte
		}{
			{kind: inboundTrojan, data: append(append([]byte(nil), user.Account.(*MemoryAccount).Key...), '\r', '\n')},
			{kind: inboundVLESS, data: append([]byte{0}, vlessID[:]...)},
			{kind: inboundAnyTLS, data: anyTLSHash[:]},
		}
		for _, credential := range credentials {
			kind, authenticated, err := server.detectProtocol(credential.data)
			if err != nil || kind != credential.kind || authenticated != user {
				t.Fatalf("email=%s kind=%d authenticated=%v err=%v", user.Email, kind, authenticated, err)
			}
		}
	}

	unknown := testMultiUserWithCredentials(t, "c5d92df3-b90a-4adb-94d6-818a28bff9c0", "unknown@example.com")
	unknownVLESS, unknownAnyTLS, err := userProtocolKeys(unknown)
	if err != nil {
		t.Fatal(err)
	}
	for name, credential := range map[string][]byte{
		"trojan": append(append([]byte(nil), unknown.Account.(*MemoryAccount).Key...), '\r', '\n'),
		"vless":  append([]byte{0}, unknownVLESS[:]...),
		"anytls": unknownAnyTLS[:],
	} {
		if _, authenticated, err := server.detectProtocol(credential); err == nil || authenticated != nil {
			t.Fatalf("unknown %s credential was accepted as %v", name, authenticated)
		}
	}
}

func TestMultiProtocolRejectsDuplicateUUID(t *testing.T) {
	server := &Server{validator: new(Validator), multi: newMultiUserRegistry()}
	first := testMultiUserWithCredentials(t, testUUID, "first@example.com")
	// UUID parsing is case-insensitive for VLESS, so a differently formatted
	// password must not overwrite the first user's normalized VLESS identity.
	duplicate := testMultiUserWithCredentials(t, strings.ToUpper(testUUID), "duplicate@example.com")
	if err := server.addUser(first); err != nil {
		t.Fatal(err)
	}
	if err := server.addUser(duplicate); err == nil {
		t.Fatal("the same UUID was assigned to two users")
	}

	vlessID, anyTLSHash, err := userProtocolKeys(first)
	if err != nil {
		t.Fatal(err)
	}
	for _, credential := range [][]byte{
		append(append([]byte(nil), first.Account.(*MemoryAccount).Key...), '\r', '\n'),
		append([]byte{0}, vlessID[:]...),
		anyTLSHash[:],
	} {
		_, authenticated, err := server.detectProtocol(credential)
		if err != nil || authenticated != first {
			t.Fatalf("duplicate UUID changed credential ownership: user=%v err=%v", authenticated, err)
		}
	}
	if server.validator.GetByEmail(duplicate.Email) != nil {
		t.Fatal("rejected duplicate user remained registered by email")
	}
}

func TestMultiProtocolAuthenticationDuringUserUpdates(t *testing.T) {
	server := &Server{validator: new(Validator), multi: newMultiUserRegistry()}
	stable := testMultiUserWithCredentials(t, testUUID, "stable@example.com")
	rotating := testMultiUserWithCredentials(t, secondTestUUID, "rotating@example.com")
	if err := server.addUser(stable); err != nil {
		t.Fatal(err)
	}
	if err := server.addUser(rotating); err != nil {
		t.Fatal(err)
	}
	stableVLESS, stableAnyTLS, err := userProtocolKeys(stable)
	if err != nil {
		t.Fatal(err)
	}
	credentials := [][]byte{
		append(append([]byte(nil), stable.Account.(*MemoryAccount).Key...), '\r', '\n'),
		append([]byte{0}, stableVLESS[:]...),
		stableAnyTLS[:],
	}

	updates := make(chan error, 1)
	go func() {
		for range 1_000 {
			if err := server.removeUser(rotating.Email); err != nil {
				updates <- err
				return
			}
			if err := server.addUser(rotating); err != nil {
				updates <- err
				return
			}
		}
		updates <- nil
	}()

	for range 5_000 {
		for _, credential := range credentials {
			_, authenticated, err := server.detectProtocol(credential)
			if err != nil || authenticated != stable {
				t.Fatalf("stable credential changed during another user update: user=%v err=%v", authenticated, err)
			}
		}
	}
	if err := <-updates; err != nil {
		t.Fatal(err)
	}
}

func makeVLESSRequest(t *testing.T, user *protocol.MemoryUser, flow string) []byte {
	return makeVLESSRequestFor(t, user, flow, protocol.RequestCommandTCP, net.TCPDestination(net.DomainAddress("example.com"), 443))
}

func makeVLESSRequestFor(t *testing.T, user *protocol.MemoryUser, flow string, command protocol.RequestCommand, destination net.Destination) []byte {
	t.Helper()
	id, _, err := userProtocolKeys(user)
	if err != nil {
		t.Fatal(err)
	}
	request := append([]byte{0}, id[:]...)
	var addons []byte
	if flow != "" {
		addons = protowire.AppendTag(addons, 1, protowire.BytesType)
		addons = protowire.AppendString(addons, flow)
	}
	request = append(request, byte(len(addons)))
	request = append(request, addons...)
	request = append(request, byte(command))
	if command == protocol.RequestCommandMux {
		return request
	}
	var encodedDestination bytes.Buffer
	if err := vlessAddressParser.WriteAddressPort(&encodedDestination, destination.Address, destination.Port); err != nil {
		t.Fatal(err)
	}
	return append(request, encodedDestination.Bytes()...)
}

func TestVLESSRequestFlowModes(t *testing.T) {
	user := testMultiUser(t)
	for _, expectedFlow := range []string{"", "xtls-rprx-vision"} {
		request := makeVLESSRequest(t, user, expectedFlow)
		id, destination, flow, command, err := readVLESSRequest(bytes.NewReader(request), user)
		if err != nil {
			t.Fatal(err)
		}
		if len(id) != 16 || destination.String() != "tcp:example.com:443" || flow != expectedFlow || command != protocol.RequestCommandTCP {
			t.Fatalf("id=%x destination=%s flow=%q command=%v", id, destination.String(), flow, command)
		}
	}
	if _, _, _, _, err := readVLESSRequest(bytes.NewReader(makeVLESSRequest(t, user, "unsupported-flow")), user); err == nil {
		t.Fatal("unsupported VLESS flow was accepted")
	}

	udpDestination := net.UDPDestination(net.DomainAddress("quic.example"), 443)
	udpRequest := makeVLESSRequestFor(t, user, "", protocol.RequestCommandUDP, udpDestination)
	_, destination, flow, command, err := readVLESSRequest(bytes.NewReader(udpRequest), user)
	if err != nil || destination != udpDestination || flow != "" || command != protocol.RequestCommandUDP {
		t.Fatalf("UDP destination=%s flow=%q command=%v err=%v", destination, flow, command, err)
	}
	visionUDP := makeVLESSRequestFor(t, user, vlessVisionFlow, protocol.RequestCommandUDP, udpDestination)
	if _, _, _, _, err := readVLESSRequest(bytes.NewReader(visionUDP), user); err == nil {
		t.Fatal("Vision direct UDP was accepted instead of requiring XUDP")
	}

	for _, wireFlow := range []string{vlessVisionFlow, vlessVisionUDP443Flow} {
		muxRequest := makeVLESSRequestFor(t, user, wireFlow, protocol.RequestCommandMux, net.Destination{})
		_, destination, flow, command, err := readVLESSRequest(bytes.NewReader(muxRequest), user)
		if err != nil || destination != vlessMuxDestination || flow != vlessVisionFlow || command != protocol.RequestCommandMux {
			t.Fatalf("flow=%q Mux destination=%s normalizedFlow=%q command=%v err=%v", wireFlow, destination, flow, command, err)
		}
	}
}

func TestVLESSUDPPacketCodecPreservesDatagrams(t *testing.T) {
	var wire bytes.Buffer
	writer := newVLESSMultiLengthPacketWriter(buf.NewWriter(&wire))
	packets := [][]byte{{0xc3, 0, 0, 1, 'q'}, []byte("second-datagram")}
	mb := make(buf.MultiBuffer, 0, len(packets))
	for _, packet := range packets {
		mb = append(mb, buf.FromBytes(packet))
	}
	if err := writer.WriteMultiBuffer(mb); err != nil {
		t.Fatal(err)
	}

	reader := newVLESSLengthPacketReader(&wire)
	for _, expected := range packets {
		packet, err := reader.ReadMultiBuffer()
		if err != nil {
			t.Fatal(err)
		}
		data := make([]byte, packet.Len())
		packet.Copy(data)
		buf.ReleaseMulti(packet)
		if !bytes.Equal(data, expected) {
			t.Fatalf("packet=%x expected=%x", data, expected)
		}
	}
}

type testActivity struct{}

func (testActivity) Update() {}

func writeTestAnyTLSFrame(t *testing.T, writer io.Writer, command byte, streamID uint32, data []byte) {
	t.Helper()
	frame := make([]byte, anyTLSFrameHeaderSize+len(data))
	frame[0] = command
	binary.BigEndian.PutUint32(frame[1:5], streamID)
	binary.BigEndian.PutUint16(frame[5:7], uint16(len(data)))
	copy(frame[7:], data)
	if _, err := writer.Write(frame); err != nil {
		t.Fatal(err)
	}
}

func readTestAnyTLSFrame(t *testing.T, reader io.Reader) (byte, uint32, []byte) {
	t.Helper()
	var header [anyTLSFrameHeaderSize]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		t.Fatal(err)
	}
	data := make([]byte, int(binary.BigEndian.Uint16(header[5:7])))
	if _, err := io.ReadFull(reader, data); err != nil {
		t.Fatal(err)
	}
	return header[0], binary.BigEndian.Uint32(header[1:5]), data
}

func TestAnyTLSV2Session(t *testing.T) {
	serverConn, clientConn := stdnet.Pipe()
	defer clientConn.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	session := newAnyTLSServerSession(ctx, serverConn, serverConn, testActivity{}, func(stream *anyTLSStream) {
		if err := stream.handshakeSuccess(); err != nil {
			return
		}
		payload := make([]byte, 4)
		if _, err := io.ReadFull(stream, payload); err == nil && bytes.Equal(payload, []byte("ping")) {
			_, _ = stream.Write([]byte("pong"))
		}
	})
	done := make(chan error, 1)
	go func() { done <- session.run() }()

	settings := []byte("v=2\nclient=xray-test\npadding-md5=" + anyTLSPaddingMD5)
	writeTestAnyTLSFrame(t, clientConn, anyTLSCmdSettings, 0, settings)
	command, _, data := readTestAnyTLSFrame(t, clientConn)
	if command != anyTLSCmdServerSetting || string(data) != "v=2" {
		t.Fatalf("unexpected server settings: command=%d data=%q", command, data)
	}

	writeTestAnyTLSFrame(t, clientConn, anyTLSCmdSYN, 1, nil)
	command, streamID, _ := readTestAnyTLSFrame(t, clientConn)
	if command != anyTLSCmdSYNACK || streamID != 1 {
		t.Fatalf("unexpected SYNACK: command=%d stream=%d", command, streamID)
	}

	writeTestAnyTLSFrame(t, clientConn, anyTLSCmdPSH, 1, []byte("ping"))
	command, streamID, data = readTestAnyTLSFrame(t, clientConn)
	if command != anyTLSCmdPSH || streamID != 1 || string(data) != "pong" {
		t.Fatalf("unexpected stream payload: command=%d stream=%d data=%q", command, streamID, data)
	}
	command, streamID, _ = readTestAnyTLSFrame(t, clientConn)
	if command != anyTLSCmdFIN || streamID != 1 {
		t.Fatalf("unexpected FIN: command=%d stream=%d", command, streamID)
	}

	_ = clientConn.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("AnyTLS server session did not stop")
	}
}

func TestAnyTLSV1Session(t *testing.T) {
	serverConn, clientConn := stdnet.Pipe()
	defer clientConn.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	session := newAnyTLSServerSession(ctx, serverConn, serverConn, testActivity{}, func(stream *anyTLSStream) {
		if err := stream.handshakeSuccess(); err != nil {
			return
		}
		payload := make([]byte, 4)
		if _, err := io.ReadFull(stream, payload); err == nil && bytes.Equal(payload, []byte("ping")) {
			_, _ = stream.Write([]byte("pong"))
		}
	})
	done := make(chan error, 1)
	go func() { done <- session.run() }()

	settings := []byte("v=1\nclient=xray-test\npadding-md5=" + anyTLSPaddingMD5)
	writeTestAnyTLSFrame(t, clientConn, anyTLSCmdSettings, 0, settings)
	writeTestAnyTLSFrame(t, clientConn, anyTLSCmdHeartRequest, 0, nil)
	writeTestAnyTLSFrame(t, clientConn, anyTLSCmdSYN, 1, nil)
	writeTestAnyTLSFrame(t, clientConn, anyTLSCmdPSH, 1, []byte("ping"))

	command, streamID, data := readTestAnyTLSFrame(t, clientConn)
	if command != anyTLSCmdPSH || streamID != 1 || string(data) != "pong" {
		t.Fatalf("v1 received a v2 control frame or bad payload: command=%d stream=%d data=%q", command, streamID, data)
	}
	command, streamID, _ = readTestAnyTLSFrame(t, clientConn)
	if command != anyTLSCmdFIN || streamID != 1 {
		t.Fatalf("unexpected FIN: command=%d stream=%d", command, streamID)
	}

	_ = clientConn.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("AnyTLS v1 server session did not stop")
	}
}

func TestAnyTLSRejectsNonIncreasingStreamID(t *testing.T) {
	for _, test := range []struct {
		name      string
		streamIDs []uint32
	}{
		{name: "duplicate", streamIDs: []uint32{2, 2}},
		{name: "decreasing", streamIDs: []uint32{2, 1}},
	} {
		t.Run(test.name, func(t *testing.T) {
			serverConn, clientConn := stdnet.Pipe()
			defer clientConn.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			session := newAnyTLSServerSession(ctx, serverConn, serverConn, testActivity{}, func(*anyTLSStream) {})
			done := make(chan error, 1)
			go func() { done <- session.run() }()

			settings := []byte("v=2\nclient=xray-test\npadding-md5=" + anyTLSPaddingMD5)
			writeTestAnyTLSFrame(t, clientConn, anyTLSCmdSettings, 0, settings)
			if command, _, _ := readTestAnyTLSFrame(t, clientConn); command != anyTLSCmdServerSetting {
				t.Fatalf("unexpected server settings command: %d", command)
			}

			writeTestAnyTLSFrame(t, clientConn, anyTLSCmdSYN, test.streamIDs[0], nil)
			if command, streamID, _ := readTestAnyTLSFrame(t, clientConn); command != anyTLSCmdFIN || streamID != test.streamIDs[0] {
				t.Fatalf("unexpected first stream response: command=%d stream=%d", command, streamID)
			}

			writeTestAnyTLSFrame(t, clientConn, anyTLSCmdSYN, test.streamIDs[1], nil)
			command, streamID, data := readTestAnyTLSFrame(t, clientConn)
			if command != anyTLSCmdAlert || streamID != 0 || string(data) != "AnyTLS stream ID is not strictly increasing" {
				t.Fatalf("unexpected invalid-ID response: command=%d stream=%d data=%q", command, streamID, data)
			}

			select {
			case err := <-done:
				if err == nil || !strings.Contains(err.Error(), "stream ID is not strictly increasing") {
					t.Fatalf("unexpected session result: %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("AnyTLS session remained open after an invalid stream ID")
			}
		})
	}
}

func TestAnyTLSDoesNotCapActiveIncreasingStreams(t *testing.T) {
	const streamCount = 300
	serverConn, clientConn := stdnet.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	opened := make(chan uint32, streamCount)
	release := make(chan struct{})
	session := newAnyTLSServerSession(ctx, serverConn, serverConn, testActivity{}, func(stream *anyTLSStream) {
		opened <- stream.id
		<-release
	})
	done := make(chan error, 1)
	go func() { done <- session.run() }()

	settings := []byte("v=1\nclient=xray-test\npadding-md5=" + anyTLSPaddingMD5)
	writeTestAnyTLSFrame(t, clientConn, anyTLSCmdSettings, 0, settings)
	for i := uint32(0); i < streamCount; i++ {
		writeTestAnyTLSFrame(t, clientConn, anyTLSCmdSYN, i*2+1, nil)
	}
	for i := uint32(0); i < streamCount; i++ {
		select {
		case streamID := <-opened:
			if streamID == 0 || streamID%2 == 0 {
				t.Fatalf("unexpected stream ID: %d", streamID)
			}
		case <-time.After(time.Second):
			t.Fatalf("only %d of %d increasing streams were opened", i, streamCount)
		}
	}

	_ = clientConn.Close()
	close(release)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("AnyTLS server session did not stop")
	}
}

func TestAnyTLSUoTPacket(t *testing.T) {
	var packet bytes.Buffer
	destination := net.UDPDestination(net.DomainAddress("dns.example"), 53)
	if err := writeAnyTLSUoTPacket(&packet, false, destination, []byte("query")); err != nil {
		t.Fatal(err)
	}
	address, port, err := anyTLSUoTAddressParser.ReadAddressPort(nil, &packet)
	if err != nil {
		t.Fatal(err)
	}
	var length [2]byte
	if _, err := io.ReadFull(&packet, length[:]); err != nil {
		t.Fatal(err)
	}
	if address.Domain() != "dns.example" || port != 53 || binary.BigEndian.Uint16(length[:]) != 5 || packet.String() != "query" {
		t.Fatalf("address=%s port=%d length=%d payload=%q", address, port, binary.BigEndian.Uint16(length[:]), packet.String())
	}
}

func BenchmarkMultiProtocolDetection(b *testing.B) {
	server, user := testMultiServer(b)
	vlessID, anyTLSHash, err := userProtocolKeys(user)
	if err != nil {
		b.Fatal(err)
	}
	credentials := map[string][]byte{
		"trojan": append(append([]byte(nil), user.Account.(*MemoryAccount).Key...), '\r', '\n'),
		"vless":  append([]byte{0}, vlessID[:]...),
		"anytls": anyTLSHash[:],
	}
	for name, credential := range credentials {
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			for range b.N {
				if _, _, err := server.detectProtocol(credential); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
