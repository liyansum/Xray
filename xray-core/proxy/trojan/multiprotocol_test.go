package trojan

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	stdnet "net"
	"strings"
	"sync"
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
	for _, wireFlow := range []string{vlessVisionFlow, vlessVisionUDP443Flow} {
		visionUDP := makeVLESSRequestFor(t, user, wireFlow, protocol.RequestCommandUDP, udpDestination)
		_, destination, flow, command, err := readVLESSRequest(bytes.NewReader(visionUDP), user)
		if err != nil || destination != udpDestination || flow != vlessVisionFlow || command != protocol.RequestCommandUDP {
			t.Fatalf("flow=%q UDP destination=%s normalizedFlow=%q command=%v err=%v", wireFlow, destination, flow, command, err)
		}
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
	largePacket := bytes.Repeat([]byte{0x5a}, buf.Size+1024)
	packets := [][]byte{{0xc3, 0, 0, 1, 'q'}, []byte("second-datagram"), largePacket}
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
		if len(packet) != 1 {
			t.Fatalf("one datagram was split into %d buffers", len(packet))
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

func TestAnyTLSSynchronousPipeBackpressuresSession(t *testing.T) {
	serverConn, clientConn := stdnet.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	slowOpened := make(chan struct{})
	releaseRead := make(chan struct{})
	slowConsumed := make(chan struct{})
	releaseSlow := make(chan struct{})
	session := newAnyTLSServerSession(ctx, serverConn, serverConn, testActivity{}, func(stream *anyTLSStream) {
		if stream.id == 1 {
			close(slowOpened)
			<-releaseRead
			payload := make([]byte, len("unread payload"))
			_, _ = io.ReadFull(stream, payload)
			close(slowConsumed)
			<-releaseSlow
			return
		}
		_ = stream.handshakeSuccess()
	})
	done := make(chan error, 1)
	go func() { done <- session.run() }()

	settings := []byte("v=2\nclient=xray-test\npadding-md5=" + anyTLSPaddingMD5)
	writeTestAnyTLSFrame(t, clientConn, anyTLSCmdSettings, 0, settings)
	if command, _, _ := readTestAnyTLSFrame(t, clientConn); command != anyTLSCmdServerSetting {
		t.Fatalf("unexpected server settings command: %d", command)
	}
	writeTestAnyTLSFrame(t, clientConn, anyTLSCmdSYN, 1, nil)
	<-slowOpened
	writeTestAnyTLSFrame(t, clientConn, anyTLSCmdPSH, 1, []byte("unread payload"))

	nextFrame := make([]byte, anyTLSFrameHeaderSize)
	nextFrame[0] = anyTLSCmdSYN
	binary.BigEndian.PutUint32(nextFrame[1:5], 3)
	nextWrite := make(chan error, 1)
	go func() {
		_, err := clientConn.Write(nextFrame)
		nextWrite <- err
	}()
	select {
	case err := <-nextWrite:
		t.Fatalf("session read another frame before the stream consumed PSH: %v", err)
	case <-time.After(25 * time.Millisecond):
	}

	close(releaseRead)
	select {
	case <-slowConsumed:
	case <-time.After(time.Second):
		t.Fatal("slow stream did not consume its synchronous PSH")
	}
	select {
	case err := <-nextWrite:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("session did not resume after the stream consumed PSH")
	}

	command, streamID, _ := readTestAnyTLSFrame(t, clientConn)
	if command != anyTLSCmdSYNACK || streamID != 3 {
		t.Fatalf("unexpected resumed stream response: command=%d stream=%d", command, streamID)
	}

	_ = clientConn.Close()
	close(releaseSlow)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("AnyTLS server session did not stop")
	}
}

func TestAnyTLSSynchronousPipeHasNoReceiveQueue(t *testing.T) {
	serverConn, clientConn := stdnet.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()
	session := newAnyTLSServerSession(context.Background(), serverConn, serverConn, testActivity{}, func(*anyTLSStream) {})
	stream := newAnyTLSStream(1, session)

	payload := buf.FromBytes(bytes.Repeat([]byte{0x5a}, 8192))
	defer payload.Release()
	delivered := make(chan error, 1)
	go func() { delivered <- stream.deliver(payload) }()
	select {
	case err := <-delivered:
		stream.abortRemote()
		t.Fatalf("synchronous delivery returned before a reader consumed it: %v", err)
	case <-time.After(25 * time.Millisecond):
	}

	readBuffer := make([]byte, payload.Len())
	if _, err := io.ReadFull(stream, readBuffer); err != nil {
		stream.abortRemote()
		t.Fatal(err)
	}
	select {
	case err := <-delivered:
		if err != nil {
			stream.abortRemote()
			t.Fatalf("synchronous delivery failed after consumption: %v", err)
		}
	case <-time.After(time.Second):
		stream.abortRemote()
		t.Fatal("synchronous delivery remained blocked after consumption")
	}
	stream.abortRemote()
}

func TestAnyTLSConcurrentUplinkThroughput(t *testing.T) {
	const (
		streamCount    = 8
		bytesPerStream = 2 * 1024 * 1024
		frameSize      = 32 * 1024
	)
	serverConn, clientConn := stdnet.Pipe()
	defer clientConn.Close()

	opened := make(chan uint32, streamCount)
	completed := make(chan error, streamCount)
	releaseHandlers := make(chan struct{})
	session := newAnyTLSServerSession(context.Background(), serverConn, serverConn, testActivity{}, func(stream *anyTLSStream) {
		opened <- stream.id
		buffer := make([]byte, frameSize)
		remaining := bytesPerStream
		for remaining > 0 {
			length := min(remaining, len(buffer))
			if _, err := io.ReadFull(stream, buffer[:length]); err != nil {
				completed <- err
				return
			}
			for _, value := range buffer[:length] {
				if value != byte(stream.id) {
					completed <- errors.New("payload crossed AnyTLS streams")
					return
				}
			}
			remaining -= length
		}
		completed <- nil
		<-releaseHandlers
	})
	done := make(chan error, 1)
	go func() { done <- session.run() }()

	settings := []byte("v=1\nclient=xray-test\npadding-md5=" + anyTLSPaddingMD5)
	writeTestAnyTLSFrame(t, clientConn, anyTLSCmdSettings, 0, settings)
	for streamID := uint32(1); streamID <= streamCount; streamID++ {
		writeTestAnyTLSFrame(t, clientConn, anyTLSCmdSYN, streamID, nil)
	}
	for range streamCount {
		select {
		case <-opened:
		case <-time.After(time.Second):
			t.Fatal("concurrent AnyTLS stream did not open")
		}
	}

	var wireMu sync.Mutex
	var senders sync.WaitGroup
	sendErrors := make(chan error, streamCount)
	for streamID := uint32(1); streamID <= streamCount; streamID++ {
		senders.Add(1)
		go func() {
			defer senders.Done()
			payload := bytes.Repeat([]byte{byte(streamID)}, frameSize)
			frame := make([]byte, anyTLSFrameHeaderSize+frameSize)
			frame[0] = anyTLSCmdPSH
			binary.BigEndian.PutUint32(frame[1:5], streamID)
			binary.BigEndian.PutUint16(frame[5:7], frameSize)
			copy(frame[7:], payload)
			for sent := 0; sent < bytesPerStream; sent += frameSize {
				wireMu.Lock()
				_, err := clientConn.Write(frame)
				wireMu.Unlock()
				if err != nil {
					sendErrors <- err
					return
				}
			}
		}()
	}
	senders.Wait()
	close(sendErrors)
	for err := range sendErrors {
		if err != nil {
			t.Fatal(err)
		}
	}
	for range streamCount {
		select {
		case err := <-completed:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("concurrent AnyTLS throughput test timed out")
		}
	}

	_ = clientConn.Close()
	close(releaseHandlers)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("AnyTLS session did not stop after throughput test")
	}
}

func TestAnyTLSConcurrentDownlinkThroughput(t *testing.T) {
	const (
		streamCount    = 8
		bytesPerStream = 2 * 1024 * 1024
		frameSize      = 32 * 1024
	)
	serverConn, clientConn := stdnet.Pipe()
	defer clientConn.Close()

	opened := make(chan uint32, streamCount)
	completed := make(chan error, streamCount)
	start := make(chan struct{})
	releaseHandlers := make(chan struct{})
	session := newAnyTLSServerSession(context.Background(), serverConn, serverConn, testActivity{}, func(stream *anyTLSStream) {
		opened <- stream.id
		<-start
		payload := bytes.Repeat([]byte{byte(stream.id)}, frameSize)
		for sent := 0; sent < bytesPerStream; sent += frameSize {
			if _, err := stream.Write(payload); err != nil {
				completed <- err
				return
			}
		}
		completed <- nil
		<-releaseHandlers
	})
	done := make(chan error, 1)
	go func() { done <- session.run() }()

	settings := []byte("v=1\nclient=xray-test\npadding-md5=" + anyTLSPaddingMD5)
	writeTestAnyTLSFrame(t, clientConn, anyTLSCmdSettings, 0, settings)
	for streamID := uint32(1); streamID <= streamCount; streamID++ {
		writeTestAnyTLSFrame(t, clientConn, anyTLSCmdSYN, streamID, nil)
	}
	for range streamCount {
		select {
		case <-opened:
		case <-time.After(time.Second):
			t.Fatal("concurrent AnyTLS downlink stream did not open")
		}
	}
	close(start)
	if err := clientConn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	received := make(map[uint32]int, streamCount)
	totalRemaining := streamCount * bytesPerStream
	for totalRemaining > 0 {
		command, streamID, payload := readTestAnyTLSFrame(t, clientConn)
		if command != anyTLSCmdPSH || streamID == 0 || streamID > streamCount {
			t.Fatalf("unexpected concurrent downlink frame: command=%d stream=%d", command, streamID)
		}
		for _, value := range payload {
			if value != byte(streamID) {
				t.Fatalf("payload crossed AnyTLS downlink streams: stream=%d", streamID)
			}
		}
		received[streamID] += len(payload)
		totalRemaining -= len(payload)
	}
	for streamID := uint32(1); streamID <= streamCount; streamID++ {
		if received[streamID] != bytesPerStream {
			t.Fatalf("stream %d received %d bytes, want %d", streamID, received[streamID], bytesPerStream)
		}
	}
	for range streamCount {
		select {
		case err := <-completed:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(time.Second):
			t.Fatal("concurrent AnyTLS downlink writer did not finish")
		}
	}

	_ = clientConn.Close()
	close(releaseHandlers)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("AnyTLS session did not stop after downlink throughput test")
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

func TestAnyTLSUoTRequestUsesSocksAddressFormat(t *testing.T) {
	tests := []struct {
		name        string
		connect     bool
		destination net.Destination
	}{
		{name: "IPv4", connect: true, destination: net.UDPDestination(net.ParseAddress("192.0.2.1"), 53)},
		{name: "domain", destination: net.UDPDestination(net.DomainAddress("dns.example"), 5353)},
		{name: "IPv6", connect: true, destination: net.UDPDestination(net.ParseAddress("2001:db8::1"), 853)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var request bytes.Buffer
			if test.connect {
				request.WriteByte(1)
			} else {
				request.WriteByte(0)
			}
			if err := anyTLSAddressParser.WriteAddressPort(&request, test.destination.Address, test.destination.Port); err != nil {
				t.Fatal(err)
			}
			connect, destination, err := readAnyTLSUoTRequest(&request)
			if err != nil {
				t.Fatal(err)
			}
			if connect != test.connect || destination != test.destination || request.Len() != 0 {
				t.Fatalf("connect=%v destination=%s remaining=%d", connect, destination, request.Len())
			}
		})
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

func BenchmarkAnyTLSSynchronousStreamPipe(b *testing.B) {
	serverConn, clientConn := stdnet.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()
	session := newAnyTLSServerSession(context.Background(), serverConn, serverConn, testActivity{}, func(*anyTLSStream) {})
	stream := newAnyTLSStream(1, session)
	payload := bytes.Repeat([]byte{0x5a}, 1200)
	readBuffer := make([]byte, len(payload))

	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	delivered := make(chan error)
	go func() {
		for range b.N {
			frame := buf.FromBytes(payload)
			err := stream.deliver(frame)
			frame.Release()
			delivered <- err
		}
	}()
	for range b.N {
		if _, err := io.ReadFull(stream, readBuffer); err != nil {
			b.Fatal(err)
		}
		if err := <-delivered; err != nil {
			b.Fatal(err)
		}
	}
	stream.abortRemote()
}
