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

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
)

const testUUID = "550e8400-e29b-41d4-a716-446655440000"

func testMultiUser(t testing.TB) *protocol.MemoryUser {
	t.Helper()
	account, err := (&Account{Password: testUUID}).AsAccount()
	if err != nil {
		t.Fatal(err)
	}
	return &protocol.MemoryUser{Email: "multi@example.com", Level: 1, Account: account}
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

func makeVLESSRequest(t *testing.T, user *protocol.MemoryUser, flow string) []byte {
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
	request = append(request, byte(protocol.RequestCommandTCP))
	var destination bytes.Buffer
	if err := vlessAddressParser.WriteAddressPort(&destination, net.DomainAddress("example.com"), 443); err != nil {
		t.Fatal(err)
	}
	return append(request, destination.Bytes()...)
}

func TestVLESSRequestFlowModes(t *testing.T) {
	user := testMultiUser(t)
	for _, expectedFlow := range []string{"", "xtls-rprx-vision"} {
		request := makeVLESSRequest(t, user, expectedFlow)
		id, destination, flow, err := readVLESSRequest(bytes.NewReader(request), user)
		if err != nil {
			t.Fatal(err)
		}
		if len(id) != 16 || destination.String() != "tcp:example.com:443" || flow != expectedFlow {
			t.Fatalf("id=%x destination=%s flow=%q", id, destination.String(), flow)
		}
	}
	if _, _, _, err := readVLESSRequest(bytes.NewReader(makeVLESSRequest(t, user, "unsupported-flow")), user); err == nil {
		t.Fatal("unsupported VLESS flow was accepted")
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
