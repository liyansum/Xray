package trojan

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	gotls "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	stdnet "net"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/transport"
	xraytls "github.com/xtls/xray-core/transport/internet/tls"
	"github.com/xtls/xray-core/transport/pipe"
)

type testPolicyManager struct{}

func (*testPolicyManager) Type() interface{}              { return policy.ManagerType() }
func (*testPolicyManager) Start() error                   { return nil }
func (*testPolicyManager) Close() error                   { return nil }
func (*testPolicyManager) ForLevel(uint32) policy.Session { return policy.SessionDefault() }
func (*testPolicyManager) ForSystem() policy.System       { return policy.System{} }

type visionTestDispatcher struct {
	received chan []byte
}

type anyTLSTestDispatcher struct {
	received chan []byte
	metadata chan *session.Inbound
}

func (*anyTLSTestDispatcher) Type() interface{} { return routing.DispatcherType() }
func (*anyTLSTestDispatcher) Start() error      { return nil }
func (*anyTLSTestDispatcher) Close() error      { return nil }
func (*anyTLSTestDispatcher) DispatchLink(context.Context, net.Destination, *transport.Link) error {
	panic("unexpected DispatchLink call")
}
func (d *anyTLSTestDispatcher) Dispatch(ctx context.Context, _ net.Destination) (*transport.Link, error) {
	uplinkReader, uplinkWriter := pipe.New(pipe.WithoutSizeLimit())
	downlinkReader, downlinkWriter := pipe.New(pipe.WithoutSizeLimit())
	inboundCopy := *session.InboundFromContext(ctx)
	d.metadata <- &inboundCopy
	go func() {
		payload, err := uplinkReader.ReadMultiBuffer()
		if err == nil {
			data := make([]byte, payload.Len())
			payload.Copy(data)
			buf.ReleaseMulti(payload)
			d.received <- data
			_ = downlinkWriter.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("anytls-response"))})
		}
		_ = downlinkWriter.Close()
	}()
	return &transport.Link{Reader: downlinkReader, Writer: uplinkWriter}, nil
}

func (*visionTestDispatcher) Type() interface{} { return routing.DispatcherType() }
func (*visionTestDispatcher) Start() error      { return nil }
func (*visionTestDispatcher) Close() error      { return nil }
func (*visionTestDispatcher) Dispatch(context.Context, net.Destination) (*transport.Link, error) {
	panic("unexpected Dispatch call")
}
func (d *visionTestDispatcher) DispatchLink(_ context.Context, _ net.Destination, link *transport.Link) error {
	payload, err := link.Reader.ReadMultiBuffer()
	if err != nil {
		return err
	}
	data := make([]byte, payload.Len())
	payload.Copy(data)
	buf.ReleaseMulti(payload)
	d.received <- data
	response := buf.FromBytes([]byte("vision-response"))
	return link.Writer.WriteMultiBuffer(buf.MultiBuffer{response})
}

func testTLSCertificate(t *testing.T) gotls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return gotls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func TestVLESSVisionOverExistingTLS(t *testing.T) {
	server, user := testMultiServer(t)
	server.policyManager = &testPolicyManager{}
	dispatcher := &visionTestDispatcher{received: make(chan []byte, 1)}

	serverRaw, clientRaw := stdnet.Pipe()
	serverTLS := xraytls.Server(serverRaw, &gotls.Config{
		Certificates: []gotls.Certificate{testTLSCertificate(t)}, MinVersion: gotls.VersionTLS13, MaxVersion: gotls.VersionTLS13,
	}).(*xraytls.Conn)
	clientTLS := gotls.Client(clientRaw, &gotls.Config{
		InsecureSkipVerify: true, ServerName: "localhost", MinVersion: gotls.VersionTLS13, MaxVersion: gotls.VersionTLS13,
	})
	defer clientTLS.Close()
	defer serverTLS.Close()

	inbound := &session.Inbound{
		Source: net.TCPDestination(net.LocalHostIP, 12345),
		Local:  net.TCPDestination(net.LocalHostIP, 443),
		Conn:   serverTLS,
	}
	ctx := session.ContextWithInbound(context.Background(), inbound)
	done := make(chan error, 1)
	go func() { done <- server.Process(ctx, net.Network_TCP, serverTLS, dispatcher) }()

	request := makeVLESSRequest(t, user, "xtls-rprx-vision")
	id, _, err := userProtocolKeys(user)
	if err != nil {
		t.Fatal(err)
	}
	writeID := append([]byte(nil), id[:]...)
	padded := proxy.XtlsPadding(buf.FromBytes([]byte("vision-request")), proxy.CommandPaddingEnd, &writeID, false, context.Background(), []uint32{900, 1, 900, 1})
	request = append(request, padded.Bytes()...)
	padded.Release()
	if _, err := clientTLS.Write(request); err != nil {
		t.Fatal(err)
	}

	select {
	case received := <-dispatcher.received:
		if string(received) != "vision-request" {
			t.Fatalf("received %q", received)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Vision request was not dispatched")
	}

	var responseHeader [2]byte
	if _, err := io.ReadFull(clientTLS, responseHeader[:]); err != nil {
		t.Fatal(err)
	}
	if responseHeader != [2]byte{0, 0} {
		t.Fatalf("response header=%x", responseHeader)
	}
	var visionHeader [21]byte
	if _, err := io.ReadFull(clientTLS, visionHeader[:]); err != nil {
		t.Fatal(err)
	}
	if string(visionHeader[:16]) != string(id[:]) {
		t.Fatalf("response UUID=%x", visionHeader[:16])
	}
	contentLength := int(visionHeader[17])<<8 | int(visionHeader[18])
	paddingLength := int(visionHeader[19])<<8 | int(visionHeader[20])
	response := make([]byte, contentLength+paddingLength)
	if _, err := io.ReadFull(clientTLS, response); err != nil {
		t.Fatal(err)
	}
	if string(response[:contentLength]) != "vision-response" {
		t.Fatalf("response=%q", response[:contentLength])
	}

	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Vision inbound did not stop")
	}
}

func TestVLESSWithoutFlowOverExistingTLS(t *testing.T) {
	server, user := testMultiServer(t)
	server.policyManager = &testPolicyManager{}
	dispatcher := &visionTestDispatcher{received: make(chan []byte, 1)}

	serverRaw, clientRaw := stdnet.Pipe()
	serverTLS := xraytls.Server(serverRaw, &gotls.Config{
		Certificates: []gotls.Certificate{testTLSCertificate(t)}, MinVersion: gotls.VersionTLS12, MaxVersion: gotls.VersionTLS12,
	}).(*xraytls.Conn)
	clientTLS := gotls.Client(clientRaw, &gotls.Config{
		InsecureSkipVerify: true, ServerName: "localhost", MinVersion: gotls.VersionTLS12, MaxVersion: gotls.VersionTLS12,
	})
	defer clientTLS.Close()
	defer serverTLS.Close()

	inbound := &session.Inbound{
		Source: net.TCPDestination(net.LocalHostIP, 12346),
		Local:  net.TCPDestination(net.LocalHostIP, 443),
		Conn:   serverTLS,
	}
	ctx := session.ContextWithInbound(context.Background(), inbound)
	done := make(chan error, 1)
	go func() { done <- server.Process(ctx, net.Network_TCP, serverTLS, dispatcher) }()

	request := append(makeVLESSRequest(t, user, ""), []byte("plain-request")...)
	if _, err := clientTLS.Write(request); err != nil {
		t.Fatal(err)
	}
	select {
	case received := <-dispatcher.received:
		if string(received) != "plain-request" {
			t.Fatalf("received %q", received)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("VLESS without flow request was not dispatched")
	}
	if inbound.Name != "vless" || inbound.User != user || inbound.CanSpliceCopy != 3 {
		t.Fatalf("inbound name=%q user=%v splice=%d", inbound.Name, inbound.User, inbound.CanSpliceCopy)
	}

	response := make([]byte, 2+len("vision-response"))
	if _, err := io.ReadFull(clientTLS, response); err != nil {
		t.Fatal(err)
	}
	if response[0] != 0 || response[1] != 0 || string(response[2:]) != "vision-response" {
		t.Fatalf("response=%x", response)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("VLESS without flow inbound did not stop")
	}
}

func appendAnyTLSFrame(buffer *bytes.Buffer, command byte, streamID uint32, data []byte) {
	header := make([]byte, anyTLSFrameHeaderSize)
	header[0] = command
	binary.BigEndian.PutUint32(header[1:5], streamID)
	binary.BigEndian.PutUint16(header[5:7], uint16(len(data)))
	buffer.Write(header)
	buffer.Write(data)
}

func testAnyTLSOverExistingTLS(t *testing.T, version int) {
	server, user := testMultiServer(t)
	server.policyManager = &testPolicyManager{}
	dispatcher := &anyTLSTestDispatcher{received: make(chan []byte, 1), metadata: make(chan *session.Inbound, 1)}

	serverRaw, clientRaw := stdnet.Pipe()
	serverTLS := xraytls.Server(serverRaw, &gotls.Config{
		Certificates: []gotls.Certificate{testTLSCertificate(t)}, MinVersion: gotls.VersionTLS13, MaxVersion: gotls.VersionTLS13,
	}).(*xraytls.Conn)
	clientTLS := gotls.Client(clientRaw, &gotls.Config{
		InsecureSkipVerify: true, ServerName: "localhost", MinVersion: gotls.VersionTLS13, MaxVersion: gotls.VersionTLS13,
	})
	defer clientTLS.Close()
	defer serverTLS.Close()

	inbound := &session.Inbound{
		Source: net.TCPDestination(net.LocalHostIP, 23456),
		Local:  net.TCPDestination(net.LocalHostIP, 443),
		Conn:   serverTLS,
	}
	ctx := session.ContextWithInbound(context.Background(), inbound)
	done := make(chan error, 1)
	go func() { done <- server.Process(ctx, net.Network_TCP, serverTLS, dispatcher) }()

	hash := sha256.Sum256([]byte(testUUID))
	var authentication bytes.Buffer
	authentication.Write(hash[:])
	authentication.Write([]byte{0, 0})
	if _, err := clientTLS.Write(authentication.Bytes()); err != nil {
		t.Fatal(err)
	}
	var settings bytes.Buffer
	appendAnyTLSFrame(&settings, anyTLSCmdSettings, 0, []byte(fmt.Sprintf("v=%d\nclient=xray-test\npadding-md5=%s", version, anyTLSPaddingMD5)))
	if _, err := clientTLS.Write(settings.Bytes()); err != nil {
		t.Fatal(err)
	}
	if version >= 2 {
		command, _, data := readTestAnyTLSFrame(t, clientTLS)
		if command != anyTLSCmdServerSetting || string(data) != "v=2" {
			t.Fatalf("unexpected settings response: command=%d data=%q", command, data)
		}
	}

	var streamRequest bytes.Buffer
	if err := anyTLSAddressParser.WriteAddressPort(&streamRequest, net.DomainAddress("example.com"), 443); err != nil {
		t.Fatal(err)
	}
	streamRequest.WriteString("anytls-request")
	var streamFrames bytes.Buffer
	appendAnyTLSFrame(&streamFrames, anyTLSCmdSYN, 1, nil)
	appendAnyTLSFrame(&streamFrames, anyTLSCmdPSH, 1, streamRequest.Bytes())
	if _, err := clientTLS.Write(streamFrames.Bytes()); err != nil {
		t.Fatal(err)
	}
	if version >= 2 {
		command, streamID, _ := readTestAnyTLSFrame(t, clientTLS)
		if command != anyTLSCmdSYNACK || streamID != 1 {
			t.Fatalf("unexpected SYNACK: command=%d stream=%d", command, streamID)
		}
	}
	command, streamID, data := readTestAnyTLSFrame(t, clientTLS)
	if command != anyTLSCmdPSH || streamID != 1 || string(data) != "anytls-response" {
		t.Fatalf("unexpected response: command=%d stream=%d data=%q", command, streamID, data)
	}

	select {
	case received := <-dispatcher.received:
		if string(received) != "anytls-request" {
			t.Fatalf("received=%q", received)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("AnyTLS request was not dispatched")
	}
	select {
	case metadata := <-dispatcher.metadata:
		if metadata.Name != "anytls" || metadata.User != user {
			t.Fatalf("metadata name=%q user=%v", metadata.Name, metadata.User)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("AnyTLS metadata was not attached")
	}

	_ = clientTLS.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("AnyTLS inbound did not stop")
	}
}

func TestAnyTLSV1OverExistingTLS(t *testing.T) { testAnyTLSOverExistingTLS(t, 1) }

func TestAnyTLSV2OverExistingTLS(t *testing.T) { testAnyTLSOverExistingTLS(t, 2) }

func testAnyTLSUoTOverExistingTLS(t *testing.T, version int) {
	server, _ := testMultiServer(t)
	server.policyManager = &testPolicyManager{}
	dispatcher := &anyTLSTestDispatcher{received: make(chan []byte, 1), metadata: make(chan *session.Inbound, 1)}

	serverRaw, clientRaw := stdnet.Pipe()
	serverTLS := xraytls.Server(serverRaw, &gotls.Config{
		Certificates: []gotls.Certificate{testTLSCertificate(t)}, MinVersion: gotls.VersionTLS13, MaxVersion: gotls.VersionTLS13,
	}).(*xraytls.Conn)
	clientTLS := gotls.Client(clientRaw, &gotls.Config{
		InsecureSkipVerify: true, ServerName: "localhost", MinVersion: gotls.VersionTLS13, MaxVersion: gotls.VersionTLS13,
	})
	defer clientTLS.Close()
	defer serverTLS.Close()

	ctx := session.ContextWithInbound(context.Background(), &session.Inbound{
		Source: net.TCPDestination(net.LocalHostIP, 34567), Local: net.TCPDestination(net.LocalHostIP, 443), Conn: serverTLS,
	})
	done := make(chan error, 1)
	go func() { done <- server.Process(ctx, net.Network_TCP, serverTLS, dispatcher) }()

	hash := sha256.Sum256([]byte(testUUID))
	var authentication bytes.Buffer
	authentication.Write(hash[:])
	authentication.Write([]byte{0, 0})
	if _, err := clientTLS.Write(authentication.Bytes()); err != nil {
		t.Fatal(err)
	}
	var settings bytes.Buffer
	appendAnyTLSFrame(&settings, anyTLSCmdSettings, 0, []byte(fmt.Sprintf("v=%d\nclient=xray-test\npadding-md5=%s", version, anyTLSPaddingMD5)))
	if _, err := clientTLS.Write(settings.Bytes()); err != nil {
		t.Fatal(err)
	}
	if version >= 2 {
		if command, _, _ := readTestAnyTLSFrame(t, clientTLS); command != anyTLSCmdServerSetting {
			t.Fatalf("settings command=%d", command)
		}
	}

	var streamRequest bytes.Buffer
	if err := anyTLSAddressParser.WriteAddressPort(&streamRequest, net.DomainAddress(anyTLSUoTMagic), 0); err != nil {
		t.Fatal(err)
	}
	streamRequest.WriteByte(1) // UoT connect mode.
	if err := anyTLSUoTAddressParser.WriteAddressPort(&streamRequest, net.DomainAddress("dns.example"), 53); err != nil {
		t.Fatal(err)
	}
	streamRequest.Write([]byte{0, 5})
	streamRequest.WriteString("query")
	var streamFrames bytes.Buffer
	appendAnyTLSFrame(&streamFrames, anyTLSCmdSYN, 1, nil)
	appendAnyTLSFrame(&streamFrames, anyTLSCmdPSH, 1, streamRequest.Bytes())
	if _, err := clientTLS.Write(streamFrames.Bytes()); err != nil {
		t.Fatal(err)
	}
	if version >= 2 {
		command, streamID, _ := readTestAnyTLSFrame(t, clientTLS)
		if command != anyTLSCmdSYNACK || streamID != 1 {
			t.Fatalf("unexpected UoT SYNACK: command=%d stream=%d", command, streamID)
		}
	}
	command, streamID, data := readTestAnyTLSFrame(t, clientTLS)
	if command != anyTLSCmdPSH || streamID != 1 || len(data) < 2 {
		t.Fatalf("unexpected UoT response frame: command=%d stream=%d data=%x", command, streamID, data)
	}
	length := int(binary.BigEndian.Uint16(data[:2]))
	if length != len(data)-2 || string(data[2:]) != "anytls-response" {
		t.Fatalf("unexpected UoT packet: length=%d data=%q", length, data[2:])
	}

	select {
	case received := <-dispatcher.received:
		if string(received) != "query" {
			t.Fatalf("UoT received=%q", received)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("UoT request was not dispatched")
	}

	_ = clientTLS.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("AnyTLS UoT inbound did not stop")
	}
}

func TestAnyTLSV1UoTOverExistingTLS(t *testing.T) { testAnyTLSUoTOverExistingTLS(t, 1) }

func TestAnyTLSV2UoTOverExistingTLS(t *testing.T) { testAnyTLSUoTOverExistingTLS(t, 2) }

func testMultiProtocolFallback(t *testing.T, payload []byte) {
	t.Helper()
	listener, err := stdnet.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	backendPayload := make(chan []byte, 1)
	backendDone := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			backendDone <- err
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		received := make([]byte, len(payload))
		if _, err := io.ReadFull(conn, received); err != nil {
			backendDone <- err
			return
		}
		backendPayload <- received
		_, err = conn.Write([]byte("fallback-response"))
		backendDone <- err
	}()

	server, _ := testMultiServer(t)
	server.policyManager = &testPolicyManager{}
	server.fallbacks = map[string]map[string]map[string]*Fallback{
		"": {"": {"": {Type: "tcp", Dest: listener.Addr().String()}}},
	}

	serverRaw, clientRaw := stdnet.Pipe()
	serverTLS := xraytls.Server(serverRaw, &gotls.Config{
		Certificates: []gotls.Certificate{testTLSCertificate(t)}, MinVersion: gotls.VersionTLS13, MaxVersion: gotls.VersionTLS13,
	}).(*xraytls.Conn)
	clientTLS := gotls.Client(clientRaw, &gotls.Config{
		InsecureSkipVerify: true, ServerName: "localhost", MinVersion: gotls.VersionTLS13, MaxVersion: gotls.VersionTLS13,
	})
	defer clientTLS.Close()
	defer serverTLS.Close()
	_ = clientTLS.SetDeadline(time.Now().Add(3 * time.Second))

	ctx := session.ContextWithInbound(context.Background(), &session.Inbound{
		Source: net.TCPDestination(net.LocalHostIP, 45678), Local: net.TCPDestination(net.LocalHostIP, 443), Conn: serverTLS,
	})
	processDone := make(chan error, 1)
	go func() { processDone <- server.Process(ctx, net.Network_TCP, serverTLS, &anyTLSTestDispatcher{}) }()

	if _, err := clientTLS.Write(payload); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, len("fallback-response"))
	if _, err := io.ReadFull(clientTLS, response); err != nil {
		t.Fatal(err)
	}
	if string(response) != "fallback-response" {
		t.Fatalf("unexpected fallback response %q", response)
	}
	select {
	case received := <-backendPayload:
		if !bytes.Equal(received, payload) {
			t.Fatalf("fallback changed probe payload: got=%x want=%x", received, payload)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("fallback backend did not receive probe")
	}
	select {
	case err := <-backendDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("fallback backend did not finish")
	}

	_ = clientTLS.Close()
	select {
	case <-processDone:
	case <-time.After(3 * time.Second):
		t.Fatal("fallback processing did not stop")
	}
}

func TestMultiProtocolHTTPProbeUsesFallback(t *testing.T) {
	testMultiProtocolFallback(t, []byte("GET /probe HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"))
}

func TestFailedMultiProtocolAuthenticationUsesFallback(t *testing.T) {
	wrongHash := sha256.Sum256([]byte("not-a-valid-user"))
	var anyTLSPayload bytes.Buffer
	anyTLSPayload.Write(wrongHash[:])
	anyTLSPayload.Write([]byte{0, 0})
	appendAnyTLSFrame(&anyTLSPayload, anyTLSCmdSettings, 0, []byte("v=1\nclient=active-probe"))

	vlessPayload := append([]byte{0}, make([]byte, 16)...)
	vlessPayload = append(vlessPayload, []byte("invalid-vless-probe")...)
	trojanPayload := append(bytes.Repeat([]byte{'0'}, userHashSize), '\r', '\n')
	trojanPayload = append(trojanPayload, []byte("invalid-trojan-probe")...)

	for name, payload := range map[string][]byte{
		"AnyTLS": anyTLSPayload.Bytes(),
		"VLESS":  vlessPayload,
		"Trojan": trojanPayload,
	} {
		t.Run(name, func(t *testing.T) {
			testMultiProtocolFallback(t, payload)
		})
	}
}
