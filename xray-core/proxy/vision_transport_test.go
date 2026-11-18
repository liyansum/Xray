package proxy_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"io"
	"math/big"
	"net"
	"reflect"
	"testing"
	"time"
	"unsafe"

	"github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/transport/internet/stat"
	xraytls "github.com/xtls/xray-core/transport/internet/tls"
)

type countOuterWriter struct {
	buf.Writer
	bytes int
}

func (w *countOuterWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	w.bytes += int(mb.Len())
	return w.Writer.WriteMultiBuffer(mb)
}

func TestVisionTLS13TransportHandoff(t *testing.T) {
	handshake, application := realTLS13(t)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	_ = a.SetDeadline(time.Now().Add(10 * time.Second))
	_ = b.SetDeadline(time.Now().Add(10 * time.Second))
	server := xraytls.Server(a, &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: tls.VersionTLS13}).(*xraytls.Conn)
	client := xraytls.Client(b, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13}).(*xraytls.Conn)
	id := bytes.Repeat([]byte{0x55}, 16)
	serverState, clientState := proxy.NewTrafficState(id), proxy.NewTrafficState(id)
	outer := &countOuterWriter{Writer: buf.NewWriter(server)}
	writer := proxy.NewVisionWriter(outer, serverState, false, context.Background(), server, nil, []uint32{900, 1, 900, 1})
	// Match the production adapter and verify Go's patched TLS buffer layout.
	typ := reflect.TypeOf(client.Conn).Elem()
	inputField, ok := typ.FieldByName("input")
	if !ok {
		t.Fatal("TLS input field missing")
	}
	rawField, ok := typ.FieldByName("rawInput")
	if !ok {
		t.Fatal("TLS rawInput field missing")
	}
	ptr := unsafe.Pointer(client.Conn)
	input := (*bytes.Reader)(unsafe.Add(ptr, inputField.Offset))
	raw := (*bytes.Buffer)(unsafe.Add(ptr, rawField.Offset))
	reader := proxy.NewVisionReader(buf.NewReader(client), clientState, false, context.Background(), client, input, raw, nil)
	done := make(chan error, 1)
	go func() {
		defer a.Close()
		for p := handshake; len(p) > 0; {
			n := min(60, len(p))
			if err := writer.WriteMultiBuffer(multi(p[:n])); err != nil {
				done <- err
				return
			}
			p = p[n:]
		}
		paddingBytes := outer.bytes
		for p := application; len(p) > 0; {
			n := min(8192, len(p))
			if err := writer.WriteMultiBuffer(multi(p[:n])); err != nil {
				done <- err
				return
			}
			p = p[n:]
		}
		if outer.bytes != paddingBytes {
			done <- io.ErrUnexpectedEOF
			return
		}
		done <- nil
	}()
	var got bytes.Buffer
	if err := buf.Copy(reader, buf.NewWriter(&got)); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	want := append(append([]byte(nil), handshake...), application...)
	if !bytes.Equal(got.Bytes(), want) {
		t.Fatalf("TLS/raw handoff corrupted stream: got=%d want=%d", got.Len(), len(want))
	}
	if !serverState.Inbound.DownlinkWriterDirectCopy || !clientState.Outbound.DownlinkReaderDirectCopy {
		t.Fatal("TLS transport did not switch both endpoints")
	}
	t.Logf("real nested TLS: %d stream bytes intact; all %d application ciphertext bytes bypassed outer TLS", len(want), len(application))
}

type partialRawConn struct{ rawSink }

func (*partialRawConn) Write(p []byte) (int, error) { return min(3, len(p)), io.ErrClosedPipe }

func TestVisionDirectCopyCountsPartialWrites(t *testing.T) {
	state := recognizedState()
	counter := new(stats.Counter)
	raw := &stat.CounterConnection{Connection: new(partialRawConn), WriteCounter: counter}
	w := proxy.NewVisionWriter(&paddingSink{}, state, false, context.Background(), raw, nil, []uint32{900, 1, 900, 1})
	if err := w.WriteMultiBuffer(multi(record(64))); err != nil {
		t.Fatal(err)
	}
	if err := w.WriteMultiBuffer(multi([]byte("partial raw write"))); err == nil {
		t.Fatal("write error lost")
	}
	if got := counter.Value(); got != 3 {
		t.Fatalf("counted %d bytes, want only 3 written bytes", got)
	}
}

func TestVisionNeverDirectCopiesMux(t *testing.T) {
	s := recognizedState()
	s.DisableDirectCopy = true
	w, outer, raw := writer(s)
	if err := w.WriteMultiBuffer(multi(record(64))); err != nil {
		t.Fatal(err)
	}
	if outer.commands[2] != 0 || outer.commands[1] != 1 || raw.calls != 0 {
		t.Fatal("UDP/Mux triggered direct copy")
	}
}

func TestVisionDirectCopyPreservesSpliceVeto(t *testing.T) {
	s := recognizedState()
	inbound := &session.Inbound{CanSpliceCopy: 3}
	ctx := session.ContextWithInbound(context.Background(), inbound)
	raw := new(rawSink)
	w := proxy.NewVisionWriter(&paddingSink{}, s, false, ctx, raw, nil, []uint32{900, 1, 900, 1})
	if err := w.WriteMultiBuffer(multi(record(64))); err != nil {
		t.Fatal(err)
	}
	if err := w.WriteMultiBuffer(multi([]byte("raw payload"))); err != nil {
		t.Fatal(err)
	}
	if inbound.CanSpliceCopy != 3 || raw.Len() == 0 {
		t.Fatal("splice veto disabled direct copy or was overwritten")
	}
}
