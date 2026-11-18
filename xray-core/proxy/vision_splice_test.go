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
	"runtime"
	"testing"
	"time"
	"unsafe"

	"github.com/xtls/xray-core/app/dispatcher"
	"github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/transport/internet/stat"
	xraytls "github.com/xtls/xray-core/transport/internet/tls"
)

func visionStreamPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	c, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	s, err := l.Accept()
	if err != nil {
		c.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close(); s.Close() })
	c.SetDeadline(time.Now().Add(10 * time.Second))
	s.SetDeadline(time.Now().Add(10 * time.Second))
	return s.(*net.TCPConn), c.(*net.TCPConn)
}

func visionOuterTLS(t *testing.T, a, b net.Conn) (*xraytls.Conn, *xraytls.Conn) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	server := xraytls.Server(a, &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: tls.VersionTLS13}).(*xraytls.Conn)
	client := xraytls.Client(b, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13}).(*xraytls.Conn)
	done := make(chan error, 1)
	go func() { done <- server.HandshakeContext(context.Background()) }()
	if err := client.HandshakeContext(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	return server, client
}

func visionReaderForTLS(t *testing.T, conn *xraytls.Conn, counted net.Conn, uplink bool) *proxy.VisionReader {
	t.Helper()
	typ := reflect.TypeOf(conn.Conn).Elem()
	input, ok := typ.FieldByName("input")
	if !ok {
		t.Fatal("missing TLS input")
	}
	raw, ok := typ.FieldByName("rawInput")
	if !ok {
		t.Fatal("missing TLS rawInput")
	}
	p := unsafe.Pointer(conn.Conn)
	return proxy.NewVisionReader(buf.NewReader(counted), proxy.NewTrafficState(make([]byte, 16)), uplink, context.Background(), counted,
		(*bytes.Reader)(unsafe.Add(p, input.Offset)), (*bytes.Buffer)(unsafe.Add(p, raw.Offset)), nil)
}

type observedVisionReader struct {
	*proxy.VisionReader
	rawReads int
}

func (r *observedVisionReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	if conn, _ := r.DirectReadConn(); conn != nil {
		r.rawReads++
	}
	return r.VisionReader.ReadMultiBuffer()
}

type observedVisionWriter struct {
	*proxy.VisionWriter
	rawWrites int
}

func (w *observedVisionWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	if conn, _ := w.DirectWriteConn(); conn != nil {
		w.rawWrites++
	}
	return w.VisionWriter.WriteMultiBuffer(mb)
}

func visionSpliceContext(t *testing.T) (context.Context, *signal.ActivityTimer) {
	t.Helper()
	ctx := session.ContextWithInbound(context.Background(), &session.Inbound{CanSpliceCopy: 2})
	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{{CanSpliceCopy: 1}})
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	t.Cleanup(cancel)
	timer := signal.CancelAfterInactivity(ctx, cancel, 5*time.Second)
	t.Cleanup(func() { timer.SetTimeout(0) })
	return ctx, timer
}

func TestVisionTCPSpliceHandoff(t *testing.T) {
	_, application := realTLS13(t)
	t.Run("uplink", func(t *testing.T) {
		in, peer := visionStreamPair(t)
		dst, consumer := visionStreamPair(t)
		server, client := visionOuterTLS(t, in, peer)
		read, written, user := new(stats.Counter), new(stats.Counter), new(stats.Counter)
		counted := &stat.CounterConnection{Connection: server, ReadCounter: read}
		reader := &observedVisionReader{VisionReader: visionReaderForTLS(t, server, counted, true)}
		wrapper := &buf.TimeoutWrapperReader{Reader: reader, Counter: user}
		outer := &countOuterWriter{Writer: buf.NewWriter(client)}
		writer := proxy.NewVisionWriter(outer, recognizedState(), true, context.Background(), client, nil, []uint32{900, 1, 900, 1})
		ctx, timer := visionSpliceContext(t)
		dstStat := &stat.CounterConnection{Connection: dst, WriteCounter: written}
		done, sent := make(chan error, 1), make(chan error, 1)
		go func() { done <- proxy.CopyDirectReader(ctx, wrapper, dstStat, buf.NewWriter(dstStat), timer, nil) }()
		go func() {
			for p := application; len(p) > 0; {
				n := min(len(p), 997) // split the initial 16 KiB TLS record
				if err := writer.WriteMultiBuffer(multi(p[:n])); err != nil {
					sent <- err
					return
				}
				p = p[n:]
			}
			peer.CloseWrite()
			sent <- nil
		}()
		got := make([]byte, len(application))
		if _, err := io.ReadFull(consumer, got); err != nil {
			t.Fatal(err)
		}
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		if err := <-sent; err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, application) || user.Value() != int64(len(application)) || written.Value() != int64(len(application)) {
			t.Fatal("uplink handoff lost data or accounting")
		}
		if runtime.GOOS == "linux" && reader.rawReads != 0 {
			t.Fatalf("upload used %d buffered raw reads", reader.rawReads)
		}
		if outer.bytes >= len(application)/2 {
			t.Fatal("outer TLS still encrypted bulk upload")
		}
		t.Logf("uplink: %d ciphertext bytes intact, outer TLS plaintext=%d, buffered raw reads=%d", len(application), outer.bytes, reader.rawReads)
	})
	t.Run("downlink", func(t *testing.T) {
		dst, peer := visionStreamPair(t)
		src, producer := visionStreamPair(t)
		server, client := visionOuterTLS(t, dst, peer)
		read, user := new(stats.Counter), new(stats.Counter)
		outer := &countOuterWriter{Writer: buf.NewWriter(server)}
		writer := &observedVisionWriter{VisionWriter: proxy.NewVisionWriter(outer, recognizedState(), false, context.Background(), server, nil, []uint32{900, 1, 900, 1})}
		statWriter := &dispatcher.SizeStatWriter{Writer: writer, Counter: user}
		reader := visionReaderForTLS(t, client, client, false)
		ctx, timer := visionSpliceContext(t)
		done, sent := make(chan error, 1), make(chan error, 1)
		go func() {
			err := proxy.CopyRawConnIfExist(ctx, &stat.CounterConnection{Connection: src, ReadCounter: read}, server, statWriter, timer, nil)
			dst.CloseWrite()
			done <- err
		}()
		go func() { _, err := producer.Write(application); producer.CloseWrite(); sent <- err }()
		var got bytes.Buffer
		if err := buf.Copy(reader, buf.NewWriter(&got)); err != nil {
			t.Fatal(err)
		}
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		if err := <-sent; err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got.Bytes(), application) || user.Value() != int64(len(application)) || read.Value() != int64(len(application)) {
			t.Fatal("downlink handoff lost data or accounting")
		}
		if runtime.GOOS == "linux" && writer.rawWrites != 0 {
			t.Fatalf("download used %d buffered raw writes", writer.rawWrites)
		}
		if outer.bytes >= len(application)/2 {
			t.Fatal("outer TLS still encrypted bulk download")
		}
		t.Logf("downlink: %d ciphertext bytes intact, outer TLS plaintext=%d, buffered raw writes=%d", len(application), outer.bytes, writer.rawWrites)
	})
}

var _ buf.DirectReader = (*observedVisionReader)(nil)
var _ buf.DirectWriter = (*observedVisionWriter)(nil)
