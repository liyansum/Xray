package mydispatcher_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/liyansum/Xray/api"
	"github.com/liyansum/Xray/app/mydispatcher"
	_ "github.com/liyansum/Xray/cmd/distro/all"
	"github.com/liyansum/Xray/service/controller"
	corelog "github.com/xtls/xray-core/app/log"
	corepolicy "github.com/xtls/xray-core/app/policy"
	"github.com/xtls/xray-core/app/proxyman"
	corestats "github.com/xtls/xray-core/app/stats"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/proxy/trojan"
)

const eofPassword = "550e8400-e29b-41d4-a716-446655440000"

// Coalesce valid encrypted application records and close_notify into one TCP
// write, so the server can deterministically read data together with EOF.
type eofStagedConn struct {
	net.Conn
	pending bytes.Buffer
	hold    bool
}

func (c *eofStagedConn) Write(p []byte) (int, error) {
	if c.hold {
		return c.pending.Write(p)
	}
	return c.Conn.Write(p)
}
func (c *eofStagedConn) flush() error {
	// tls.CloseWrite expires the underlying write deadline. The record writes
	// already succeeded into our fixture buffer; restore it only to drain them.
	if err := c.Conn.SetWriteDeadline(time.Now().Add(3 * time.Second)); err != nil {
		return err
	}
	c.hold = false
	_, err := io.Copy(c.Conn, &c.pending)
	return err
}

type eofCountingReader struct {
	io.Reader
	n int
}

func (r *eofCountingReader) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	r.n += n
	return n, err
}

type eofFixture struct {
	address     string
	roots       *x509.CertPool
	destination xnet.Destination
	server      *core.Instance
	hits        atomic.Int32
}

func newEOFFixture(t *testing.T, sniff bool) *eofFixture {
	t.Helper()
	f := new(eofFixture)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certificate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certPath, certPEM, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		t.Fatal(err)
	}
	f.roots = x509.NewCertPool()
	f.roots.AppendCertsFromPEM(certPEM)
	backend, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	target := &http.Server{ReadTimeout: 3 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.hits.Add(1)
		w.Header().Set("Connection", "close")
		w.WriteHeader(204)
	})}
	go target.Serve(backend)
	t.Cleanup(func() { target.Close() })
	f.destination = xnet.TCPDestination(xnet.LocalHostIP, xnet.Port(backend.Addr().(*net.TCPAddr).Port))
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := uint32(listener.Addr().(*net.TCPAddr).Port)
	listener.Close()
	config := &controller.Config{ListenIP: "127.0.0.1", SendIP: "0.0.0.0", DisableSniffing: !sniff, CertConfig: &controller.CertConfig{CertMode: "file", CertFile: certPath, KeyFile: keyPath}}
	node := &api.NodeInfo{NodeType: "Trojan", Port: port, TransportProtocol: "tcp", EnableTLS: true}
	inbound, err := controller.InboundBuilder(config, node, "eof")
	if err != nil {
		t.Fatal(err)
	}
	inbound.ProxySettings = serial.ToTypedMessage(&trojan.ServerConfig{Users: []*protocol.User{{Email: "eof|user@example.com|1", Account: serial.ToTypedMessage(&trojan.Account{Password: eofPassword})}}})
	outbound, err := controller.OutboundBuilder(config, node, "eof")
	if err != nil {
		t.Fatal(err)
	}
	plcy := &corepolicy.Config{Level: map[uint32]*corepolicy.Policy{0: {Timeout: &corepolicy.Policy_Timeout{Handshake: &corepolicy.Second{Value: 4}, ConnectionIdle: &corepolicy.Second{Value: 30}, UplinkOnly: &corepolicy.Second{Value: 2}, DownlinkOnly: &corepolicy.Second{Value: 4}}, Stats: &corepolicy.Policy_Stats{UserUplink: true, UserDownlink: true}}}}
	f.server, err = core.New(&core.Config{App: []*serial.TypedMessage{serial.ToTypedMessage(new(corelog.Config)), serial.ToTypedMessage(new(mydispatcher.Config)), serial.ToTypedMessage(new(corestats.Config)), serial.ToTypedMessage(new(proxyman.InboundConfig)), serial.ToTypedMessage(new(proxyman.OutboundConfig)), serial.ToTypedMessage(plcy)}, Inbound: []*core.InboundHandlerConfig{inbound}, Outbound: []*core.OutboundHandlerConfig{outbound}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.server.Close() })
	dispatcher := f.server.GetFeature(routing.DispatcherType()).(*mydispatcher.DefaultDispatcher)
	users := []api.UserInfo{{UID: 1, Email: "user@example.com", UUID: eofPassword}}
	if err := dispatcher.Limiter.AddInboundLimiter("eof", 0, &users, nil); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { dispatcher.Limiter.DeleteInboundLimiter("eof") })
	if err := f.server.Start(); err != nil {
		t.Fatal(err)
	}
	f.address = fmt.Sprintf("127.0.0.1:%d", port)
	return f
}

func (f *eofFixture) header(t *testing.T, password string) []byte {
	t.Helper()
	account, err := (&trojan.Account{Password: password}).AsAccount()
	if err != nil {
		t.Fatal(err)
	}
	var header bytes.Buffer
	writer := &trojan.ConnWriter{Writer: &header, Target: f.destination, Account: account.(*trojan.MemoryAccount)}
	if _, err := writer.Write(nil); err != nil {
		t.Fatal(err)
	}
	return header.Bytes()
}

func (f *eofFixture) client(t *testing.T, version uint16) (*tls.Conn, *eofStagedConn) {
	t.Helper()
	raw, err := net.DialTimeout("tcp4", f.address, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { raw.Close() })
	raw.SetDeadline(time.Now().Add(3 * time.Second))
	staged := &eofStagedConn{Conn: raw}
	conn := tls.Client(staged, &tls.Config{ServerName: "localhost", RootCAs: f.roots, MinVersion: version, MaxVersion: version})
	if err := conn.HandshakeContext(context.Background()); err != nil {
		t.Fatal(err)
	}
	return conn, staged
}

func TestTrojanTLSCloseNotifyPreservesRequestAndTraffic(t *testing.T) {
	for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		for _, sniff := range []bool{true, false} {
			for _, phase := range []string{"first-read", "header-read", "sniff-read", "sniff-fragment"} {
				t.Run(fmt.Sprintf("TLS%d/sniff%t/%s", version, sniff, phase), func(t *testing.T) {
					f := newEOFFixture(t, sniff)
					conn, staged := f.client(t, version)
					header := f.header(t, eofPassword)
					request, _ := http.NewRequest("HEAD", "http://localhost/probe", nil)
					request.Host = "localhost"
					var wire bytes.Buffer
					if err := request.Write(&wire); err != nil {
						t.Fatal(err)
					}
					payload := wire.Bytes()
					initial := []byte(nil)
					final := append(append([]byte(nil), header...), payload...)
					switch phase {
					case "header-read":
						initial = header[:58]
						final = append(append([]byte(nil), header[58:]...), payload...)
					case "sniff-read":
						initial = header
						final = payload
					case "sniff-fragment":
						initial = append(append([]byte(nil), header...), payload[:2]...)
						final = payload[2:]
					}
					if len(initial) > 0 {
						if _, err := conn.Write(initial); err != nil {
							t.Fatal(err)
						}
						time.Sleep(2 * time.Millisecond)
					}
					staged.hold = true
					if _, err := conn.Write(final); err != nil {
						t.Fatal(err)
					}
					if err := conn.CloseWrite(); err != nil {
						t.Fatal(err)
					}
					if err := staged.flush(); err != nil {
						t.Fatal(err)
					}
					counted := &eofCountingReader{Reader: conn}
					reader := bufio.NewReader(counted)
					response, err := http.ReadResponse(reader, request)
					if err != nil {
						t.Fatal(err)
					}
					response.Body.Close()
					if response.StatusCode != 204 || f.hits.Load() != 1 {
						t.Fatalf("missing or duplicated request: %s / %d", response.Status, f.hits.Load())
					}
					if _, err := reader.ReadByte(); err != io.EOF {
						t.Fatalf("TLS did not close cleanly: %v", err)
					}
					manager := f.server.GetFeature(stats.ManagerType()).(stats.Manager)
					for direction, want := range map[string]int64{"uplink": int64(len(payload)), "downlink": int64(counted.n)} {
						counter := manager.GetCounter("user>>>eof|user@example.com|1>>>traffic>>>" + direction)
						if counter == nil || counter.Value() != want {
							t.Fatalf("%s traffic mismatch: %v, want %d", direction, counter, want)
						}
					}
				})
			}
		}
	}
}

func TestTrojanTLSCloseNotifyDoesNotAcceptInvalidHeaders(t *testing.T) {
	for _, mode := range []string{"truncated", "wrong-user"} {
		t.Run(mode, func(t *testing.T) {
			f := newEOFFixture(t, true)
			conn, staged := f.client(t, tls.VersionTLS12)
			header := f.header(t, "6ba7b810-9dad-11d1-80b4-00c04fd430c8")
			if mode == "truncated" {
				header = f.header(t, eofPassword)[:20]
			}
			staged.hold = true
			if _, err := conn.Write(header); err != nil {
				t.Fatal(err)
			}
			if err := conn.CloseWrite(); err != nil {
				t.Fatal(err)
			}
			if err := staged.flush(); err != nil {
				t.Fatal(err)
			}
			data, err := io.ReadAll(conn)
			if err != nil || len(data) != 0 || f.hits.Load() != 0 {
				t.Fatalf("invalid request reached target: %q / %v / %d", data, err, f.hits.Load())
			}
		})
	}
}
