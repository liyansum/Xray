package trojan

import (
	"bytes"
	"context"
	gotls "crypto/tls"
	"fmt"
	"io"
	stdnet "net"
	"testing"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
	xraytls "github.com/xtls/xray-core/transport/internet/tls"
)

type tcpTestDispatcher struct {
	routing.Dispatcher
	run func(context.Context, net.Destination, *transport.Link) error
}

func (*tcpTestDispatcher) Dispatch(context.Context, net.Destination) (*transport.Link, error) {
	panic("Trojan TCP used intermediate pipes")
}
func (d *tcpTestDispatcher) DispatchLink(ctx context.Context, dest net.Destination, link *transport.Link) error {
	return d.run(ctx, dest, link)
}

func trojanTCPPair(t *testing.T) (*stdnet.TCPConn, *stdnet.TCPConn) {
	t.Helper()
	l, err := stdnet.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	c, err := stdnet.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	s, err := l.Accept()
	if err != nil {
		c.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close(); s.Close() })
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	_ = s.SetDeadline(time.Now().Add(5 * time.Second))
	return s.(*stdnet.TCPConn), c.(*stdnet.TCPConn)
}

func TestTrojanTCPDispatchLinkOverTLS(t *testing.T) {
	for _, version := range []uint16{gotls.VersionTLS12, gotls.VersionTLS13} {
		t.Run(fmt.Sprint(version), func(t *testing.T) {
			s, user := testMultiServer(t)
			s.policyManager = &testPolicyManager{}
			serverRaw, clientRaw := trojanTCPPair(t)
			serverTLS := xraytls.Server(serverRaw, &gotls.Config{Certificates: []gotls.Certificate{testTLSCertificate(t)}, MinVersion: version, MaxVersion: version}).(*xraytls.Conn)
			clientTLS := gotls.Client(clientRaw, &gotls.Config{InsecureSkipVerify: true, MinVersion: version, MaxVersion: version})
			defer serverTLS.Close()
			defer clientTLS.Close()
			payload := bytes.Repeat([]byte("trojan-tcp-payload"), 32768)
			d := &tcpTestDispatcher{run: func(ctx context.Context, dest net.Destination, link *transport.Link) error {
				in := session.InboundFromContext(ctx)
				if in.Name != "trojan" || in.User != user || in.CanSpliceCopy != 3 || dest != net.TCPDestination(net.DomainAddress("example.com"), 443) {
					return fmt.Errorf("wrong dispatch metadata: %+v %+v", in, dest)
				}
				if err := buf.Copy(link.Reader, link.Writer); err != nil {
					return err
				}
				if err := common.Close(link.Writer); err != nil {
					return err
				}
				return common.Interrupt(link.Reader) // normal outbound handler cleanup
			}}
			ctx := session.ContextWithInbound(context.Background(), &session.Inbound{Conn: serverTLS})
			done := make(chan error, 1)
			go func() {
				err := s.Process(ctx, net.Network_TCP, serverTLS, d)
				_ = serverTLS.Close()
				done <- err
			}()
			request := bytes.NewBuffer(nil)
			cw := &ConnWriter{Writer: request, Target: net.TCPDestination(net.DomainAddress("example.com"), 443), Account: user.Account.(*MemoryAccount)}
			if _, err := cw.Write(nil); err != nil {
				t.Fatal(err)
			}
			writeDone := make(chan error, 1)
			go func() {
				_, err := clientTLS.Write(append(request.Bytes(), payload...))
				if err == nil {
					err = clientTLS.CloseWrite()
				}
				writeDone <- err
			}()
			got := make([]byte, len(payload))
			if _, err := io.ReadFull(clientTLS, got); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, payload) {
				t.Fatal("TLS payload corrupted or truncated")
			}
			if _, err := clientTLS.Read(make([]byte, 1)); err != io.EOF {
				t.Fatalf("normal TLS shutdown lost close_notify: %v", err)
			}
			if err := <-writeDone; err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-done:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("client write EOF did not complete relay")
			}
		})
	}
}

func TestTrojanTCPDownlinkEOFStillAllowsUpload(t *testing.T) {
	s, c := trojanTCPPair(t)
	closed := make(chan struct{})
	got := make(chan []byte, 1)
	d := &tcpTestDispatcher{run: func(_ context.Context, _ net.Destination, link *transport.Link) error {
		if err := common.Close(link.Writer); err != nil {
			return err
		}
		_ = common.Close(link.Writer) // outbound handler may close twice
		close(closed)
		var data bytes.Buffer
		err := buf.Copy(link.Reader, buf.NewWriter(&data))
		got <- data.Bytes()
		return err
	}}
	done := make(chan error, 1)
	go func() {
		done <- new(Server).handleTCPConnection(context.Background(), policy.SessionDefault(), net.TCPDestination(net.LocalHostIP, 80), buf.NewReader(s), buf.NewWriter(s), s, d)
	}()
	<-closed
	if _, err := c.Write([]byte("upload-after-response-eof")); err != nil {
		t.Fatal(err)
	}
	_ = c.CloseWrite()
	if string(<-got) != "upload-after-response-eof" {
		t.Fatal("response EOF closed the upload")
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestTrojanTCPInterruptsBlockedReads(t *testing.T) {
	for _, mode := range []string{"cancel", "idle", "downlink-only", "uplink-only"} {
		t.Run(mode, func(t *testing.T) {
			s, c := trojanTCPPair(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			plcy := policy.SessionDefault()
			plcy.Timeouts.ConnectionIdle = time.Second
			plcy.Timeouts.DownlinkOnly = 20 * time.Millisecond
			plcy.Timeouts.UplinkOnly = 20 * time.Millisecond
			if mode == "idle" {
				plcy.Timeouts.ConnectionIdle = 20 * time.Millisecond
			}
			entered := make(chan struct{})
			d := &tcpTestDispatcher{run: func(ctx context.Context, _ net.Destination, link *transport.Link) error {
				close(entered)
				if mode == "uplink-only" {
					_ = common.Close(link.Writer)
				}
				_, err := link.Reader.ReadMultiBuffer()
				if mode == "downlink-only" {
					<-ctx.Done()
				}
				return err
			}}
			done := make(chan error, 1)
			go func() {
				done <- new(Server).handleTCPConnection(ctx, plcy, net.TCPDestination(net.LocalHostIP, 80), buf.NewReader(s), buf.NewWriter(s), s, d)
			}()
			<-entered
			if mode == "cancel" {
				cancel()
			}
			if mode == "downlink-only" {
				_ = c.CloseWrite()
			}
			select {
			case <-done:
			case <-time.After(700 * time.Millisecond):
				t.Fatal("cancellation/directional timeout did not release relay")
			}
		})
	}
}

func TestTrojanTCPCancelInterruptsBlockedWrite(t *testing.T) {
	s, c := stdnet.Pipe()
	defer s.Close()
	defer c.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	entered := make(chan struct{})
	d := &tcpTestDispatcher{run: func(_ context.Context, _ net.Destination, link *transport.Link) error {
		close(entered)
		return link.Writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("blocked-response"))})
	}}
	done := make(chan error, 1)
	go func() {
		done <- new(Server).handleTCPConnection(ctx, policy.SessionDefault(), net.TCPDestination(net.LocalHostIP, 80), buf.NewReader(s), buf.NewWriter(s), s, d)
	}()
	<-entered
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("blocked write unexpectedly succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation did not release blocked write")
	}
}
