package shadowsocks

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	stdnet "net"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
)

type finalRequestReader struct{ terminal error }

func (r finalRequestReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	return buf.MultiBuffer{buf.FromBytes([]byte("request-with-eof"))}, r.terminal
}
func (r finalRequestReader) ReadMultiBufferTimeout(time.Duration) (buf.MultiBuffer, error) {
	return r.ReadMultiBuffer()
}

type eofClientDialer struct {
	internet.Dialer
	conn stdnet.Conn
}

func (d eofClientDialer) Dial(context.Context, net.Destination) (stat.Connection, error) {
	return d.conn, nil
}

func TestClientFlushesFinalRequestBeforeEOF(t *testing.T) {
	for _, cipher := range []CipherType{CipherType_AES_128_GCM, CipherType_CHACHA20_POLY1305} {
		for _, terminal := range []error{io.EOF, errors.New("transport failure")} {
			t.Run(fmt.Sprint(cipher, "/", terminal), func(t *testing.T) {
				account, err := (&Account{Password: "test-password", CipherType: cipher}).AsAccount()
				if err != nil {
					t.Fatal(err)
				}
				user := &protocol.MemoryUser{Account: account}
				destination := net.TCPDestination(net.DomainAddress("example.com"), 443)
				client := &Client{server: protocol.NewServerSpec(net.TCPDestination(net.LocalHostIP, 1234), user), policyManager: policy.DefaultManager{}}
				conn, peer := stdnet.Pipe()
				defer conn.Close()
				defer peer.Close()
				conn.SetDeadline(time.Now().Add(3 * time.Second))
				peer.SetDeadline(time.Now().Add(3 * time.Second))
				remoteDone := make(chan error, 1)
				go func() {
					defer peer.Close()
					validator := new(Validator)
					if err := validator.Add(user); err != nil {
						remoteDone <- err
						return
					}
					request, body, err := ReadTCPSession(validator, peer)
					if err != nil {
						remoteDone <- err
						return
					}
					if request.Address.String() != destination.Address.String() || request.Port != destination.Port {
						remoteDone <- fmt.Errorf("wrong destination: %+v", request)
						return
					}
					data := make([]byte, len("request-with-eof"))
					if _, err := io.ReadFull(&buf.BufferedReader{Reader: body}, data); err != nil || string(data) != "request-with-eof" {
						remoteDone <- fmt.Errorf("lost final request: %q / %v", data, err)
						return
					}
					if terminal != io.EOF {
						remoteDone <- nil
						return
					}
					response, err := WriteTCPResponse(request, peer)
					if err == nil {
						err = response.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("response-after-eof"))})
					}
					remoteDone <- err
				}()
				var output bytes.Buffer
				ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{Target: destination}})
				processErr := client.Process(ctx, &transport.Link{Reader: finalRequestReader{terminal: terminal}, Writer: buf.NewWriter(&output)}, eofClientDialer{conn: conn})
				if (terminal == io.EOF && processErr != nil) || (terminal != io.EOF && processErr == nil) {
					t.Fatalf("incorrect completion: %v", processErr)
				}
				if err := <-remoteDone; err != nil {
					t.Fatal(err)
				}
				if terminal == io.EOF && output.String() != "response-after-eof" {
					t.Fatalf("lost response after request EOF: %q", output.String())
				}
			})
		}
	}
}
