//go:build linux

package internet

import (
	"context"
	stdnet "net"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
)

func TestSystemTCPDefaultsOverrideMPTCPEnvironment(t *testing.T) {
	t.Setenv("GODEBUG", "multipathtcp=3")
	for _, side := range []string{"listener", "dialer"} {
		t.Run(side, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			var listener stdnet.Listener
			var err error
			if side == "listener" {
				listener, err = new(DefaultListener).Listen(ctx, &stdnet.TCPAddr{IP: stdnet.IPv4(127, 0, 0, 1)}, nil)
			} else {
				var config stdnet.ListenConfig
				config.SetMultipathTCP(true)
				listener, err = config.Listen(ctx, "tcp", "127.0.0.1:0")
			}
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			var client stdnet.Conn
			if side == "dialer" {
				port := net.Port(listener.Addr().(*stdnet.TCPAddr).Port)
				client, err = new(DefaultSystemDialer).Dial(ctx, nil, net.TCPDestination(net.LocalHostIP, port), nil)
			} else {
				var d stdnet.Dialer
				d.SetMultipathTCP(true)
				client, err = d.DialContext(ctx, "tcp", listener.Addr().String())
			}
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			server, err := listener.Accept()
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			for _, c := range []stdnet.Conn{client, server} {
				on, err := c.(*stdnet.TCPConn).MultipathTCP()
				if err != nil {
					t.Fatal(err)
				}
				if on {
					t.Fatalf("%s default unexpectedly negotiated MPTCP", side)
				}
			}
		})
	}
}
