//go:build linux

package udp

import (
	"testing"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"golang.org/x/sys/unix"
)

func TestBatchConnPreservesOriginalDestination(t *testing.T) {
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	raw, err := server.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	if err := raw.Control(func(fd uintptr) {
		err = unix.SetsockoptInt(int(fd), unix.SOL_IP, unix.IP_RECVORIGDSTADDR, 1)
	}); err != nil {
		t.Fatal(err)
	}
	if err != nil {
		t.Fatal(err)
	}

	client, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if _, err := client.WriteToUDP([]byte("original-destination"), server.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatal(err)
	}

	batch := NewBatchConn(server)
	if batch == nil {
		t.Fatal("UDP batching is unavailable")
	}
	b := buf.New()
	defer b.Release()
	oob := make([]byte, 256)
	messages := []BatchReadMessage{{Buffer: b, OOB: oob}}
	n, err := batch.Read(messages, false)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 || messages[0].NN == 0 {
		t.Fatalf("received %d packets with %d OOB bytes", n, messages[0].NN)
	}
	target := RetrieveOriginalDest(oob[:messages[0].NN])
	want := server.LocalAddr().(*net.UDPAddr)
	if !target.IsValid() || target.Port != net.Port(want.Port) || target.Address.String() != want.IP.String() {
		t.Fatalf("original destination is %v, want %v", target, want)
	}
}
