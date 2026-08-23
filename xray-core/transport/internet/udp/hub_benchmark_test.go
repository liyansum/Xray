package udp_test

import (
	"context"
	"testing"

	"github.com/xtls/xray-core/common/net"
	. "github.com/xtls/xray-core/transport/internet/udp"
)

func BenchmarkHubSingleFlowSinglePacket(b *testing.B) {
	benchmarkHub(b, 1, 1)
}

func BenchmarkHubSingleFlowBurst16(b *testing.B) {
	benchmarkHub(b, 1, 16)
}

func BenchmarkHubMultiFlow64(b *testing.B) {
	benchmarkHub(b, 64, 1)
}

func benchmarkHub(b *testing.B, flows, packetsPerFlow int) {
	hub, err := ListenUDP(context.Background(), net.LocalHostIP, 0, nil, HubCapacity(4096))
	if err != nil {
		b.Fatal(err)
	}
	defer hub.Close()
	dest := hub.Addr().(*net.UDPAddr)

	clients := make([]*net.UDPConn, flows)
	for i := range clients {
		clients[i], err = net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
		if err != nil {
			b.Fatal(err)
		}
		defer clients[i].Close()
	}

	payload := make([]byte, 200)
	packetsPerIteration := flows * packetsPerFlow
	b.ReportAllocs()
	b.SetBytes(int64(len(payload) * packetsPerIteration))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, client := range clients {
			for j := 0; j < packetsPerFlow; j++ {
				if _, err := client.WriteToUDP(payload, dest); err != nil {
					b.Fatal(err)
				}
			}
		}
		for j := 0; j < packetsPerIteration; j++ {
			packet, ok := <-hub.Receive()
			if !ok {
				b.Fatal("UDP hub closed unexpectedly")
			}
			if packet.Payload.Len() != int32(len(payload)) {
				b.Fatalf("received %d bytes, want %d", packet.Payload.Len(), len(payload))
			}
			packet.Payload.Release()
		}
	}
	b.StopTimer()
}
