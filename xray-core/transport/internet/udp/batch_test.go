package udp_test

import (
	bytespkg "bytes"
	"fmt"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	. "github.com/xtls/xray-core/transport/internet/udp"
)

var benchmarkBatchConn *BatchConn

func TestBatchConnReadWrite(t *testing.T) {
	testBatchConnReadWrite(t, "udp4", "127.0.0.1")
}

func TestBatchConnReadWriteIPv6(t *testing.T) {
	testBatchConnReadWrite(t, "udp6", "::1")
}

func testBatchConnReadWrite(t *testing.T, network, ip string) {
	server, err := net.ListenUDP(network, &net.UDPAddr{IP: net.ParseIP(ip)})
	if err != nil {
		t.Skip(err)
	}
	defer server.Close()
	client, err := net.ListenUDP(network, &net.UDPAddr{IP: net.ParseIP(ip)})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	batch := NewBatchConn(server)
	if batch == nil {
		t.Skip("UDP batching is unavailable")
	}

	const packetCount = 8
	for i := 0; i < packetCount; i++ {
		payload := []byte(fmt.Sprintf("request-%02d", i))
		if _, err := client.WriteToUDP(payload, server.LocalAddr().(*net.UDPAddr)); err != nil {
			t.Fatal(err)
		}
	}

	var reads [packetCount]BatchReadMessage
	for i := range reads {
		reads[i].Buffer = buf.New()
		defer reads[i].Buffer.Release()
	}
	if err := server.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	n, err := batch.Read(reads[:], false)
	if err != nil {
		t.Fatal(err)
	}
	if n != packetCount {
		t.Fatalf("received %d packets, want %d", n, packetCount)
	}

	writes := make([]BatchWriteMessage, n)
	for i := 0; i < n; i++ {
		want := []byte(fmt.Sprintf("request-%02d", i))
		if !bytespkg.Equal(reads[i].Buffer.Bytes(), want) {
			t.Fatalf("packet %d is %q, want %q", i, reads[i].Buffer.Bytes(), want)
		}
		writes[i] = BatchWriteMessage{Payload: reads[i].Buffer.Bytes(), Addr: reads[i].Addr}
	}
	written, err := batch.Write(writes)
	if err != nil {
		t.Fatal(err)
	}
	if written != packetCount {
		t.Fatalf("sent %d packets, want %d", written, packetCount)
	}

	if err := client.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	received := make([]byte, buf.Size)
	for i := 0; i < packetCount; i++ {
		n, _, err := client.ReadFromUDP(received)
		if err != nil {
			t.Fatal(err)
		}
		want := []byte(fmt.Sprintf("request-%02d", i))
		if !bytespkg.Equal(received[:n], want) {
			t.Fatalf("response %d is %q, want %q", i, received[:n], want)
		}
	}
}

func BenchmarkUDPWrite16Scalar(b *testing.B) {
	benchmarkUDPWrite16(b, false)
}

func BenchmarkNewBatchConn(b *testing.B) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		b.Fatal(err)
	}
	defer conn.Close()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		benchmarkBatchConn = NewBatchConn(conn)
	}
}

func BenchmarkUDPWrite16Batch(b *testing.B) {
	benchmarkUDPWrite16(b, true)
}

func BenchmarkUDPRead16Scalar(b *testing.B) {
	benchmarkUDPRead16(b, false)
}

func BenchmarkUDPRead16Batch(b *testing.B) {
	benchmarkUDPRead16(b, true)
}

func benchmarkUDPWrite16(b *testing.B, batched bool) {
	receiver, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		b.Fatal(err)
	}
	sender, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		receiver.Close()
		b.Fatal(err)
	}
	defer sender.Close()

	done := make(chan struct{})
	go func() {
		payload := make([]byte, buf.Size)
		for {
			if _, _, err := receiver.ReadFromUDP(payload); err != nil {
				close(done)
				return
			}
		}
	}()
	defer func() {
		receiver.Close()
		<-done
	}()

	payload := make([]byte, 200)
	dest := receiver.LocalAddr()
	batch := NewBatchConn(sender)
	if batched && batch == nil {
		b.Skip("UDP batching is unavailable")
	}
	var messages [MaxBatchSize]BatchWriteMessage
	for i := range messages {
		messages[i] = BatchWriteMessage{Payload: payload, Addr: dest}
	}

	b.ReportAllocs()
	b.SetBytes(int64(len(payload) * len(messages)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if batched {
			if n, err := batch.Write(messages[:]); err != nil || n != len(messages) {
				b.Fatalf("batch write: n=%d err=%v", n, err)
			}
			continue
		}
		for range messages {
			if _, err := sender.WriteTo(payload, dest); err != nil {
				b.Fatal(err)
			}
		}
	}
}

func benchmarkUDPRead16(b *testing.B, batched bool) {
	receiver, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		b.Fatal(err)
	}
	defer receiver.Close()
	sender, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		b.Fatal(err)
	}
	defer sender.Close()

	payload := make([]byte, 200)
	dest := receiver.LocalAddr().(*net.UDPAddr)
	batch := NewBatchConn(receiver)
	if batched && batch == nil {
		b.Skip("UDP batching is unavailable")
	}
	var messages [MaxBatchSize]BatchReadMessage

	b.ReportAllocs()
	b.SetBytes(int64(len(payload) * len(messages)))
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		for range messages {
			if _, err := sender.WriteToUDP(payload, dest); err != nil {
				b.Fatal(err)
			}
		}
		for j := range messages {
			messages[j] = BatchReadMessage{Buffer: buf.New()}
		}
		b.StartTimer()

		if batched {
			n, err := batch.Read(messages[:], false)
			if err != nil || n != len(messages) {
				b.Fatalf("batch read: n=%d err=%v", n, err)
			}
		} else {
			for j := range messages {
				n, _, err := receiver.ReadFromUDP(messages[j].Buffer.WritableBytes())
				if err != nil {
					b.Fatal(err)
				}
				messages[j].Buffer.Commit(int32(n))
			}
		}

		b.StopTimer()
		for j := range messages {
			messages[j].Buffer.Release()
			messages[j].Buffer = nil
		}
		b.StartTimer()
	}
}
