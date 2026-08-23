package freedom

import (
	bytespkg "bytes"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/utils"
	"github.com/xtls/xray-core/transport/internet"
	internetudp "github.com/xtls/xray-core/transport/internet/udp"
)

type testCounter struct {
	value atomic.Int64
}

func (c *testCounter) Value() int64      { return c.value.Load() }
func (c *testCounter) Set(v int64) int64 { return c.value.Swap(v) }
func (c *testCounter) Add(v int64) int64 { return c.value.Add(v) - v }

func TestPacketWriterBatchPreservesStats(t *testing.T) {
	receiver, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer receiver.Close()
	sender, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()

	batch := internetudp.NewBatchConn(sender)
	if batch == nil {
		t.Skip("UDP batching is unavailable")
	}
	counter := new(testCounter)
	dest := net.UDPDestination(net.IPAddress(receiver.LocalAddr().(*net.UDPAddr).IP), net.Port(receiver.LocalAddr().(*net.UDPAddr).Port))
	wrapper := &internet.PacketConnWrapper{PacketConn: sender, Dest: receiver.LocalAddr()}
	writer := &PacketWriter{
		PacketConnWrapper: wrapper,
		BatchConn:         batch,
		Counter:           counter,
	}

	const packetCount = 8
	mb := make(buf.MultiBuffer, 0, packetCount)
	wantBytes := int64(0)
	for i := 0; i < packetCount; i++ {
		b := buf.New()
		payload := []byte(fmt.Sprintf("payload-%02d", i))
		_, _ = b.Write(payload)
		b.UDP = &dest
		mb = append(mb, b)
		wantBytes += int64(len(payload))
	}
	if err := writer.WriteMultiBuffer(mb); err != nil {
		t.Fatal(err)
	}
	if got := counter.Value(); got != wantBytes {
		t.Fatalf("counter is %d, want %d", got, wantBytes)
	}

	if err := receiver.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	data := make([]byte, buf.Size)
	for i := 0; i < packetCount; i++ {
		n, _, err := receiver.ReadFromUDP(data)
		if err != nil {
			t.Fatal(err)
		}
		want := []byte(fmt.Sprintf("payload-%02d", i))
		if !bytespkg.Equal(data[:n], want) {
			t.Fatalf("packet %d is %q, want %q", i, data[:n], want)
		}
	}
}

func TestPacketReaderDrainsBurstAndPreservesStats(t *testing.T) {
	receiver, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer receiver.Close()
	sender, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()

	batch := internetudp.NewBatchConn(receiver)
	if batch == nil {
		t.Skip("UDP batching is unavailable")
	}
	counter := new(testCounter)
	reader := &PacketReader{
		PacketConnWrapper: &internet.PacketConnWrapper{PacketConn: receiver, Dest: sender.LocalAddr()},
		BatchConn:         batch,
		Counter:           counter,
	}

	const packetCount = 8
	wantBytes := int64(0)
	for i := 0; i < packetCount; i++ {
		payload := []byte(fmt.Sprintf("response-%02d", i))
		if _, err := sender.WriteToUDP(payload, receiver.LocalAddr().(*net.UDPAddr)); err != nil {
			t.Fatal(err)
		}
		wantBytes += int64(len(payload))
	}
	if err := receiver.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	mb, err := reader.ReadMultiBuffer()
	if err != nil {
		t.Fatal(err)
	}
	defer buf.ReleaseMulti(mb)
	if len(mb) != packetCount {
		t.Fatalf("read %d packets, want %d", len(mb), packetCount)
	}
	if got := counter.Value(); got != wantBytes {
		t.Fatalf("counter is %d, want %d", got, wantBytes)
	}
}

func TestResolvedUDPAddrCacheIsBounded(t *testing.T) {
	writer := &PacketWriter{ResolvedUDPAddr: utils.NewTypedSyncMap[string, net.Address]()}
	address := net.IPAddress([]byte{127, 0, 0, 1})
	for i := 0; i < resolvedUDPAddrCacheCapacity+32; i++ {
		writer.cacheResolvedUDPAddr(fmt.Sprintf("host-%d.example", i), address)
	}
	count := 0
	writer.ResolvedUDPAddr.Range(func(string, net.Address) bool {
		count++
		return true
	})
	if got := count; got != resolvedUDPAddrCacheCapacity {
		t.Fatalf("cache contains %d entries, want %d", got, resolvedUDPAddrCacheCapacity)
	}
	if _, found := writer.ResolvedUDPAddr.Load("host-0.example"); found {
		t.Fatal("oldest cache entry was not evicted")
	}
	if got, found := writer.ResolvedUDPAddr.Load(fmt.Sprintf("host-%d.example", resolvedUDPAddrCacheCapacity+31)); !found || got != address {
		t.Fatal("newest cache entry is missing")
	}
}

func TestResolvedUDPAddrCacheLoadOrStore(t *testing.T) {
	writer := &PacketWriter{ResolvedUDPAddr: utils.NewTypedSyncMap[string, net.Address]()}
	first := net.IPAddress([]byte{127, 0, 0, 1})
	second := net.IPAddress([]byte{127, 0, 0, 2})
	if got := writer.cacheResolvedUDPAddr("example.com", first); got != first {
		t.Fatal("first address was not stored")
	}
	if got := writer.cacheResolvedUDPAddr("example.com", second); got != first {
		t.Fatal("existing address was not kept stable")
	}
}
