//go:build linux || android

package proxy

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common/signal"
)

func spliceTCPPair(t testing.TB) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	l, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	c, err := net.DialTCP("tcp", nil, l.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	s, err := l.AcceptTCP()
	if err != nil {
		c.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close(); s.Close() })
	c.SetDeadline(time.Now().Add(5 * time.Second))
	s.SetDeadline(time.Now().Add(5 * time.Second))
	return s, c
}

func waitCounter(t *testing.T, counter *stats.Counter, want int64) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for counter.Value() != want && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := counter.Value(); got != want {
		t.Fatalf("counter=%d, want=%d", got, want)
	}
}

func TestSpliceProgressAndIdleCancellation(t *testing.T) {
	src, sender := spliceTCPPair(t)
	dst, receiver := spliceTCPPair(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	timer := signal.CancelAfterInactivity(ctx, cancel, 100*time.Millisecond)
	defer timer.SetTimeout(0)
	read, written, user := new(stats.Counter), new(stats.Counter), new(stats.Counter)
	done := make(chan error, 1)
	go func() {
		handled, err := spliceCopy(ctx, src, dst, read, written, user, timer)
		if !handled {
			err = errors.New("splice unavailable on TCP")
		}
		done <- err
	}()
	payload := bytes.Repeat([]byte{0xa5}, 64*1024)
	for i := range 6 {
		if _, err := sender.Write(payload); err != nil {
			t.Fatal(err)
		}
		got := make([]byte, len(payload))
		if _, err := io.ReadFull(receiver, got); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, payload) {
			t.Fatal("splice corrupted data")
		}
		want := int64((i + 1) * len(payload))
		waitCounter(t, read, want)
		waitCounter(t, written, want)
		waitCounter(t, user, want)
		if ctx.Err() != nil {
			t.Fatal("active connection timed out")
		}
		time.Sleep(50 * time.Millisecond)
	}
	// Keep the sender open: both statistics and idle cleanup must work before EOF.
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("idle cancellation: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("idle splice did not stop")
	}
}

func TestSpliceDuplexAndHalfClose(t *testing.T) {
	left, client := spliceTCPPair(t)
	right, server := spliceTCPPair(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	up, down := new(stats.Counter), new(stats.Counter)
	upload, download := make(chan error, 1), make(chan error, 1)
	go func() { _, err := spliceCopy(ctx, left, right, nil, nil, up); upload <- err }()
	go func() { _, err := spliceCopy(ctx, right, left, nil, nil, down); download <- err }()
	payload := bytes.Repeat([]byte("duplex"), 32768)
	write := make(chan error, 1)
	go func() { _, err := client.Write(payload); client.CloseWrite(); write <- err }()
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(server, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("upload changed")
	}
	if err := <-write; err != nil {
		t.Fatal(err)
	}
	if err := <-upload; err != nil {
		t.Fatal(err)
	}
	// Upload EOF must leave the reverse direction usable.
	go func() { _, err := server.Write(payload); server.CloseWrite(); write <- err }()
	if _, err := io.ReadFull(client, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("download changed")
	}
	if err := <-write; err != nil {
		t.Fatal(err)
	}
	if err := <-download; err != nil {
		t.Fatal(err)
	}
	waitCounter(t, up, int64(len(payload)))
	waitCounter(t, down, int64(len(payload)))
}

func TestSpliceCancellationDuringBlockedWrite(t *testing.T) {
	src, sender := spliceTCPPair(t)
	dst, receiver := spliceTCPPair(t)
	dst.SetWriteBuffer(1024)
	receiver.SetReadBuffer(1024)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	read, written := new(stats.Counter), new(stats.Counter)
	done := make(chan error, 1)
	go func() { _, err := spliceCopy(ctx, src, dst, read, written, nil); done <- err }()
	go sender.Write(make([]byte, 8*1024*1024))
	deadline := time.Now().Add(time.Second)
	for read.Value() < 65536 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if read.Value() == 0 {
		t.Fatal("no input spliced")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancel: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("blocked write ignored cancellation")
	}
	if written.Value() > read.Value() {
		t.Fatal("accounted for unwritten data")
	}
}

func TestSpliceUnsupportedSourceLeavesDataUntouched(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	dst, _ := spliceTCPPair(t)
	if handled, err := spliceCopy(context.Background(), a, dst, nil, nil, nil); handled || err != nil {
		t.Fatalf("unsupported source: handled=%v error=%v", handled, err)
	}
	done := make(chan error, 1)
	go func() { _, err := b.Write([]byte("untouched")); done <- err }()
	got := make([]byte, 9)
	if _, err := io.ReadFull(a, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != "untouched" {
		t.Fatal("fallback lost data")
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

// Compare against the former TCPConn.ReadFrom path with the same TCP producer
// and consumer. This is a loopback microbenchmark, not an Internet speed test.
func BenchmarkSpliceAccounting(b *testing.B) {
	for _, progress := range []bool{false, true} {
		name := "ReadFrom"
		if progress {
			name = "Incremental"
		}
		b.Run(name, func(b *testing.B) {
			src, sender := spliceTCPPair(b)
			dst, receiver := spliceTCPPair(b)
			// Benchmark calibration may run longer than normal regression tests.
			src.SetDeadline(time.Time{})
			sender.SetDeadline(time.Time{})
			dst.SetDeadline(time.Time{})
			receiver.SetDeadline(time.Time{})
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			timer := signal.CancelAfterInactivity(ctx, cancel, time.Minute)
			defer timer.SetTimeout(0)
			const perOp = 1024 * 1024
			total := int64(b.N) * perOp
			read, written, user := new(stats.Counter), new(stats.Counter), new(stats.Counter)
			start := make(chan struct{})
			sent, received := make(chan error, 1), make(chan error, 1)
			go func() {
				<-start
				block := make([]byte, 64*1024)
				for remaining := total; remaining > 0; {
					n, err := sender.Write(block[:min(int64(len(block)), remaining)])
					if err != nil {
						sent <- err
						return
					}
					remaining -= int64(n)
				}
				sender.CloseWrite()
				sent <- nil
			}()
			go func() { <-start; _, err := io.CopyN(io.Discard, receiver, total); received <- err }()
			b.SetBytes(perOp)
			b.ReportAllocs()
			b.ResetTimer()
			close(start)
			var err error
			if progress {
				_, err = spliceCopy(ctx, src, dst, read, written, user, timer)
			} else {
				var n int64
				n, err = dst.ReadFrom(src)
				read.Add(n)
				written.Add(n)
				user.Add(n)
			}
			if err != nil {
				b.Fatal(err)
			}
			if err := <-sent; err != nil {
				b.Fatal(err)
			}
			if err := <-received; err != nil {
				b.Fatal(err)
			}
			b.StopTimer()
			if user.Value() != total {
				b.Fatalf("counter=%d, want=%d", user.Value(), total)
			}
		})
	}
}
