package trojan

import (
	"bytes"
	"errors"
	"io"
	"os"
	"testing"
	"time"
)

func TestAnyTLSSyncPipeBackpressureAndPartialReads(t *testing.T) {
	reader, writer := newAnyTLSSyncPipe()
	expected := bytes.Repeat([]byte{0x7a}, 32*1024)
	writeDone := make(chan error, 1)
	go func() {
		written, err := writer.Write(expected)
		if err == nil && written != len(expected) {
			err = io.ErrShortWrite
		}
		writeDone <- err
	}()

	select {
	case err := <-writeDone:
		t.Fatalf("write completed without a reader: %v", err)
	case <-time.After(20 * time.Millisecond):
	}

	actual := make([]byte, len(expected))
	for offset := 0; offset < len(actual); {
		end := min(offset+8192, len(actual))
		read, err := reader.Read(actual[offset:end])
		if err != nil {
			t.Fatal(err)
		}
		offset += read
	}
	if !bytes.Equal(actual, expected) {
		t.Fatal("synchronous pipe changed payload contents")
	}
	if err := <-writeDone; err != nil {
		t.Fatal(err)
	}
	_ = reader.Close()
}

func TestAnyTLSSyncPipeReadDeadlineCanBeReset(t *testing.T) {
	reader, _ := newAnyTLSSyncPipe()
	if err := reader.SetReadDeadline(time.Now().Add(10 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	var payload [1]byte
	if _, err := reader.Read(payload[:]); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("deadline returned %v, want %v", err, os.ErrDeadlineExceeded)
	}
	if err := reader.SetReadDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	_ = reader.Close()
}

func TestAnyTLSSyncPipeCloseUnblocksWriter(t *testing.T) {
	reader, writer := newAnyTLSSyncPipe()
	writeDone := make(chan error, 1)
	go func() {
		_, err := writer.Write([]byte("blocked"))
		writeDone <- err
	}()
	time.Sleep(10 * time.Millisecond)
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-writeDone:
		if !errors.Is(err, io.ErrClosedPipe) {
			t.Fatalf("closed pipe returned %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("closing the reader did not unblock the writer")
	}
}
