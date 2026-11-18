package proxy_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/proxy"
)

func multi(data []byte) buf.MultiBuffer {
	var mb buf.MultiBuffer
	for len(data) > 0 {
		n := min(len(data), buf.Size)
		b := buf.New()
		_, _ = b.Write(data[:n])
		mb = append(mb, b)
		data = data[n:]
	}
	return mb
}

func record(n int) []byte {
	b := bytes.Repeat([]byte{0xa5}, n+5)
	copy(b, []byte{0x17, 0x03, 0x03, byte(n >> 8), byte(n)})
	return b
}

type paddingSink struct {
	first    bool
	calls    int
	commands [3]int
	content  bytes.Buffer
}

func (s *paddingSink) WriteMultiBuffer(mb buf.MultiBuffer) error {
	defer buf.ReleaseMulti(mb)
	s.calls++
	for _, b := range mb {
		p := b.Bytes()
		if !s.first {
			if len(p) < 16 {
				return fmt.Errorf("missing UUID")
			}
			p = p[16:]
			s.first = true
		}
		if len(p) < 5 {
			return fmt.Errorf("short padding header")
		}
		n, pad := int(binary.BigEndian.Uint16(p[1:3])), int(binary.BigEndian.Uint16(p[3:5]))
		if len(p) != 5+n+pad || p[0] > 2 {
			return fmt.Errorf("invalid padding frame")
		}
		s.commands[p[0]]++
		s.content.Write(p[5 : 5+n])
	}
	return nil
}

type rawSink struct {
	bytes.Buffer
	calls int
}

func (s *rawSink) Write(p []byte) (int, error)    { s.calls++; return s.Buffer.Write(p) }
func (*rawSink) Read([]byte) (int, error)         { return 0, io.EOF }
func (*rawSink) Close() error                     { return nil }
func (*rawSink) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (*rawSink) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (*rawSink) SetDeadline(time.Time) error      { return nil }
func (*rawSink) SetReadDeadline(time.Time) error  { return nil }
func (*rawSink) SetWriteDeadline(time.Time) error { return nil }

func writer(state *proxy.TrafficState) (*proxy.VisionWriter, *paddingSink, *rawSink) {
	outer, raw := &paddingSink{}, &rawSink{}
	w := proxy.NewVisionWriter(outer, state, false, context.Background(), raw, nil, []uint32{900, 1, 900, 1})
	return w, outer, raw
}

func recognizedState() *proxy.TrafficState {
	s := proxy.NewTrafficState(make([]byte, 16))
	s.IsTLS, s.IsTLS12orAbove, s.EnableXtls = true, true, true
	s.NumberOfPacketToFilter = 0
	return s
}

func TestIsCompleteRecordBatchBoundaries(t *testing.T) {
	r := record(16384 + 17)
	tests := []struct {
		name string
		data []byte
		want bool
	}{
		{"whole_record_across_three_buffers_same_batch", r, true},
		{"first_batch_8192", r[:8192], false},
		{"second_batch_8192", r[8192:16384], false},
		{"last_batch_22", r[16384:], false},
		{"complete_record_plus_partial_next", append(record(64), r[:100]...), false},
		{"two_complete_records", append(record(64), r...), true},
		{"partial_header", r[:2], false},
		{"remaining_header_and_body", r[2:], false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mb := multi(tc.data)
			defer buf.ReleaseMulti(mb)
			if got := proxy.IsCompleteRecord(mb); got != tc.want {
				t.Fatalf("got=%v want=%v", got, tc.want)
			}
		})
	}
}

func TestWriterCompleteRecordSwitchesToRaw(t *testing.T) {
	s := recognizedState()
	w, outer, raw := writer(s)
	if err := w.WriteMultiBuffer(multi(record(16384 + 17))); err != nil {
		t.Fatal(err)
	}
	if s.Inbound.IsPadding || !s.Inbound.DownlinkWriterDirectCopy || outer.commands[2] != 1 {
		t.Fatalf("no direct command: state=%+v commands=%v", s.Inbound, outer.commands)
	}
	marker := []byte("next_write_bypasses_outer_TLS_writer")
	if err := w.WriteMultiBuffer(multi(marker)); err != nil {
		t.Fatal(err)
	}
	if outer.calls != 1 || !bytes.Equal(raw.Bytes(), marker) {
		t.Fatalf("outer calls=%d raw=%q", outer.calls, raw.Bytes())
	}
	t.Logf("complete record: padding=false, command2=1, next write raw=%d bytes", raw.Len())
}

func TestWriterSplitRecordsSwitchAtRecordBoundary(t *testing.T) {
	s := recognizedState()
	w, outer, raw := writer(s)
	stream := bytes.Repeat(record(16384+17), 128)
	calls := 0
	for p := stream; len(p) > 0; {
		n := min(len(p), 8192)
		if err := w.WriteMultiBuffer(multi(p[:n])); err != nil {
			t.Fatal(err)
		}
		p = p[n:]
		calls++
	}
	if s.Inbound.IsPadding || !s.Inbound.DownlinkWriterDirectCopy || outer.commands[2] != 1 || raw.calls == 0 {
		t.Fatalf("unexpected switch: state=%+v commands=%v raw=%d", s.Inbound, outer.commands, raw.calls)
	}
	if !bytes.Equal(append(outer.content.Bytes(), raw.Bytes()...), stream) {
		t.Fatal("payload changed")
	}
	t.Logf("%d records, %d bytes, %d batches: padding=%v command2=%d raw_writes=%d", 128, len(stream), calls, s.Inbound.IsPadding, outer.commands[2], raw.calls)

}

type recordingConn struct {
	net.Conn
	writes bytes.Buffer
}

func (c *recordingConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.writes.Write(p[:n])
	return n, err
}

// Capture genuine Go TLS 1.3 server ciphertext, including a real ServerHello,
// then test the existing VisionWriter with different read batching only.
func realTLS13(t *testing.T) (handshake, application []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	_ = a.SetDeadline(time.Now().Add(10 * time.Second))
	_ = b.SetDeadline(time.Now().Add(10 * time.Second))
	rec := &recordingConn{Conn: a}
	server := tls.Server(rec, &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, SessionTicketsDisabled: true, DynamicRecordSizingDisabled: true})
	client := tls.Client(b, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13})
	done := make(chan error, 1)
	go func() { done <- server.Handshake() }()
	if err := client.Handshake(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	handshake = append([]byte(nil), rec.writes.Bytes()...)
	rec.writes.Reset()
	const plaintextBytes = 128 * 16384
	go func() {
		n, err := io.CopyN(io.Discard, client, plaintextBytes)
		if err == nil && n != plaintextBytes {
			err = io.ErrUnexpectedEOF
		}
		done <- err
	}()
	if _, err := server.Write(bytes.Repeat([]byte{0x42}, plaintextBytes)); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	application = append([]byte(nil), rec.writes.Bytes()...)
	return
}

func TestRealTLS13CiphertextBatching(t *testing.T) {
	handshake, application := realTLS13(t)
	var records [][]byte
	for p := application; len(p) > 0; {
		if len(p) < 5 {
			t.Fatal("short real TLS record")
		}
		n := 5 + int(binary.BigEndian.Uint16(p[3:5]))
		if p[0] != 23 || n > len(p) {
			t.Fatal("invalid real application record")
		}
		records = append(records, p[:n])
		p = p[n:]
	}
	t.Logf("real TLS 1.3: handshake=%d bytes, encrypted application=%d bytes, records=%d, first_record=%d bytes", len(handshake), len(application), len(records), len(records[0]))
	for _, aligned := range []bool{true, false} {
		t.Run(fmt.Sprintf("record_aligned=%v", aligned), func(t *testing.T) {
			s := proxy.NewTrafficState(make([]byte, 16))
			w, outer, raw := writer(s)
			if err := w.WriteMultiBuffer(multi(handshake)); err != nil {
				t.Fatal(err)
			}
			if !s.IsTLS || !s.IsTLS12orAbove || !s.EnableXtls {
				t.Fatalf("real TLS 1.3 not recognized: %+v", s)
			}
			if s.Inbound.IsPadding {
				t.Fatal("encrypted TLS 1.3 handshake record did not switch to direct copy")
			}
			batches := 0
			if aligned {
				for _, r := range records {
					if err := w.WriteMultiBuffer(multi(r)); err != nil {
						t.Fatal(err)
					}
					batches++
				}
			} else {
				for p := application; len(p) > 0; {
					n := min(8192, len(p))
					if err := w.WriteMultiBuffer(multi(p[:n])); err != nil {
						t.Fatal(err)
					}
					p = p[n:]
					batches++
				}
			}
			if s.Inbound.IsPadding || outer.commands[2] != 1 || raw.Len() == 0 {
				t.Fatal("real TLS did not switch to direct copy")
			}
			expectedPrefix := 0
			for expectedPrefix < len(handshake) {
				start := expectedPrefix
				expectedPrefix += 5 + int(binary.BigEndian.Uint16(handshake[start+3:start+5]))
				if handshake[start] == 23 {
					break
				}
			}
			if outer.content.Len() != expectedPrefix {
				t.Fatal("switch did not occur at the first application record boundary")
			}

			want := append(append([]byte(nil), handshake...), application...)
			got := append(append([]byte(nil), outer.content.Bytes()...), raw.Bytes()...)
			if !bytes.Equal(got, want) {
				t.Fatal("reconstructed TLS stream mismatch")
			}
			t.Logf("EnableXtls=%v IsTLS12orAbove=%v filter_remaining=%d application_batches=%d padding=%v command2=%d outer_writer_calls=%d raw_bytes=%d", s.EnableXtls, s.IsTLS12orAbove, s.NumberOfPacketToFilter, batches, s.Inbound.IsPadding, outer.commands[2], outer.calls, raw.Len())
		})
	}
}
