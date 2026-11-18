package proxy_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"sync"
	"testing"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/proxy"
)

func TestVisionServerHelloFragmentation(t *testing.T) {
	handshake, _ := realTLS13(t)
	ext := bytes.Index(handshake, proxy.Tls13SupportedVersions)
	if ext < 0 {
		t.Fatal("real ServerHello missing supported_versions")
	}
	for _, cut := range []int{len(handshake), 5, 60, ext + 3} {
		t.Run(fmt.Sprintf("first_batch_%d", cut), func(t *testing.T) {
			s := proxy.NewTrafficState(make([]byte, 16))
			for _, part := range [][]byte{handshake[:cut], handshake[cut:]} {
				if len(part) == 0 || s.NumberOfPacketToFilter <= 0 {
					continue
				}
				mb := multi(part)
				proxy.XtlsFilterTls(mb, s, context.Background())
				buf.ReleaseMulti(mb)
			}
			want := true
			if s.EnableXtls != want {
				t.Fatalf("EnableXtls=%v want=%v", s.EnableXtls, want)
			}
			t.Logf("cut=%d IsTLS=%v IsTLS12orAbove=%v EnableXtls=%v cipher=%04x", cut, s.IsTLS, s.IsTLS12orAbove, s.EnableXtls, s.Cipher)
		})
	}
}

type fragmentReader struct{ parts [][]byte }

func (r *fragmentReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	if len(r.parts) == 0 {
		return nil, io.EOF
	}
	p := r.parts[0]
	r.parts = r.parts[1:]
	return multi(p), nil
}

func TestVisionInitialUUIDFragmentation(t *testing.T) {
	id := bytes.Repeat([]byte{0x55}, 16)
	writeID := append([]byte(nil), id...)
	payload := []byte("valid-inner-TLS-or-XUDP-payload")
	b := proxy.XtlsPadding(buf.FromBytes(payload), proxy.CommandPaddingEnd, &writeID, false, context.Background(), []uint32{900, 1, 900, 1})
	wire := append([]byte(nil), b.Bytes()...)
	b.Release()
	s := proxy.NewTrafficState(id)
	r := proxy.NewVisionReader(&fragmentReader{parts: [][]byte{wire[:8], wire[8:]}}, s, true, context.Background(), nil, nil, nil, nil)
	var got []byte
	for range 2 {
		mb, err := r.ReadMultiBuffer()
		if err != nil {
			t.Fatal(err)
		}
		part := make([]byte, mb.Len())
		mb.Copy(part)
		got = append(got, part...)
		buf.ReleaseMulti(mb)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("unexpected result: got=%x", got)
	}
	t.Logf("first padding UUID split at 8 bytes: %d decoded bytes, expected payload %d bytes", len(got), len(payload))
}

// Run separately with -race: an initial uplink read and downlink write use the
// same TrafficState in production. Both paths access TLS recognition fields.
func TestVisionConcurrentReadWrite(t *testing.T) {
	s := proxy.NewTrafficState(make([]byte, 16))
	parts := make([][]byte, 32)
	for i := range parts {
		parts[i] = []byte{0x16, 3, 1, 0, 4, 1, 0, 0, 0}
	}
	r := proxy.NewVisionReader(&fragmentReader{parts: parts}, s, true, context.Background(), nil, nil, nil, nil)
	w, _, _ := writer(s)
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		<-start
		for range 32 {
			mb, _ := r.ReadMultiBuffer()
			buf.ReleaseMulti(mb)
		}
	}()
	go func() {
		defer wg.Done()
		<-start
		for range 32 {
			_ = w.WriteMultiBuffer(multi([]byte("non-TLS-downlink")))
		}
	}()
	close(start)
	wg.Wait()
}
