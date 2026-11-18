package proxy

import (
	"context"
	"encoding/binary"
	"testing"

	"github.com/xtls/xray-core/common/buf"
)

func testServerHello(version uint16, cipher uint16) []byte {
	body := make([]byte, 46)
	body[0], body[1] = 3, 3
	binary.BigEndian.PutUint16(body[35:], cipher)
	binary.BigEndian.PutUint16(body[38:], 6)
	binary.BigEndian.PutUint16(body[40:], 43)
	binary.BigEndian.PutUint16(body[42:], 2)
	binary.BigEndian.PutUint16(body[44:], version)
	return append([]byte{2, 0, 0, byte(len(body))}, body...)
}
func testTLSRecord(kind byte, data []byte) []byte {
	return append([]byte{kind, 3, 3, byte(len(data) >> 8), byte(len(data))}, data...)
}

func TestVisionHelloAcrossRecordsAndByteReads(t *testing.T) {
	hello := testServerHello(0x0304, 0x1301)
	for cut := 1; cut < len(hello); cut++ {
		s := NewTrafficState(make([]byte, 16))
		wire := append(testTLSRecord(22, hello[:cut]), testTLSRecord(22, hello[cut:])...)
		for _, v := range wire {
			mb := buf.MultiBuffer{buf.FromBytes([]byte{v})}
			s.filterTLS(mb, false)
		}
		if !s.EnableXtls || s.Cipher != 0x1301 {
			t.Fatalf("split %d did not negotiate TLS 1.3", cut)
		}
	}
}

func TestVisionDoesNotDirectCopyOtherTLSVersionsOrCiphers(t *testing.T) {
	for _, tc := range []struct {
		version, cipher uint16
		want            bool
	}{{0x0304, 0x1301, true}, {0x0304, 0x1303, true}, {0x0304, 0x1305, false}, {0x0303, 0xc02b, false}, {0x0304, 0xffff, false}} {
		s := NewTrafficState(make([]byte, 16))
		mb := buf.MultiBuffer{buf.FromBytes(testTLSRecord(22, testServerHello(tc.version, tc.cipher)))}
		status, _ := s.filterTLS(mb, false)
		if status.enableXtls != tc.want {
			t.Fatalf("version=%x cipher=%x enable=%v", tc.version, tc.cipher, status.enableXtls)
		}
	}
}

func TestVisionRejectsMalformedHelloLengths(t *testing.T) {
	for _, mutate := range []func([]byte){func(b []byte) { b[4+34] = 255 }, func(b []byte) { b[4+38] = 255 }, func(b []byte) { b[4+42] = 255 }} {
		s := NewTrafficState(make([]byte, 16))
		hello := testServerHello(0x0304, 0x1301)
		mutate(hello)
		status, _ := s.filterTLS(buf.MultiBuffer{buf.FromBytes(testTLSRecord(22, hello))}, false)
		if status.enableXtls || !status.stopPadding {
			t.Fatal("malformed ServerHello accepted")
		}
	}
}

func TestVisionUnpaddingEveryHeaderSplit(t *testing.T) {
	id := []byte("sixteen-byte-key")
	payload := []byte("payload remains byte-exact")
	writeID := append([]byte(nil), id...)
	encoded := XtlsPadding(buf.FromBytes(payload), CommandPaddingEnd, &writeID, false, context.Background(), []uint32{900, 1, 900, 1})
	defer encoded.Release()
	for cut := 1; cut < 21; cut++ {
		s := NewTrafficState(id)
		var got []byte
		for _, part := range [][]byte{encoded.BytesTo(int32(cut)), encoded.BytesFrom(int32(cut))} {
			out, err := xtlsUnpadding(buf.FromBytes(part), s, true)
			if err != nil {
				t.Fatal(err)
			}
			got = append(got, out.Bytes()...)
			out.Release()
		}
		if string(got) != string(payload) || !s.Inbound.padding.done {
			t.Fatalf("header split %d: %q", cut, got)
		}
	}
}

func BenchmarkVisionRecordBoundary(b *testing.B) {
	data := testTLSRecord(23, make([]byte, 16384+17))
	mb := buf.MergeBytes(nil, data)
	defer buf.ReleaseMulti(mb)
	b.ReportAllocs()
	b.SetBytes(int64(len(data)))
	s := TrafficState{IsTLS: true, EnableXtls: true, tlsNegotiated: true}
	for b.Loop() {
		status, end := s.filterTLS(mb, false)
		if !status.enableXtls || end != int32(len(data)) {
			b.Fatal(end)
		}
	}
}

func BenchmarkVisionIsCompleteRecord(b *testing.B) {
	data := testTLSRecord(23, make([]byte, 16384+17))
	mb := buf.MergeBytes(nil, data)
	defer buf.ReleaseMulti(mb)
	b.ReportAllocs()
	b.SetBytes(int64(len(data)))
	for b.Loop() {
		if !IsCompleteRecord(mb) {
			b.Fatal("incomplete")
		}
	}
}
