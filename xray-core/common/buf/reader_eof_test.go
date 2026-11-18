package buf_test

import (
	"bytes"
	"errors"
	"io"
	"testing"

	. "github.com/xtls/xray-core/common/buf"
)

type finalBatchReader struct {
	calls int
	err   error
}

func (r *finalBatchReader) ReadMultiBuffer() (MultiBuffer, error) {
	r.calls++
	if r.calls > 1 {
		return nil, io.EOF
	}
	return MultiBuffer{FromBytes([]byte("header-body"))}, r.err
}

func TestBufferedReaderRetainsFinalBatchAcrossReadMethods(t *testing.T) {
	for _, terminal := range []error{io.EOF, io.ErrUnexpectedEOF, errors.New("transport failure")} {
		t.Run(terminal.Error(), func(t *testing.T) {
			source := &finalBatchReader{err: terminal}
			reader := &BufferedReader{Reader: source}
			first, err := reader.ReadByte()
			if err != nil || first != 'h' {
				t.Fatalf("lost final data while reading header: %q / %v", first, err)
			}
			prefix, err := reader.ReadAtMost(5)
			if err != nil || prefix.String() != "eader" {
				t.Fatalf("bad prefix: %q / %v", prefix.String(), err)
			}
			ReleaseMulti(prefix)
			body, err := reader.ReadMultiBuffer()
			defer ReleaseMulti(body)
			if body.String() != "-body" || !errors.Is(err, terminal) {
				t.Fatalf("lost body or read error: %q / %v", body.String(), err)
			}
			if source.calls != 1 {
				t.Fatal("read beyond pending terminal error")
			}
		})
	}
}

func TestBufferedReaderWriteToRetainsPendingError(t *testing.T) {
	terminal := errors.New("transport failure")
	source := &finalBatchReader{err: terminal}
	reader := &BufferedReader{Reader: source}
	prefix, err := reader.ReadAtMost(6)
	if err != nil || prefix.String() != "header" {
		t.Fatalf("bad header: %q / %v", prefix.String(), err)
	}
	ReleaseMulti(prefix)
	var body bytes.Buffer
	n, err := reader.WriteTo(&body)
	if n != 5 || body.String() != "-body" || !errors.Is(err, terminal) || source.calls != 1 {
		t.Fatalf("lost data/error: %d / %q / %v / %d", n, body.String(), err, source.calls)
	}
}

func TestBufferedReaderReadFullFinalDataBeforeEOF(t *testing.T) {
	source := &finalBatchReader{err: io.EOF}
	reader := &BufferedReader{Reader: source}
	data := make([]byte, 11)
	if _, err := io.ReadFull(reader, data); err != nil || string(data) != "header-body" {
		t.Fatalf("final read: %q / %v", data, err)
	}
	if _, err := reader.Read(make([]byte, 1)); err != io.EOF || source.calls != 1 {
		t.Fatal("lost pending EOF")
	}
}
