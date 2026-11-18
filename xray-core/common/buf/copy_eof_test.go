package buf_test

import (
	"bytes"
	"errors"
	"io"
	"testing"
	"time"

	. "github.com/xtls/xray-core/common/buf"
)

type onceFinalReader struct{ *finalBatchReader }

func (r onceFinalReader) ReadMultiBufferTimeout(time.Duration) (MultiBuffer, error) {
	return r.ReadMultiBuffer()
}

type failingFinalWriter struct{ err error }

func (w failingFinalWriter) WriteMultiBuffer(mb MultiBuffer) error { ReleaseMulti(mb); return w.err }

func TestCopyOnceTimeoutPreservesFinalPayloadAndError(t *testing.T) {
	for _, terminal := range []error{io.EOF, io.ErrUnexpectedEOF, errors.New("transport failure")} {
		t.Run(terminal.Error(), func(t *testing.T) {
			reader := onceFinalReader{&finalBatchReader{err: terminal}}
			var output bytes.Buffer
			err := CopyOnceTimeout(reader, NewWriter(&output), time.Second)
			if output.String() != "header-body" || !errors.Is(err, terminal) {
				t.Fatalf("lost data or error: %q / %v", output.String(), err)
			}
		})
	}
}
func TestCopyOnceTimeoutReportsWriteFailure(t *testing.T) {
	reader := onceFinalReader{&finalBatchReader{err: io.EOF}}
	want := errors.New("write failure")
	if err := CopyOnceTimeout(reader, failingFinalWriter{want}, time.Second); !errors.Is(err, want) || !IsWriteError(err) {
		t.Fatalf("masked write failure: %v", err)
	}
}
