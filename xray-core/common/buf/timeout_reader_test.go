package buf

import (
	"errors"
	"testing"
	"time"
)

type timeoutDelegateReader struct {
	readCalls        int
	timeoutReadCalls int
	mb               MultiBuffer
	err              error
}

func (r *timeoutDelegateReader) ReadMultiBuffer() (MultiBuffer, error) {
	r.readCalls++
	return r.mb, r.err
}

func (r *timeoutDelegateReader) ReadMultiBufferTimeout(time.Duration) (MultiBuffer, error) {
	r.timeoutReadCalls++
	return r.mb, r.err
}

type blockingTestReader struct {
	result chan MultiBuffer
}

func (r *blockingTestReader) ReadMultiBuffer() (MultiBuffer, error) {
	return <-r.result, nil
}

func TestTimeoutWrapperReaderDelegatesAndCounts(t *testing.T) {
	b := FromBytes(make([]byte, 1234))
	reader := &timeoutDelegateReader{mb: MultiBuffer{b}}
	var counter testCounter
	wrapper := &TimeoutWrapperReader{Reader: reader, Counter: &counter}

	mb, err := wrapper.ReadMultiBufferTimeout(time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if reader.timeoutReadCalls != 1 || reader.readCalls != 0 {
		t.Fatalf("timeout calls = %d, ordinary calls = %d", reader.timeoutReadCalls, reader.readCalls)
	}
	if got := mb.Len(); got != 1234 {
		t.Fatalf("length = %d, want 1234", got)
	}
	if got := counter.Value(); got != 1234 {
		t.Fatalf("counter = %d, want 1234", got)
	}
}

func TestTimeoutWrapperReaderMapsReadTimeout(t *testing.T) {
	reader := &timeoutDelegateReader{err: ErrReadTimeout}
	wrapper := &TimeoutWrapperReader{Reader: reader}

	mb, err := wrapper.ReadMultiBufferTimeout(time.Millisecond)
	if err != nil || !mb.IsEmpty() {
		t.Fatalf("got (%v, %v), want (nil, nil)", mb, err)
	}
}

func TestTimeoutWrapperReaderPreservesOtherErrors(t *testing.T) {
	want := errors.New("read failure")
	reader := &timeoutDelegateReader{err: want}
	wrapper := &TimeoutWrapperReader{Reader: reader}

	_, err := wrapper.ReadMultiBufferTimeout(time.Millisecond)
	if !errors.Is(err, want) {
		t.Fatalf("error = %v, want %v", err, want)
	}
}

func TestTimeoutWrapperReaderFallbackRetainsPendingRead(t *testing.T) {
	reader := &blockingTestReader{result: make(chan MultiBuffer, 1)}
	var counter testCounter
	wrapper := &TimeoutWrapperReader{Reader: reader, Counter: &counter}

	mb, err := wrapper.ReadMultiBufferTimeout(time.Millisecond)
	if err != nil || !mb.IsEmpty() {
		t.Fatalf("got (%v, %v), want timeout as (nil, nil)", mb, err)
	}
	reader.result <- MultiBuffer{FromBytes(make([]byte, 321))}
	mb, err = wrapper.ReadMultiBuffer()
	if err != nil {
		t.Fatal(err)
	}
	if got := mb.Len(); got != 321 {
		t.Fatalf("length = %d, want 321", got)
	}
	if got := counter.Value(); got != 321 {
		t.Fatalf("counter = %d, want 321", got)
	}
}
