package trojan

import (
	"sync"

	singbuf "github.com/sagernet/sing/common/buf"
)

const anyTLSMaxPooledBufferSize = 64 * 1024

var (
	anyTLSInitialDataFramePool = sync.Pool{New: func() any {
		return new([anyTLSInitialFrameBufferSize]byte)
	}}
	anyTLSLargeDataFramePool = sync.Pool{New: func() any {
		return new([anyTLSMaxFrameBufferSize]byte)
	}}
)

func getAnyTLSDataFrameStorage(payloadCapacity int) []byte {
	switch {
	case payloadCapacity <= 0:
		panic("invalid AnyTLS data frame payload capacity")
	case payloadCapacity <= anyTLSInitialFramePayloadSize:
		return anyTLSInitialDataFramePool.Get().(*[anyTLSInitialFrameBufferSize]byte)[:]
	case payloadCapacity <= anyTLSMaxFramePayloadSize:
		return anyTLSLargeDataFramePool.Get().(*[anyTLSMaxFrameBufferSize]byte)[:]
	default:
		panic("AnyTLS data frame payload capacity is too large")
	}
}

func putAnyTLSDataFrameStorage(storage []byte) {
	switch cap(storage) {
	case anyTLSInitialFrameBufferSize:
		anyTLSInitialDataFramePool.Put((*[anyTLSInitialFrameBufferSize]byte)(storage[:anyTLSInitialFrameBufferSize]))
	case anyTLSMaxFrameBufferSize:
		anyTLSLargeDataFramePool.Put((*[anyTLSMaxFrameBufferSize]byte)(storage[:anyTLSMaxFrameBufferSize]))
	default:
		panic("invalid AnyTLS data frame storage")
	}
}

// AnyTLS frames use uint16 payload lengths. Reuse the same 64B..64KiB
// power-of-two allocator as sing-anytls instead of Xray's coarser
// 2/8/32/128KiB classes. A control frame may contain a full uint16 payload
// plus its header, so the oversized edge case is allocated exactly.
func getAnyTLSBufferStorage(size int) []byte {
	if size <= 0 {
		panic("invalid AnyTLS pooled buffer size")
	}
	if size > anyTLSMaxPooledBufferSize {
		return make([]byte, size)
	}
	return singbuf.Get(size)
}

func putAnyTLSBufferStorage(storage []byte) {
	if cap(storage) > anyTLSMaxPooledBufferSize {
		return
	}
	if err := singbuf.Put(storage); err != nil {
		panic(err)
	}
}
