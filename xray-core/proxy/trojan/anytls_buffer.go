package trojan

import singbuf "github.com/sagernet/sing/common/buf"

const anyTLSMaxPooledBufferSize = 64 * 1024

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
