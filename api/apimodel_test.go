package api

import "testing"

func TestPortValidation(t *testing.T) {
	for _, port := range []int64{1, 443, 65535} {
		got, err := PortFromInt64(port)
		if err != nil || got != uint32(port) {
			t.Fatalf("PortFromInt64(%d) = %d, %v", port, got, err)
		}
	}
	for _, port := range []int64{-1, 0, 65536} {
		if _, err := PortFromInt64(port); err == nil {
			t.Fatalf("PortFromInt64(%d) accepted an invalid port", port)
		}
	}
	for _, port := range []uint64{0, 65536, ^uint64(0)} {
		if _, err := PortFromUint64(port); err == nil {
			t.Fatalf("PortFromUint64(%d) accepted an invalid port", port)
		}
	}
}
