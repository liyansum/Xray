package proxy

import (
	"bytes"
	"context"
	"testing"

	"github.com/xtls/xray-core/common/buf"
)

func TestVisionPaddingRoundTrip(t *testing.T) {
	userID := []byte{0x55, 0x0e, 0x84, 0x00, 0xe2, 0x9b, 0x41, 0xd4, 0xa7, 0x16, 0x44, 0x66, 0x55, 0x44, 0x00, 0x00}
	payload := []byte("vision payload")
	input := buf.FromBytes(append([]byte(nil), payload...))
	writeID := append([]byte(nil), userID...)
	padded := XtlsPadding(input, CommandPaddingDirect, &writeID, false, context.Background(), []uint32{900, 1, 900, 1})

	state := NewTrafficState(userID)
	output := XtlsUnpadding(padded, state, true, context.Background())
	defer output.Release()
	if !bytes.Equal(output.Bytes(), payload) {
		t.Fatalf("payload mismatch: got %q want %q", output.Bytes(), payload)
	}
	if state.Inbound.CurrentCommand != int(CommandPaddingDirect) {
		t.Fatalf("command=%d", state.Inbound.CurrentCommand)
	}
}
