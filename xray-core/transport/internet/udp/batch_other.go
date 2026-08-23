//go:build !linux

package udp

import "github.com/xtls/xray-core/common/net"

func NewBatchConn(net.PacketConn) *BatchConn {
	return nil
}

func IsBatchWouldBlock(error) bool {
	return false
}
