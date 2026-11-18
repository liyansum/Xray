//go:build !linux && !android

package proxy

import (
	"context"
	"net"

	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/features/stats"
)

func spliceCopy(context.Context, net.Conn, *net.TCPConn, stats.Counter, stats.Counter, stats.Counter, ...*signal.ActivityTimer) (bool, error) {
	return false, nil
}
