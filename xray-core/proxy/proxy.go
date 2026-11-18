// Package proxy contains all proxies used by Xray.
//
// To implement an inbound or outbound proxy, one needs to do the following:
// 1. Implement the interface(s) below.
// 2. Register a config creator through common.RegisterConfig.
package proxy

import (
	"context"
	"io"
	"runtime"

	"github.com/pires/go-proxyproto"
	"github.com/xtls/xray-core/app/dispatcher"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/internet/tls"
)

// An Inbound processes inbound connections.
type Inbound interface {
	// Network returns a list of networks that this inbound supports. Connections with not-supported networks will not be passed into Process().
	Network() []net.Network

	// Process processes a connection of given network. If necessary, the Inbound can dispatch the connection to an Outbound.
	Process(context.Context, net.Network, stat.Connection, routing.Dispatcher) error
}

// An Outbound process outbound connections.
type Outbound interface {
	// Process processes the given connection. The given dialer may be used to dial a system outbound connection.
	Process(context.Context, *transport.Link, internet.Dialer) error
}

// UserManager is the interface for Inbounds and Outbounds that can manage their users.
type UserManager interface {
	// AddUser adds a new user.
	AddUser(context.Context, *protocol.MemoryUser) error

	// RemoveUser removes a user by email.
	RemoveUser(context.Context, string) error

	// Get user by email.
	GetUser(context.Context, string) *protocol.MemoryUser

	// Get all users.
	GetUsers(context.Context) []*protocol.MemoryUser

	// Get users count.
	GetUsersCount(context.Context) int64
}

type GetInbound interface {
	GetInbound() Inbound
}

type GetOutbound interface {
	GetOutbound() Outbound
}

// UnwrapRawConn unwraps stats, mask, TLS, proxy protocol, and Unix socket wrappers.
func UnwrapRawConn(conn net.Conn) (net.Conn, stats.Counter, stats.Counter) {
	var readCounter, writerCounter stats.Counter
	if conn != nil {
		if statConn, ok := conn.(*stat.CounterConnection); ok {
			conn = statConn.Connection
			readCounter = statConn.ReadCounter
			writerCounter = statConn.WriteCounter
		}

		if tlsConn, ok := conn.(*tls.Conn); ok {
			conn = tlsConn.NetConn()
		} else if utlsConn, ok := conn.(*tls.UConn); ok {
			conn = utlsConn.NetConn()
		}

		if pc, ok := conn.(*proxyproto.Conn); ok {
			conn = pc.Raw()
			// 8192 > 4096, there is no need to process pc's bufReader
		}
		if uc, ok := conn.(*internet.UnixConnWrapper); ok {
			conn = uc.UnixConn
		}
	}
	return conn, readCounter, writerCounter
}

// splicePermitted preserves explicit transport vetoes. Directional protocol
// readiness is checked separately, by the goroutine that owns that direction.
func splicePermitted(ctx context.Context) bool {
	inbound := session.InboundFromContext(ctx)
	if inbound == nil || inbound.CanSpliceCopy == 3 {
		return false
	}
	outbounds := session.OutboundsFromContext(ctx)
	if len(outbounds) == 0 {
		return false
	}
	for _, ob := range outbounds {
		if ob == nil || ob.CanSpliceCopy == 3 {
			return false
		}
	}
	return true
}

func spliceOutboundsReady(ctx context.Context) bool {
	for _, ob := range session.OutboundsFromContext(ctx) {
		if ob.CanSpliceCopy != 1 {
			return false
		}
	}
	return true
}

// CopyRawConnIfExist copies a raw response, switching to splice only after the
// protocol writer has flushed its transition and any raw suffix.
func CopyRawConnIfExist(ctx context.Context, readerConn net.Conn, writerConn net.Conn, writer buf.Writer, timer *signal.ActivityTimer, inTimer *signal.ActivityTimer) error {
	readerConn, readCounter, _ := UnwrapRawConn(readerConn)
	rawWriter, _, writeCounter := UnwrapRawConn(writerConn)
	reader := buf.NewReader(readerConn)
	_, tcp := rawWriter.(*net.TCPConn)
	eligible := (runtime.GOOS == "linux" || runtime.GOOS == "android") && tcp && splicePermitted(ctx)
	for {
		if eligible {
			var userCounter stats.Counter
			ready := session.InboundFromContext(ctx).CanSpliceCopy == 1
			if direct, ok := writer.(buf.DirectWriter); ok {
				conn, counter := direct.DirectWriteConn()
				if conn != nil {
					rawWriter, _, writeCounter = UnwrapRawConn(conn)
					userCounter, ready = counter, true
				}
			}
			if userCounter == nil {
				if sw, ok := writer.(*dispatcher.SizeStatWriter); ok {
					userCounter = sw.Counter
				}
			}
			if dst, ok := rawWriter.(*net.TCPConn); ready && ok && spliceOutboundsReady(ctx) {
				if handled, err := spliceCopy(ctx, readerConn, dst, readCounter, writeCounter, userCounter, timer, inTimer); handled {
					return err
				}
				eligible = false // unsupported; keep all wrappers in the fallback
			}
		}
		buffer, err := reader.ReadMultiBuffer()
		if !buffer.IsEmpty() {
			if readCounter != nil {
				readCounter.Add(int64(buffer.Len()))
			}
			if timer != nil {
				timer.Update()
			}
			if werr := writer.WriteMultiBuffer(buffer); werr != nil {
				return werr
			}
		}
		if err != nil {
			if errors.Cause(err) == io.EOF {
				return nil
			}
			return err
		}
	}
}

// CopyDirectReader copies a request, allowing Vision to expose its raw source
// once all TLS, sniffing and protocol buffers have been forwarded. No shared
// readiness flag is written by the opposite direction.
func CopyDirectReader(ctx context.Context, reader buf.Reader, writerConn net.Conn, writer buf.Writer, timer *signal.ActivityTimer, inTimer *signal.ActivityTimer) error {
	direct, ok := reader.(buf.DirectReader)
	rawWriter, _, writeCounter := UnwrapRawConn(writerConn)
	dst, tcp := rawWriter.(*net.TCPConn)
	if !ok || !tcp || !splicePermitted(ctx) || (runtime.GOOS != "linux" && runtime.GOOS != "android") {
		return buf.Copy(reader, writer, buf.UpdateActivity(timer))
	}
	eligible := true
	for {
		if eligible {
			if conn, userCounter := direct.DirectReadConn(); conn != nil && spliceOutboundsReady(ctx) {
				src, readCounter, _ := UnwrapRawConn(conn)
				if handled, err := spliceCopy(ctx, src, dst, readCounter, writeCounter, userCounter, timer, inTimer); handled {
					return err
				}
				eligible = false
			}
		}
		mb, err := reader.ReadMultiBuffer()
		if !mb.IsEmpty() {
			if timer != nil {
				timer.Update()
			}
			if werr := writer.WriteMultiBuffer(mb); werr != nil {
				return werr
			}
		}
		if err != nil {
			if errors.Cause(err) == io.EOF {
				return nil
			}
			return err
		}
	}
}

func IsRAWTransportWithoutSecurity(conn stat.Connection) bool {
	iConn := stat.TryUnwrapStatsConn(conn)
	_, ok1 := iConn.(*proxyproto.Conn)
	_, ok2 := iConn.(*net.TCPConn)
	_, ok3 := iConn.(*internet.UnixConnWrapper)
	return ok1 || ok2 || ok3
}
