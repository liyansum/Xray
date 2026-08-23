package freedom

import (
	"context"
	"crypto/rand"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pires/go-proxyproto"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/crypto"
	"github.com/xtls/xray-core/common/dice"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/platform"
	"github.com/xtls/xray-core/common/retry"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/common/utils"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
	internetudp "github.com/xtls/xray-core/transport/internet/udp"
)

var useSplice atomic.Bool

func reloadEnvSettings() error {
	const defaultFlagValue = "NOT_DEFINED_AT_ALL"
	value := platform.NewEnvFlag(platform.UseFreedomSplice).GetValue(func() string { return defaultFlagValue })
	enabled := false
	switch value {
	case defaultFlagValue, "auto", "enable":
		enabled = true
	}
	useSplice.Store(enabled)
	return nil
}

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		h := new(Handler)
		if err := core.RequireFeatures(ctx, func(pm policy.Manager) error {
			return h.Init(config.(*Config), pm)
		}); err != nil {
			return nil, err
		}
		return h, nil
	}))

	platform.RegisterEnvReload(reloadEnvSettings)
}

// Handler handles Freedom connections.
type Handler struct {
	policyManager policy.Manager
	config        *Config
}

// Init initializes the Handler with necessary parameters.
func (h *Handler) Init(config *Config, pm policy.Manager) error {
	h.config = config
	h.policyManager = pm
	return nil
}

func (h *Handler) policy() policy.Session {
	p := h.policyManager.ForLevel(h.config.UserLevel)
	return p
}

func isValidAddress(addr *net.IPOrDomain) bool {
	if addr == nil {
		return false
	}

	a := addr.AsAddress()
	return a != net.AnyIP && a != net.AnyIPv6
}

// Process implements proxy.Outbound.
func (h *Handler) Process(ctx context.Context, link *transport.Link, dialer internet.Dialer) error {
	outbounds := session.OutboundsFromContext(ctx)
	ob := outbounds[len(outbounds)-1]
	if !ob.Target.IsValid() {
		return errors.New("target not specified.")
	}
	ob.Name = "freedom"
	ob.CanSpliceCopy = 1
	inbound := session.InboundFromContext(ctx)

	destination := ob.Target
	origTargetAddr := ob.OriginalTarget.Address
	if origTargetAddr == nil {
		origTargetAddr = ob.Target.Address
	}
	dialer.SetOutboundGateway(ctx, ob)
	outGateway := ob.Gateway
	UDPOverride := net.UDPDestination(nil, 0)
	if h.config.DestinationOverride != nil {
		server := h.config.DestinationOverride.Server
		if isValidAddress(server.Address) {
			destination.Address = server.Address.AsAddress()
			UDPOverride.Address = destination.Address
		}
		if server.Port != 0 {
			destination.Port = net.Port(server.Port)
			UDPOverride.Port = destination.Port
		}
	}

	input := link.Reader
	output := link.Writer

	var conn stat.Connection
	err := retry.ExponentialBackoff(5, 100).On(func() error {
		dialDest := destination
		if h.config.DomainStrategy.HasStrategy() && dialDest.Address.Family().IsDomain() {
			strategy := h.config.DomainStrategy
			if destination.Network == net.Network_UDP && origTargetAddr != nil && outGateway == nil {
				strategy = strategy.GetDynamicStrategy(origTargetAddr.Family())
			}
			ips, err := internet.LookupForIP(dialDest.Address.Domain(), strategy, outGateway)
			if err != nil {
				errors.LogInfoInner(ctx, err, "failed to get IP address for domain ", dialDest.Address.Domain())
				if h.config.DomainStrategy.ForceIP() {
					return err
				}
			} else {
				dialDest = net.Destination{
					Network: dialDest.Network,
					Address: net.IPAddress(ips[dice.Roll(len(ips))]),
					Port:    dialDest.Port,
				}
				errors.LogInfo(ctx, "dialing to ", dialDest)
			}
		}

		rawConn, err := dialer.Dial(ctx, dialDest)
		if err != nil {
			return err
		}

		conn = rawConn
		return nil
	})
	if err != nil {
		return errors.New("failed to open connection to ", destination).Base(err)
	}
	if h.config.ProxyProtocol > 0 && h.config.ProxyProtocol <= 2 {
		version := byte(h.config.ProxyProtocol)
		srcAddr := inbound.Source.RawNetAddr()
		dstAddr := conn.RemoteAddr()
		header := proxyproto.HeaderProxyFromAddrs(version, srcAddr, dstAddr)
		if _, err = header.WriteTo(conn); err != nil {
			conn.Close()
			return errors.New("failed to set PROXY protocol v", version).Base(err)
		}
	}
	defer conn.Close()
	var udpBatchConn *internetudp.BatchConn
	if destination.Network == net.Network_UDP {
		udpBatchConn = newPacketBatchConn(conn)
	}
	errors.LogInfo(ctx, "connection opened to ", destination, ", local endpoint ", conn.LocalAddr(), ", remote endpoint ", conn.RemoteAddr())

	var newCtx context.Context
	var newCancel context.CancelFunc
	if session.TimeoutOnlyFromContext(ctx) {
		newCtx, newCancel = context.WithCancel(context.Background())
	}

	plcy := h.policy()
	ctx, cancel := context.WithCancel(ctx)
	timer := signal.CancelAfterInactivity(ctx, func() {
		cancel()
		if newCancel != nil {
			newCancel()
		}
	}, plcy.Timeouts.ConnectionIdle)
	defer cancel()
	if newCancel != nil {
		defer newCancel()
	}
	defer timer.SetTimeout(0)

	requestDone := func() error {
		defer timer.SetTimeout(plcy.Timeouts.DownlinkOnly)

		var writer buf.Writer
		if destination.Network == net.Network_TCP {
			if h.config.Fragment != nil {
				errors.LogDebug(ctx, "FRAGMENT", h.config.Fragment.PacketsFrom, h.config.Fragment.PacketsTo, h.config.Fragment.LengthMin, h.config.Fragment.LengthMax,
					h.config.Fragment.IntervalMin, h.config.Fragment.IntervalMax, h.config.Fragment.MaxSplitMin, h.config.Fragment.MaxSplitMax)
				writer = buf.NewWriter(&FragmentWriter{
					fragment: h.config.Fragment,
					writer:   conn,
				})
			} else {
				writer = buf.NewWriter(conn)
			}
		} else {
			writer = newPacketWriter(conn, h, UDPOverride, destination, udpBatchConn)
			if h.config.Noises != nil {
				errors.LogDebug(ctx, "NOISE", h.config.Noises)
				writer = &NoisePacketWriter{
					Writer:      writer,
					noises:      h.config.Noises,
					firstWrite:  true,
					UDPOverride: UDPOverride,
					remoteAddr:  net.DestinationFromAddr(conn.RemoteAddr()).Address,
				}
			}
		}

		if err := buf.Copy(input, writer, buf.UpdateActivity(timer)); err != nil {
			return errors.New("failed to process request").Base(err)
		}

		return nil
	}

	responseDone := func() error {
		defer timer.SetTimeout(plcy.Timeouts.UplinkOnly)
		if destination.Network == net.Network_TCP && useSplice.Load() && proxy.IsRAWTransportWithoutSecurity(conn) { // it would be tls conn in special use case of MITM, we need to let link handle traffic
			var writeConn net.Conn
			var inTimer *signal.ActivityTimer
			if inbound := session.InboundFromContext(ctx); inbound != nil && inbound.Conn != nil {
				writeConn = inbound.Conn
				inTimer = inbound.Timer
			}
			return proxy.CopyRawConnIfExist(ctx, conn, writeConn, link.Writer, timer, inTimer)
		}
		var reader buf.Reader
		if destination.Network == net.Network_TCP {
			reader = buf.NewReader(conn)
		} else {
			reader = newPacketReader(conn, UDPOverride, destination, udpBatchConn)
		}
		if err := buf.Copy(reader, output, buf.UpdateActivity(timer)); err != nil {
			return errors.New("failed to process response").Base(err)
		}
		return nil
	}

	if newCtx != nil {
		ctx = newCtx
	}

	if err := task.Run(ctx, requestDone, task.OnSuccess(responseDone, task.Close(output))); err != nil {
		return errors.New("connection ends").Base(err)
	}

	return nil
}

func NewPacketReader(conn net.Conn, UDPOverride net.Destination, DialDest net.Destination) buf.Reader {
	return newPacketReader(conn, UDPOverride, DialDest, nil)
}

func newPacketReader(conn net.Conn, UDPOverride net.Destination, DialDest net.Destination, batchConn *internetudp.BatchConn) buf.Reader {
	iConn := conn
	statConn, ok := iConn.(*stat.CounterConnection)
	if ok {
		iConn = statConn.Connection
	}
	var counter stats.Counter
	if statConn != nil {
		counter = statConn.ReadCounter
	}
	if c, ok := iConn.(*internet.PacketConnWrapper); ok {
		if batchConn == nil {
			batchConn = internetudp.NewBatchConn(c.PacketConn)
		}
		isOverridden := false
		if UDPOverride.Address != nil || UDPOverride.Port != 0 {
			isOverridden = true
		}

		return &PacketReader{
			PacketConnWrapper: c,
			BatchConn:         batchConn,
			Counter:           counter,
			IsOverridden:      isOverridden,
			InitUnchangedAddr: DialDest.Address,
			InitChangedAddr:   net.DestinationFromAddr(conn.RemoteAddr()).Address,
		}
	}
	return &buf.PacketReader{Reader: conn}
}

type PacketReader struct {
	*internet.PacketConnWrapper
	BatchConn *internetudp.BatchConn
	stats.Counter
	IsOverridden      bool
	InitUnchangedAddr net.Address
	InitChangedAddr   net.Address
}

func (r *PacketReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	b := buf.New()
	readStarted := time.Now()
	n, d, err := r.PacketConnWrapper.ReadFrom(b.WritableBytes())
	readImmediately := time.Since(readStarted) <= 100*time.Microsecond
	if err != nil {
		b.Release()
		return nil, err
	}
	b.Commit(int32(n))
	if !r.setPacketSource(b, d) {
		b.Release()
		return nil, errors.New("invalid UDP source address")
	}

	mb := buf.MultiBuffer{b}
	total := int64(n)
	if readImmediately && r.BatchConn != nil && r.BatchConn.HasPending() {
		// The first packet has already been read without retaining extra memory.
		// Drain at most seven queued packets so idle UDP sessions never hold a
		// permanent 16-buffer recvmmsg working set.
		var messages [7]internetudp.BatchReadMessage
		for i := range messages {
			messages[i].Buffer = buf.New()
		}
		batchN, batchErr := r.BatchConn.Read(messages[:], true)
		for i := 0; i < batchN; i++ {
			packet := messages[i].Buffer
			messages[i].Buffer = nil
			if !r.setPacketSource(packet, messages[i].Addr) {
				packet.Release()
				continue
			}
			total += int64(messages[i].N)
			mb = append(mb, packet)
		}
		for i := batchN; i < len(messages); i++ {
			messages[i].Buffer.Release()
		}
		if batchErr != nil && !internetudp.IsBatchWouldBlock(batchErr) {
			// Preserve the already received datagram and fall back to the regular
			// path for future reads if this socket can't use recvmmsg.
			r.BatchConn = nil
		}
	}
	if r.Counter != nil {
		r.Counter.Add(total)
	}
	return mb, nil
}

func (r *PacketReader) setPacketSource(b *buf.Buffer, addr net.Addr) bool {
	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		return false
	}
	sourceAddr := net.IPAddress(udpAddr.IP)

	// If UDP destination address is changed, the correct source address is
	// unavailable. Don't attach source info in that case to preserve cone mode.
	if !r.IsOverridden {
		if r.InitChangedAddr == sourceAddr {
			sourceAddr = r.InitUnchangedAddr
		}
		b.UDP = &net.Destination{
			Address: sourceAddr,
			Port:    net.Port(udpAddr.Port),
			Network: net.Network_UDP,
		}
	}
	return true
}

// DialDest means the dial target used in the dialer when creating conn
func NewPacketWriter(conn net.Conn, h *Handler, UDPOverride net.Destination, DialDest net.Destination) buf.Writer {
	return newPacketWriter(conn, h, UDPOverride, DialDest, nil)
}

func newPacketWriter(conn net.Conn, h *Handler, UDPOverride net.Destination, DialDest net.Destination, batchConn *internetudp.BatchConn) buf.Writer {
	iConn := conn
	statConn, ok := iConn.(*stat.CounterConnection)
	if ok {
		iConn = statConn.Connection
	}
	var counter stats.Counter
	if statConn != nil {
		counter = statConn.WriteCounter
	}
	if c, ok := iConn.(*internet.PacketConnWrapper); ok {
		if batchConn == nil {
			batchConn = internetudp.NewBatchConn(c.PacketConn)
		}
		// If DialDest is a domain, it will be resolved in dialer
		// check this behavior and add it to map
		resolvedUDPAddr := utils.NewTypedSyncMap[string, net.Address]()
		var resolvedUDPOrder []string
		if DialDest.Address.Family().IsDomain() {
			resolvedUDPAddr.Store(DialDest.Address.Domain(), net.DestinationFromAddr(conn.RemoteAddr()).Address)
			resolvedUDPOrder = append(resolvedUDPOrder, DialDest.Address.Domain())
		}
		return &PacketWriter{
			PacketConnWrapper: c,
			BatchConn:         batchConn,
			Counter:           counter,
			Handler:           h,
			UDPOverride:       UDPOverride,
			ResolvedUDPAddr:   resolvedUDPAddr,
			LocalAddr:         net.DestinationFromAddr(conn.LocalAddr()).Address,
			resolvedUDPOrder:  resolvedUDPOrder,
		}

	}
	return &buf.SequentialWriter{Writer: conn}
}

func newPacketBatchConn(conn net.Conn) *internetudp.BatchConn {
	iConn := conn
	if statConn, ok := iConn.(*stat.CounterConnection); ok {
		iConn = statConn.Connection
	}
	if c, ok := iConn.(*internet.PacketConnWrapper); ok {
		return internetudp.NewBatchConn(c.PacketConn)
	}
	return nil
}

type PacketWriter struct {
	*internet.PacketConnWrapper
	BatchConn *internetudp.BatchConn
	stats.Counter
	*Handler
	UDPOverride net.Destination

	// Dest of udp packets might be a domain, we will resolve them to IP
	// But resolver will return a random one if the domain has many IPs
	// Resulting in these packets being sent to many different IPs randomly
	// So, cache and keep the resolve result
	ResolvedUDPAddr *utils.TypedSyncMap[string, net.Address]
	LocalAddr       net.Address

	resolvedUDPMu    sync.Mutex
	resolvedUDPOrder []string
	resolvedUDPNext  int
}

const resolvedUDPAddrCacheCapacity = 256

// cacheResolvedUDPAddr keeps a stable address for each recently used domain
// while preserving PacketWriter's existing public map type. FIFO eviction is
// sufficient because DNS TTL isn't tracked; the requirement here is a fixed
// per-session memory bound.
func (w *PacketWriter) cacheResolvedUDPAddr(domain string, address net.Address) net.Address {
	w.resolvedUDPMu.Lock()
	defer w.resolvedUDPMu.Unlock()
	if existing, found := w.ResolvedUDPAddr.Load(domain); found {
		return existing
	}
	if len(w.resolvedUDPOrder) == resolvedUDPAddrCacheCapacity {
		w.ResolvedUDPAddr.Delete(w.resolvedUDPOrder[w.resolvedUDPNext])
		w.resolvedUDPOrder[w.resolvedUDPNext] = domain
		w.resolvedUDPNext = (w.resolvedUDPNext + 1) % resolvedUDPAddrCacheCapacity
	} else {
		w.resolvedUDPOrder = append(w.resolvedUDPOrder, domain)
	}
	w.ResolvedUDPAddr.Store(domain, address)
	return address
}

func (w *PacketWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	defer buf.ReleaseMulti(mb)
	if w.BatchConn == nil || len(mb) < 2 {
		for _, b := range mb {
			addr, ok := w.resolvePacketAddress(b)
			if !ok {
				continue
			}
			n, err := w.PacketConnWrapper.WriteTo(b.Bytes(), addr)
			if err != nil {
				return err
			}
			if w.Counter != nil {
				w.Counter.Add(int64(n))
			}
		}
		return nil
	}

	var messages [internetudp.MaxBatchSize]internetudp.BatchWriteMessage
	for first := 0; first < len(mb); {
		count := 0
		for first < len(mb) && count < len(messages) {
			b := mb[first]
			first++
			addr, ok := w.resolvePacketAddress(b)
			if !ok {
				continue
			}
			if b.IsEmpty() {
				n, err := w.PacketConnWrapper.WriteTo(nil, addr)
				if err != nil {
					return err
				}
				if w.Counter != nil {
					w.Counter.Add(int64(n))
				}
				continue
			}
			messages[count] = internetudp.BatchWriteMessage{Payload: b.Bytes(), Addr: addr}
			count++
		}

		sent := 0
		for sent < count {
			n, err := w.BatchConn.Write(messages[sent:count])
			if w.Counter != nil {
				for i := sent; i < sent+n; i++ {
					w.Counter.Add(int64(messages[i].N))
				}
			}
			sent += n
			if err != nil {
				return err
			}
		}
		for i := 0; i < count; i++ {
			messages[i] = internetudp.BatchWriteMessage{}
		}
	}
	return nil
}

func (w *PacketWriter) resolvePacketAddress(b *buf.Buffer) (net.Addr, bool) {
	if b.UDP == nil {
		return w.PacketConnWrapper.Dest, true
	}
	if w.UDPOverride.Address != nil {
		b.UDP.Address = w.UDPOverride.Address
	}
	if w.UDPOverride.Port != 0 {
		b.UDP.Port = w.UDPOverride.Port
	}
	if b.UDP.Address.Family().IsDomain() {
		domain := b.UDP.Address.Domain()
		if ip, ok := w.ResolvedUDPAddr.Load(domain); ok {
			b.UDP.Address = ip
		} else {
			shouldUseSystemResolver := true
			var ip net.Address
			if w.Handler.config.DomainStrategy.HasStrategy() {
				ips, err := internet.LookupForIP(domain, w.Handler.config.DomainStrategy, w.LocalAddr)
				if err != nil {
					if w.Handler.config.DomainStrategy.ForceIP() {
						return nil, false
					}
				} else {
					ip = net.IPAddress(ips[dice.Roll(len(ips))])
					shouldUseSystemResolver = false
				}
			}
			if shouldUseSystemResolver {
				udpAddr, err := net.ResolveUDPAddr("udp", b.UDP.NetAddr())
				if err != nil {
					return nil, false
				}
				ip = net.IPAddress(udpAddr.IP)
			}
			if ip != nil {
				b.UDP.Address = w.cacheResolvedUDPAddr(domain, ip)
			}
		}
	}
	destAddr := b.UDP.RawNetAddr()
	return destAddr, destAddr != nil
}

type NoisePacketWriter struct {
	buf.Writer
	noises      []*Noise
	firstWrite  bool
	UDPOverride net.Destination
	remoteAddr  net.Address
}

// MultiBuffer writer with Noise before first packet
func (w *NoisePacketWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	if w.firstWrite {
		w.firstWrite = false
		// Do not send Noise for dns requests(just to be safe)
		if w.UDPOverride.Port == 53 {
			return w.Writer.WriteMultiBuffer(mb)
		}
		var noise []byte
		var err error
		if w.remoteAddr.Family().IsDomain() {
			panic("impossible, remoteAddr is always IP")
		}
		for _, n := range w.noises {
			switch n.ApplyTo {
			case "ipv4":
				if w.remoteAddr.Family().IsIPv6() {
					continue
				}
			case "ipv6":
				if w.remoteAddr.Family().IsIPv4() {
					continue
				}
			case "ip":
			default:
				panic("unreachable, applyTo is ip/ipv4/ipv6")
			}
			// User input string or base64 encoded string or hex string
			if n.Packet != nil {
				noise = n.Packet
			} else {
				// Random noise
				noise, err = GenerateRandomBytes(crypto.RandBetween(int64(n.LengthMin),
					int64(n.LengthMax)))
			}
			if err != nil {
				return err
			}
			err = w.Writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes(noise)})
			if err != nil {
				return err
			}

			if n.DelayMin != 0 || n.DelayMax != 0 {
				time.Sleep(time.Duration(crypto.RandBetween(int64(n.DelayMin), int64(n.DelayMax))) * time.Millisecond)
			}
		}

	}
	return w.Writer.WriteMultiBuffer(mb)
}

type FragmentWriter struct {
	fragment *Fragment
	writer   io.Writer
	count    uint64
}

func (f *FragmentWriter) Write(b []byte) (int, error) {
	f.count++

	if f.fragment.PacketsFrom == 0 && f.fragment.PacketsTo == 1 {
		if f.count != 1 || len(b) <= 5 || b[0] != 22 {
			return f.writer.Write(b)
		}
		recordLen := 5 + ((int(b[3]) << 8) | int(b[4]))
		if len(b) < recordLen { // maybe already fragmented somehow
			return f.writer.Write(b)
		}
		data := b[5:recordLen]
		buff := make([]byte, 2048)
		var hello []byte
		maxSplit := crypto.RandBetween(int64(f.fragment.MaxSplitMin), int64(f.fragment.MaxSplitMax))
		var splitNum int64
		for from := 0; ; {
			to := from + int(crypto.RandBetween(int64(f.fragment.LengthMin), int64(f.fragment.LengthMax)))
			splitNum++
			if to > len(data) || (maxSplit > 0 && splitNum >= maxSplit) {
				to = len(data)
			}
			l := to - from
			if 5+l > len(buff) {
				buff = make([]byte, 5+l)
			}
			copy(buff[:3], b)
			copy(buff[5:], data[from:to])
			from = to
			buff[3] = byte(l >> 8)
			buff[4] = byte(l)
			if f.fragment.IntervalMax == 0 { // combine fragmented tlshello if interval is 0
				hello = append(hello, buff[:5+l]...)
			} else {
				_, err := f.writer.Write(buff[:5+l])
				time.Sleep(time.Duration(crypto.RandBetween(int64(f.fragment.IntervalMin), int64(f.fragment.IntervalMax))) * time.Millisecond)
				if err != nil {
					return 0, err
				}
			}
			if from == len(data) {
				if len(hello) > 0 {
					_, err := f.writer.Write(hello)
					if err != nil {
						return 0, err
					}
				}
				if len(b) > recordLen {
					n, err := f.writer.Write(b[recordLen:])
					if err != nil {
						return recordLen + n, err
					}
				}
				return len(b), nil
			}
		}
	}

	if f.fragment.PacketsFrom != 0 && (f.count < f.fragment.PacketsFrom || f.count > f.fragment.PacketsTo) {
		return f.writer.Write(b)
	}
	maxSplit := crypto.RandBetween(int64(f.fragment.MaxSplitMin), int64(f.fragment.MaxSplitMax))
	var splitNum int64
	for from := 0; ; {
		to := from + int(crypto.RandBetween(int64(f.fragment.LengthMin), int64(f.fragment.LengthMax)))
		splitNum++
		if to > len(b) || (maxSplit > 0 && splitNum >= maxSplit) {
			to = len(b)
		}
		n, err := f.writer.Write(b[from:to])
		from += n
		if err != nil {
			return from, err
		}
		time.Sleep(time.Duration(crypto.RandBetween(int64(f.fragment.IntervalMin), int64(f.fragment.IntervalMax))) * time.Millisecond)
		if from >= len(b) {
			return from, nil
		}
	}
}

func GenerateRandomBytes(n int64) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	// Note that err == nil only if we read len(b) bytes.
	if err != nil {
		return nil, err
	}

	return b, nil
}
