package udp

import (
	"context"
	"io"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol/udp"
	"github.com/xtls/xray-core/transport/internet"
)

type HubOption func(h *Hub)

func HubCapacity(capacity int) HubOption {
	return func(h *Hub) {
		h.capacity = capacity
	}
}

func HubReceiveOriginalDestination(r bool) HubOption {
	return func(h *Hub) {
		h.recvOrigDest = r
	}
}

type Hub struct {
	conn         net.PacketConn
	udpConn      *net.UDPConn
	batchConn    *BatchConn
	cache        chan *udp.Packet
	capacity     int
	recvOrigDest bool
}

func ListenUDP(ctx context.Context, address net.Address, port net.Port, streamSettings *internet.MemoryStreamConfig, options ...HubOption) (*Hub, error) {
	hub := &Hub{
		capacity:     256,
		recvOrigDest: false,
	}
	for _, opt := range options {
		opt(hub)
	}

	if address.Family().IsDomain() && address.Domain() == "localhost" {
		address = net.LocalHostIP
	}

	if address.Family().IsDomain() {
		return nil, errors.New("domain address is not allowed for listening: ", address.Domain())
	}

	var sockopt *internet.SocketConfig
	if streamSettings != nil {
		sockopt = streamSettings.SocketSettings
	}
	if sockopt != nil && sockopt.ReceiveOriginalDestAddress {
		hub.recvOrigDest = true
	}

	var err error
	hub.conn, err = internet.ListenSystemPacket(ctx, &net.UDPAddr{
		IP:   address.IP(),
		Port: int(port),
	}, sockopt)
	if err != nil {
		return nil, err
	}

	errors.LogInfo(ctx, "listening UDP on ", address, ":", port)
	hub.udpConn, _ = hub.conn.(*net.UDPConn)
	hub.batchConn = NewBatchConn(hub.conn)
	hub.cache = make(chan *udp.Packet, hub.capacity)

	go hub.start()
	return hub, nil
}

// Close implements net.Listener.
func (h *Hub) Close() error {
	h.conn.Close()
	return nil
}

func (h *Hub) WriteTo(payload []byte, dest net.Destination) (int, error) {
	return h.conn.WriteTo(payload, &net.UDPAddr{
		IP:   dest.Address.IP(),
		Port: int(dest.Port),
	})
}

// WriteMultiBuffer sends existing datagrams in batches when the platform and
// socket support it. It doesn't take ownership of mb and never waits to build a
// larger batch.
func (h *Hub) WriteMultiBuffer(mb buf.MultiBuffer, dest net.Destination) (int64, error) {
	addr := &net.UDPAddr{
		IP:   dest.Address.IP(),
		Port: int(dest.Port),
	}
	if h.batchConn == nil || len(mb) < 2 {
		var total int64
		for _, b := range mb {
			n, err := h.conn.WriteTo(b.Bytes(), addr)
			total += int64(n)
			if err != nil {
				return total, err
			}
		}
		return total, nil
	}

	var messages [MaxBatchSize]BatchWriteMessage
	var total int64
	for first := 0; first < len(mb); {
		if mb[first].IsEmpty() {
			n, err := h.conn.WriteTo(nil, addr)
			total += int64(n)
			if err != nil {
				return total, err
			}
			first++
			continue
		}

		count := 0
		for first+count < len(mb) && count < MaxBatchSize && !mb[first+count].IsEmpty() {
			messages[count] = BatchWriteMessage{Payload: mb[first+count].Bytes(), Addr: addr}
			count++
		}

		sent := 0
		for sent < count {
			n, err := h.batchConn.Write(messages[sent:count])
			for i := sent; i < sent+n; i++ {
				total += int64(messages[i].N)
			}
			sent += n
			if err != nil {
				return total, err
			}
			if n == 0 {
				return total, io.ErrNoProgress
			}
		}
		for i := 0; i < count; i++ {
			messages[i] = BatchWriteMessage{}
		}
		first += count
	}
	return total, nil
}

func (h *Hub) start() {
	c := h.cache
	defer close(c)

	oobBytes := make([]byte, 256)
	var batchMessages [MaxBatchSize - 1]BatchReadMessage
	var batchOOB [MaxBatchSize - 1][256]byte
	batchReadEnabled := h.batchConn != nil

	for {
		buffer := buf.New()
		var noob int
		var udpAddr *net.UDPAddr
		rawBytes := buffer.WritableBytes()

		var n int
		var err error
		readStarted := time.Now()
		if h.udpConn != nil {
			n, noob, _, udpAddr, err = ReadUDPMsg(h.udpConn, rawBytes, oobBytes)
		} else {
			var addr net.Addr
			n, addr, err = h.conn.ReadFrom(rawBytes)
			if err == nil {
				udpAddr = addr.(*net.UDPAddr)
			}
		}
		readImmediately := time.Since(readStarted) <= 100*time.Microsecond

		if err != nil {
			errors.LogInfoInner(context.Background(), err, "failed to read UDP msg")
			buffer.Release()
			break
		}
		buffer.Commit(int32(n))

		h.enqueue(c, buffer, udpAddr, oobBytes[:noob])

		if !readImmediately || !batchReadEnabled || !h.batchConn.HasPending() {
			continue
		}

		for i := range batchMessages {
			batchMessages[i] = BatchReadMessage{Buffer: buf.New(), OOB: batchOOB[i][:]}
		}
		batchN, batchErr := h.batchConn.Read(batchMessages[:], true)
		for i := 0; i < batchN; i++ {
			packetBuffer := batchMessages[i].Buffer
			batchMessages[i].Buffer = nil
			packetAddr, ok := batchMessages[i].Addr.(*net.UDPAddr)
			if !ok {
				packetBuffer.Release()
				continue
			}
			h.enqueue(c, packetBuffer, packetAddr, batchMessages[i].OOB[:batchMessages[i].NN])
		}
		for i := batchN; i < len(batchMessages); i++ {
			batchMessages[i].Buffer.Release()
			batchMessages[i].Buffer = nil
		}
		if batchErr != nil && !IsBatchWouldBlock(batchErr) {
			batchReadEnabled = false
		}
	}
}

func (h *Hub) enqueue(c chan<- *udp.Packet, buffer *buf.Buffer, udpAddr *net.UDPAddr, oob []byte) {
	if buffer.IsEmpty() {
		buffer.Release()
		return
	}

	payload := &udp.Packet{
		Payload: buffer,
		Source:  net.UDPDestination(net.IPAddress(udpAddr.IP), net.Port(udpAddr.Port)),
	}
	if h.recvOrigDest && len(oob) > 0 {
		payload.Target = RetrieveOriginalDest(oob)
		if payload.Target.IsValid() {
			errors.LogDebug(context.Background(), "UDP original destination: ", payload.Target)
		} else {
			errors.LogInfo(context.Background(), "failed to read UDP original destination")
		}
	}

	select {
	case c <- payload:
	default:
		buffer.Release()
		payload.Payload = nil
	}
}

// Addr implements net.Listener.
func (h *Hub) Addr() net.Addr {
	return h.conn.LocalAddr()
}

func (h *Hub) Receive() <-chan *udp.Packet {
	return h.cache
}
