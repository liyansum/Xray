package udp

import (
	"io"
	"sync"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"golang.org/x/net/ipv4"
)

const MaxBatchSize = 16

type batchPacketConn interface {
	WriteBatch([]ipv4.Message, int) (int, error)
}

type batchReceiver interface {
	Read([]BatchReadMessage, bool) (int, error)
}

type batchPendingChecker interface {
	HasPending() bool
}

// BatchReadMessage describes one datagram receive slot. Buffer must be empty;
// a successful read commits only the bytes initialized by the kernel.
type BatchReadMessage struct {
	Buffer *buf.Buffer
	OOB    []byte
	Addr   net.Addr
	N      int
	NN     int
	Flags  int
	addrIP [16]byte
	addr   net.UDPAddr
}

// BatchWriteMessage describes one datagram to send.
type BatchWriteMessage struct {
	Payload []byte
	Addr    net.Addr
	N       int
}

// BatchConn provides allocation-free scratch space around recvmmsg/sendmmsg.
// Read and Write have separate locks so a UDP socket can receive and send at
// the same time.
type BatchConn struct {
	conn     batchPacketConn
	receiver batchReceiver
	pending  batchPendingChecker

	writeMu       sync.Mutex
	writeMessages [MaxBatchSize]ipv4.Message
	writeBuffers  [MaxBatchSize][1][]byte
}

// HasPending reports whether at least one datagram is already queued by the
// kernel. It is used to avoid allocating batch receive slots for request/reply
// traffic that happens to have a high packet rate but no receive backlog.
func (c *BatchConn) HasPending() bool {
	return c != nil && c.pending != nil && c.pending.HasPending()
}

func (c *BatchConn) Read(messages []BatchReadMessage, nonblocking bool) (int, error) {
	if c == nil || c.receiver == nil {
		return 0, errors.New("UDP batch receive is unavailable")
	}
	if len(messages) == 0 {
		return 0, nil
	}
	if len(messages) > MaxBatchSize {
		return 0, errors.New("UDP receive batch is too large: ", len(messages))
	}

	for i := range messages {
		if messages[i].Buffer == nil || !messages[i].Buffer.IsEmpty() {
			return 0, errors.New("UDP batch receive requires empty buffers")
		}
	}

	n, err := c.receiver.Read(messages, nonblocking)
	if n < 0 && err != nil {
		n = 0
	}
	if n < 0 || n > len(messages) {
		return 0, errors.New("invalid UDP receive batch size: ", n)
	}
	for i := 0; i < n; i++ {
		if messages[i].N < 0 || int32(messages[i].N) > messages[i].Buffer.Available() {
			return 0, errors.New("invalid UDP datagram size: ", messages[i].N)
		}
		if messages[i].NN < 0 || messages[i].NN > len(messages[i].OOB) {
			return 0, errors.New("invalid UDP control message size: ", messages[i].NN)
		}
	}
	for i := 0; i < n; i++ {
		messages[i].Buffer.Commit(int32(messages[i].N))
	}
	return n, err
}

func (c *BatchConn) Write(messages []BatchWriteMessage) (int, error) {
	if c == nil || c.conn == nil {
		return 0, errors.New("UDP batch send is unavailable")
	}
	if len(messages) == 0 {
		return 0, nil
	}
	if len(messages) > MaxBatchSize {
		return 0, errors.New("UDP send batch is too large: ", len(messages))
	}

	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	ms := c.writeMessages[:len(messages)]
	defer func() {
		for i := range ms {
			c.writeBuffers[i][0] = nil
			ms[i] = ipv4.Message{Buffers: c.writeBuffers[i][:]}
		}
	}()

	for i := range messages {
		if len(messages[i].Payload) == 0 {
			return 0, errors.New("UDP batch send does not accept empty payloads")
		}
		c.writeBuffers[i][0] = messages[i].Payload
		ms[i].Buffers = c.writeBuffers[i][:]
		ms[i].Addr = messages[i].Addr
	}

	n, err := c.conn.WriteBatch(ms, 0)
	if n < 0 && err != nil {
		n = 0
	}
	if n < 0 || n > len(messages) {
		return 0, errors.New("invalid UDP send batch size: ", n)
	}
	for i := 0; i < n; i++ {
		messages[i].N = ms[i].N
		if messages[i].N == 0 {
			// Datagram writes are atomic. Some implementations don't populate N,
			// so use the payload length for a successfully sent message.
			messages[i].N = len(messages[i].Payload)
		}
	}
	if n == 0 && err == nil {
		return 0, io.ErrNoProgress
	}
	return n, err
}
