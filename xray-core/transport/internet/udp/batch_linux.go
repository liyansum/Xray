//go:build linux

package udp

import (
	stderrors "errors"
	"os"
	"runtime"
	"sync"
	"syscall"
	"unsafe"

	"github.com/xtls/xray-core/common/net"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
)

type linuxMmsghdr struct {
	Hdr unix.Msghdr
	Len uint32
}

type linuxBatchReceiver struct {
	sync.Mutex
	raw         syscall.RawConn
	checkFunc   func(uintptr) bool
	receiveFunc func(uintptr) bool
	pending     int
	headers     [MaxBatchSize]linuxMmsghdr
	iovecs      [MaxBatchSize]unix.Iovec
	names       [MaxBatchSize]unix.RawSockaddrAny
	count       int
	flags       int
	n           int
	err         error
}

func (c *linuxBatchReceiver) check(fd uintptr) bool {
	c.pending, _ = unix.IoctlGetInt(int(fd), unix.TIOCINQ)
	return true
}

func (c *linuxBatchReceiver) HasPending() bool {
	c.Lock()
	defer c.Unlock()
	c.pending = 0
	if err := c.raw.Read(c.checkFunc); err != nil {
		return false
	}
	return c.pending > 0
}

func (c *linuxBatchReceiver) receive(fd uintptr) bool {
	r0, _, errno := unix.Syscall6(
		unix.SYS_RECVMMSG,
		fd,
		uintptr(unsafe.Pointer(&c.headers[0])),
		uintptr(c.count),
		uintptr(c.flags),
		0,
		0,
	)
	if errno != 0 {
		c.n = 0
		c.err = errno
		return c.flags&unix.MSG_DONTWAIT != 0 || (errno != syscall.EAGAIN && errno != syscall.EWOULDBLOCK)
	}
	c.n = int(r0)
	c.err = nil
	return true
}

func (c *linuxBatchReceiver) Read(messages []BatchReadMessage, nonblocking bool) (int, error) {
	c.Lock()
	defer c.Unlock()

	c.count = len(messages)
	c.flags = unix.MSG_WAITFORONE
	if nonblocking {
		c.flags = unix.MSG_DONTWAIT
	}
	c.n = 0
	c.err = nil
	for i := range messages {
		writable := messages[i].Buffer.WritableBytes()
		c.iovecs[i].Base = &writable[0]
		c.iovecs[i].SetLen(len(writable))
		hdr := &c.headers[i].Hdr
		hdr.Name = (*byte)(unsafe.Pointer(&c.names[i]))
		hdr.Namelen = uint32(unsafe.Sizeof(c.names[i]))
		hdr.Iov = &c.iovecs[i]
		hdr.SetIovlen(1)
		if len(messages[i].OOB) > 0 {
			hdr.Control = &messages[i].OOB[0]
			hdr.SetControllen(len(messages[i].OOB))
		}
	}
	defer func() {
		for i := range messages {
			c.headers[i] = linuxMmsghdr{}
			c.iovecs[i] = unix.Iovec{}
			c.names[i] = unix.RawSockaddrAny{}
		}
		runtime.KeepAlive(messages)
	}()

	if err := c.raw.Read(c.receiveFunc); err != nil {
		return 0, err
	}
	if c.err != nil {
		return 0, os.NewSyscallError("recvmmsg", c.err)
	}
	if c.n < 0 || c.n > len(messages) {
		return c.n, nil
	}
	for i := 0; i < c.n; i++ {
		messages[i].N = int(c.headers[i].Len)
		messages[i].NN = int(c.headers[i].Hdr.Controllen)
		messages[i].Flags = int(c.headers[i].Hdr.Flags)
		if err := c.setAddress(&messages[i], &c.names[i]); err != nil {
			return 0, err
		}
	}
	return c.n, nil
}

func (c *linuxBatchReceiver) setAddress(message *BatchReadMessage, raw *unix.RawSockaddrAny) error {
	message.addr = net.UDPAddr{}
	message.addrIP = [16]byte{}
	switch raw.Addr.Family {
	case unix.AF_INET:
		addr := (*unix.RawSockaddrInet4)(unsafe.Pointer(raw))
		copy(message.addrIP[:4], addr.Addr[:])
		message.addr.IP = message.addrIP[:4]
		message.addr.Port = networkPort(addr.Port)
	case unix.AF_INET6:
		addr := (*unix.RawSockaddrInet6)(unsafe.Pointer(raw))
		copy(message.addrIP[:], addr.Addr[:])
		message.addr.IP = message.addrIP[:]
		message.addr.Port = networkPort(addr.Port)
	default:
		return os.NewSyscallError("recvmmsg", syscall.EAFNOSUPPORT)
	}
	message.Addr = &message.addr
	return nil
}

func networkPort(port uint16) int {
	b := (*[2]byte)(unsafe.Pointer(&port))
	return int(b[0])<<8 | int(b[1])
}

func NewBatchConn(conn net.PacketConn) *BatchConn {
	if conn == nil {
		return nil
	}
	syscallConn, ok := conn.(syscall.Conn)
	if !ok {
		return nil
	}
	if _, ok := conn.(net.Conn); !ok {
		return nil
	}

	var batchConn batchPacketConn
	if addr, ok := conn.LocalAddr().(*net.UDPAddr); ok && addr.IP.To4() == nil {
		batchConn = ipv6.NewPacketConn(conn)
	} else {
		batchConn = ipv4.NewPacketConn(conn)
	}
	rawConn, err := syscallConn.SyscallConn()
	if err != nil {
		return nil
	}
	receiver := &linuxBatchReceiver{raw: rawConn}
	receiver.checkFunc = receiver.check
	receiver.receiveFunc = receiver.receive
	return &BatchConn{conn: batchConn, receiver: receiver, pending: receiver}
}

func IsBatchWouldBlock(err error) bool {
	return stderrors.Is(err, syscall.EAGAIN) || stderrors.Is(err, syscall.EWOULDBLOCK)
}
