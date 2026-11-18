//go:build linux || android

package proxy

import (
	"context"
	"errors"
	"net"
	"os"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/features/stats"
)

// spliceCopy keeps payload in the kernel while accounting for each completed
// transfer. Unlike TCPConn.ReadFrom, it also reports progress before EOF and
// leaves the configured inactivity timeout in force.
// handled is false only if it is safe to fall back without losing any bytes.
func spliceCopy(ctx context.Context, src net.Conn, dst *net.TCPConn, readCounter, writeCounter, userCounter stats.Counter, timers ...*signal.ActivityTimer) (handled bool, err error) {
	switch src.(type) {
	case *net.TCPConn, *net.UnixConn:
	default:
		return false, nil
	}
	srcRaw, err := src.(syscall.Conn).SyscallConn()
	if err != nil {
		return false, nil
	}
	dstRaw, err := dst.SyscallConn()
	if err != nil {
		return false, nil
	}
	var pipe [2]int
	if err := unix.Pipe2(pipe[:], unix.O_CLOEXEC|unix.O_NONBLOCK); err != nil {
		return false, nil
	}
	defer unix.Close(pipe[0])
	defer unix.Close(pipe[1])
	// Best effort: kernels or containers may cap the pipe at a smaller size.
	_, _ = unix.FcntlInt(uintptr(pipe[0]), unix.F_SETPIPE_SZ, 1<<20)

	canceled := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		// Only interrupt this direction of each socket. The reverse direction
		// may still be finishing its own copy and accounting.
		_ = src.SetReadDeadline(time.Now())
		_ = dst.SetWriteDeadline(time.Now())
		close(canceled)
	})
	defer func() {
		if !stop() {
			<-canceled
		}
		if ctx.Err() != nil {
			handled, err = true, ctx.Err()
		}
	}()
	progress := func() {
		for _, timer := range timers {
			if timer != nil {
				timer.Update()
			}
		}
	}
	// Reuse callbacks and syscall result storage for the whole connection.
	// Allocating closures per poll operation creates garbage proportional to
	// traffic volume even though splice itself never copies payload to Go.
	var n, written int64
	var spliceErr error
	readPipe := func(fd uintptr) bool {
		for {
			n, spliceErr = unix.Splice(int(fd), nil, pipe[1], nil, 1<<20, unix.SPLICE_F_MOVE|unix.SPLICE_F_NONBLOCK)
			if spliceErr != unix.EINTR {
				return spliceErr != unix.EAGAIN
			}
		}
	}
	writePipe := func(fd uintptr) bool {
		for {
			written, spliceErr = unix.Splice(pipe[0], nil, int(fd), nil, int(n), unix.SPLICE_F_MOVE|unix.SPLICE_F_NONBLOCK)
			if spliceErr != unix.EINTR {
				return spliceErr != unix.EAGAIN
			}
		}
	}
	for {
		n, spliceErr = 0, nil
		pollErr := srcRaw.Read(readPipe)
		if pollErr != nil {
			return true, pollErr
		}
		if spliceErr != nil {
			if !handled && (errors.Is(spliceErr, unix.EINVAL) || errors.Is(spliceErr, unix.ENOSYS) || errors.Is(spliceErr, unix.EOPNOTSUPP) || errors.Is(spliceErr, unix.EPERM)) {
				return false, nil
			}
			return true, os.NewSyscallError("splice", spliceErr)
		}
		handled = true
		if n == 0 {
			return true, nil
		}
		if readCounter != nil {
			readCounter.Add(n)
		}
		progress()
		for n > 0 {
			written, spliceErr = 0, nil
			pollErr = dstRaw.Write(writePipe)
			if written > 0 {
				n -= written
				if writeCounter != nil {
					writeCounter.Add(written)
				}
				if userCounter != nil {
					userCounter.Add(written)
				}
				progress()
			}
			if pollErr != nil {
				return true, pollErr
			}
			if spliceErr != nil {
				return true, os.NewSyscallError("splice", spliceErr)
			}
			if written == 0 {
				return true, os.NewSyscallError("splice", unix.EIO)
			}
		}
	}
}
