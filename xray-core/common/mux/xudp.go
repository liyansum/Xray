package mux

import (
	"context"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport/pipe"
)

func forgetXUDP(x *XUDP) {
	XUDPManager.Lock()
	if XUDPManager.Map[x.Key] == x {
		delete(XUDPManager.Map, x.Key)
	}
	old := x.Mux
	XUDPManager.Unlock()
	if old != nil {
		common.Interrupt(old.input)
		_ = common.Close(old.output)
	}
}

func (w *ServerWorker) handleXUDP(ctx context.Context, meta *FrameMetadata, reader *buf.BufferedReader) error {
	mb, err := NewPacketReader(reader, &meta.Target).ReadMultiBuffer()
	if err != nil {
		return err
	}
	key := xudpKey(ctx, meta.GlobalID)
	XUDPManager.Lock()
	x := XUDPManager.Map[key]
	if x != nil && x.Status == Initializing {
		XUDPManager.Unlock()
		buf.ReleaseMulti(mb)
		// Keep unrelated sessions on this Mux alive. The next Keep for this
		// unregistered session receives End, matching the original retry path.
		return nil
	}
	if x == nil {
		x = &XUDP{Key: key, GlobalID: meta.GlobalID}
		XUDPManager.Map[key] = x
	}
	x.Status = Initializing
	previous := x.Mux
	XUDPManager.Unlock()
	// Initializing grants this operation exclusive ownership. Never hold the
	// global cache lock while joining a reader, dispatching, or writing packets.
	if previous != nil {
		_ = previous.Close(false)
		if previous.readerDone != nil {
			timer := time.NewTimer(5 * time.Second)
			select {
			case <-previous.readerDone:
				timer.Stop()
			case <-ctx.Done():
				timer.Stop()
				buf.ReleaseMulti(mb)
				forgetXUDP(x)
				return ctx.Err()
			case <-timer.C:
				buf.ReleaseMulti(mb)
				forgetXUDP(x)
				return errors.New("XUDP response handoff timed out")
			}
		}
		previous.input.(*pipe.Reader).Recover()
		backup := buf.New()
		_, _ = backup.Write(mb[0].Bytes())
		backup.UDP = mb[0].UDP
		if err := previous.output.WriteMultiBuffer(mb); err != nil {
			common.Interrupt(previous.input)
			_ = common.Close(previous.output)
			mb = buf.MultiBuffer{backup}
			previous = nil
		} else {
			backup.Release()
			mb = nil
		}
	}
	if previous == nil {
		ctx = session.ContextWithTimeoutOnly(ctx, true)
		link, err := w.dispatcher.Dispatch(ctx, meta.Target)
		if err != nil {
			buf.ReleaseMulti(mb)
			forgetXUDP(x)
			return errors.New("failed to dispatch XUDP request").Base(err)
		}
		if err := link.Writer.WriteMultiBuffer(mb); err != nil {
			common.Interrupt(link.Reader)
			_ = common.Close(link.Writer)
			forgetXUDP(x)
			return err
		}
		previous = &Session{input: link.Reader, output: link.Writer}
	}
	next := &Session{
		input: previous.input, output: previous.output, parent: w.sessionManager,
		ID: meta.SessionID, transferType: protocol.TransferTypePacket,
		XUDP: x, readerDone: make(chan struct{}),
	}
	if !w.sessionManager.Add(next) {
		common.Interrupt(next.input)
		_ = common.Close(next.output)
		forgetXUDP(x)
		return errors.New("failed to add XUDP session")
	}
	XUDPManager.Lock()
	x.Mux = next
	// Close may already have removed next while we were adding it. The parent
	// lock below serializes publication with Session.Close without lock inversion.
	XUDPManager.Unlock()
	w.sessionManager.Lock()
	XUDPManager.Lock()
	if next.closed {
		x.Status = Expiring
		x.Expire = time.Now().Add(time.Minute)
	} else {
		x.Status = Active
	}
	XUDPManager.Unlock()
	w.sessionManager.Unlock()
	go handle(ctx, next, w.link.Writer)
	return nil
}
