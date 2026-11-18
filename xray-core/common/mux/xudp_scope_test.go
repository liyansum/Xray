package mux

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

type scopePacket struct {
	user *protocol.MemoryUser
	data string
}
type scopeDispatcher struct {
	mu        sync.Mutex
	calls     int
	packets   chan scopePacket
	resources []any
	wg        sync.WaitGroup
}

func (*scopeDispatcher) Type() interface{} { return routing.DispatcherType() }
func (*scopeDispatcher) Start() error      { return nil }
func (*scopeDispatcher) Close() error      { return nil }
func (*scopeDispatcher) DispatchLink(context.Context, net.Destination, *transport.Link) error {
	return fmt.Errorf("unexpected DispatchLink")
}
func (d *scopeDispatcher) Dispatch(ctx context.Context, _ net.Destination) (*transport.Link, error) {
	user := session.InboundFromContext(ctx).User
	ir, iw := pipe.New(pipe.WithoutSizeLimit())
	or, ow := pipe.New(pipe.WithoutSizeLimit())
	d.mu.Lock()
	d.calls++
	d.resources = append(d.resources, ir, iw, or, ow)
	d.mu.Unlock()
	d.wg.Add(1)
	go func() {
		defer d.wg.Done()
		for {
			mb, err := ir.ReadMultiBuffer()
			if !mb.IsEmpty() {
				data := make([]byte, mb.Len())
				mb.Copy(data)
				buf.ReleaseMulti(mb)
				d.packets <- scopePacket{user, string(data)}
			}
			if err != nil {
				return
			}
		}
	}()
	return &transport.Link{Reader: or, Writer: iw}, nil
}

func TestXUDPAssociationsAreScoped(t *testing.T) {
	for _, scenario := range []string{"same-user-reconnect", "different-user", "different-node", "different-source", "replaced-user"} {
		t.Run(scenario, func(t *testing.T) {
			d := &scopeDispatcher{packets: make(chan scopePacket, 8)}
			userA := &protocol.MemoryUser{Email: "user-A"}
			userB := userA
			tagA, tagB := "node-A", "node-A"
			ipA, ipB := "192.0.2.1", "192.0.2.1"
			wantCalls := 2
			switch scenario {
			case "same-user-reconnect":
				wantCalls = 1
			case "different-user":
				userB = &protocol.MemoryUser{Email: "user-B"}
			case "different-node":
				tagB = "node-B"
			case "different-source":
				ipB = "192.0.2.2"
			case "replaced-user":
				userB = &protocol.MemoryUser{Email: "user-A"}
			}
			id := [8]byte{0x97, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77}
			var workers []*ServerWorker
			t.Cleanup(func() {
				for _, w := range workers {
					_ = w.sessionManager.Close()
				}
				var pumps []<-chan struct{}
				XUDPManager.Lock()
				for key, x := range XUDPManager.Map {
					if key.GlobalID == id {
						x.Interrupt()
						if x.Mux.readerDone != nil {
							pumps = append(pumps, x.Mux.readerDone)
						}
						delete(XUDPManager.Map, key)
					}
				}
				XUDPManager.Unlock()
				for _, ch := range pumps {
					select {
					case <-ch:
					case <-time.After(time.Second):
						t.Error("response pump did not exit")
					}
				}
				for _, r := range d.resources {
					common.Interrupt(r)
					_ = common.Close(r)
				}
				d.wg.Wait()
			})
			send := func(user *protocol.MemoryUser, tag, ip, payload string) {
				ctx := session.ContextWithInbound(context.Background(), &session.Inbound{Tag: tag, User: user, Source: net.TCPDestination(net.ParseAddress(ip), 12345)})
				ctx = session.ContextWithAllowedNetwork(ctx, net.Network_UDP)
				w := &ServerWorker{dispatcher: d, link: &transport.Link{Writer: buf.Discard}, sessionManager: NewSessionManager()}
				workers = append(workers, w)
				var body bytes.Buffer
				_ = binary.Write(&body, binary.BigEndian, uint16(len(payload)))
				body.WriteString(payload)
				meta := &FrameMetadata{GlobalID: id, SessionID: 1, Target: net.UDPDestination(net.DomainAddress("quic.example"), 443), Option: OptionData}
				if err := w.handleStatusNew(ctx, meta, &buf.BufferedReader{Reader: buf.NewReader(&body)}); err != nil {
					t.Fatal(err)
				}
				select {
				case got := <-d.packets:
					if got.user != user || got.data != payload {
						t.Fatalf("packet belongs to %p, want %p: %q", got.user, user, got.data)
					}
				case <-time.After(time.Second):
					t.Fatal("packet timeout")
				}
			}
			send(userA, tagA, ipA, "first")
			send(userB, tagB, ipB, "second")
			if d.calls != wantCalls {
				t.Fatalf("dispatches=%d want=%d", d.calls, wantCalls)
			}
		})
	}
}

// A closed previous pump must leave EOF pending until handoff joins it. This
// catches the former Gosched/Recover race that could leave two readers alive.
func TestXUDPCloseStopsResponsePump(t *testing.T) {
	ir, iw := pipe.New(pipe.WithoutSizeLimit())
	defer iw.Close()
	m := NewSessionManager()
	x := &XUDP{Status: Active}
	s := &Session{input: ir, output: buf.Discard, parent: m, ID: 1, XUDP: x, readerDone: make(chan struct{})}
	x.Mux = s
	if !m.Add(s) {
		t.Fatal("add")
	}
	go handle(context.Background(), s, buf.Discard)
	if err := s.Close(false); err != nil {
		t.Fatal(err)
	}
	select {
	case <-s.readerDone:
	case <-time.After(time.Second):
		t.Fatal("response pump survived close")
	}
	if err := ir.Recover(); err != nil {
		t.Fatalf("response pump did not consume its wake-up error: %v", err)
	}
}

func TestXUDPConcurrentAttachKeepsOtherMuxSessions(t *testing.T) {
	id := [8]byte{0x37, 1, 2, 3, 4, 5, 6, 7}
	ctx := session.ContextWithInbound(context.Background(), &session.Inbound{Tag: "node", User: &protocol.MemoryUser{Email: "user"}})
	key := xudpKey(ctx, id)
	XUDPManager.Lock()
	XUDPManager.Map[key] = &XUDP{Key: key, GlobalID: id, Status: Initializing}
	XUDPManager.Unlock()
	defer func() { XUDPManager.Lock(); delete(XUDPManager.Map, key); XUDPManager.Unlock() }()
	w := &ServerWorker{sessionManager: NewSessionManager()}
	reader := &buf.BufferedReader{Reader: buf.NewReader(bytes.NewReader([]byte{0, 1, 'x'}))}
	meta := &FrameMetadata{GlobalID: id, SessionID: 1, Target: net.UDPDestination(net.LocalHostIP, 443), Option: OptionData}
	if err := w.handleStatusNew(ctx, meta, reader); err != nil {
		t.Fatalf("concurrent attach would close the entire Mux: %v", err)
	}
	if w.sessionManager.Size() != 0 {
		t.Fatal("concurrent attach created another reader")
	}
}
