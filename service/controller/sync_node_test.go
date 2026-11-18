package controller

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/liyansum/Xray/api"
	"github.com/liyansum/Xray/app/mydispatcher"
	_ "github.com/liyansum/Xray/cmd/distro/all"
	"github.com/xtls/xray-core/app/proxyman"
	corestats "github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/inbound"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/features/stats"
)

type syncFailInbound struct {
	inbound.Manager
	fail bool
}

func (m *syncFailInbound) AddHandler(ctx context.Context, handler inbound.Handler) error {
	if m.fail {
		m.fail = false
		return errors.New("injected inbound creation failure")
	}
	return m.Manager.AddHandler(ctx, handler)
}

func TestUserSyncRetriesNodeRebuildAfterNotModified(t *testing.T) {
	for _, revert := range []bool{false, true} {
		t.Run(fmt.Sprint(revert), func(t *testing.T) {
			server, err := core.New(&core.Config{App: []*serial.TypedMessage{
				serial.ToTypedMessage(new(mydispatcher.Config)), serial.ToTypedMessage(new(proxyman.InboundConfig)),
				serial.ToTypedMessage(new(proxyman.OutboundConfig)), serial.ToTypedMessage(new(corestats.Config)),
			}})
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			old := []api.UserInfo{{UID: 1, Email: "old", UUID: "550e8400-e29b-41d4-a716-446655440000"}}
			c, _, a := newSyncTestController(t, old)
			c.server = server
			manager := &syncFailInbound{Manager: server.GetFeature(inbound.ManagerType()).(inbound.Manager)}
			c.ibm, c.obm = manager, server.GetFeature(outbound.ManagerType()).(outbound.Manager)
			c.dispatcher = server.GetFeature(routing.DispatcherType()).(*mydispatcher.DefaultDispatcher)
			c.stm = server.GetFeature(stats.ManagerType()).(stats.Manager)
			c.config.ListenIP = "127.0.0.1"
			c.config.SendIP = "0.0.0.0"
			c.nodeInfo.TransportProtocol = "tcp"
			if err := c.addNewTag(c.nodeInfo); err != nil {
				t.Fatal(err)
			}
			if err := c.AddInboundLimiter(c.Tag, 0, &old, nil); err != nil {
				t.Fatal(err)
			}
			c.appliedUsers = make(map[string]api.UserInfo)
			if err := c.applyUserSnapshot(&old, c.nodeInfo); err != nil {
				t.Fatal(err)
			}
			original := c.nodeInfo
			next := *original
			next.Port = 8443
			a.node = &next
			manager.fail = true
			pollSync(t, c)
			if c.nodeInfo != original || c.pendingNode == nil || c.runtimeNode != nil {
				t.Fatal("failed rebuild advanced or lost node snapshot")
			}
			if revert {
				a.node = original
			}
			pollSync(t, c)
			expected := &next
			if revert {
				expected = original
			}
			if c.nodeInfo != expected || c.runtimeNode == nil || c.pendingNode != nil {
				t.Fatal("pending/reverted node not retried")
			}
			users, err := c.userManager()
			if err != nil || users.GetUser(context.Background(), c.buildUserTag(&old[0])) == nil {
				t.Fatalf("rebuilt listener lost users: %v", err)
			}
		})
	}
}
