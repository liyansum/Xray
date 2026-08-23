package mydispatcher

import (
	"bytes"
	"context"
	"testing"

	"github.com/liyansum/Xray/api"
	commonLimiter "github.com/liyansum/Xray/common/limiter"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/transport"
)

type dispatchLinkTestPolicy struct{}

func (dispatchLinkTestPolicy) Type() interface{}              { return policy.ManagerType() }
func (dispatchLinkTestPolicy) Start() error                   { return nil }
func (dispatchLinkTestPolicy) Close() error                   { return nil }
func (dispatchLinkTestPolicy) ForLevel(uint32) policy.Session { return policy.SessionDefault() }
func (dispatchLinkTestPolicy) ForSystem() policy.System       { return policy.System{} }

func newDispatchLinkTestDispatcher(t *testing.T, users []api.UserInfo) *DefaultDispatcher {
	t.Helper()
	limiter := commonLimiter.New()
	if err := limiter.AddInboundLimiter("node", 0, &users, nil); err != nil {
		t.Fatal(err)
	}
	return &DefaultDispatcher{
		policy:  dispatchLinkTestPolicy{},
		stats:   stats.NoopManager{},
		Limiter: limiter,
	}
}

func dispatchLinkTestContext(protocolName, email, ip string) context.Context {
	inbound := &session.Inbound{
		Tag:    "node",
		Name:   protocolName,
		Source: net.TCPDestination(net.ParseAddress(ip), 12345),
		User:   &protocol.MemoryUser{Email: email},
	}
	return session.ContextWithInbound(context.Background(), inbound)
}

func newDispatchLinkTestLink() *transport.Link {
	return &transport.Link{
		Reader: buf.NewReader(bytes.NewReader(nil)),
		Writer: buf.Discard,
	}
}

func admitProtocolConnection(dispatcher *DefaultDispatcher, protocolName, email, ip string) error {
	ctx := dispatchLinkTestContext(protocolName, email, ip)
	if protocolName == "vless" || protocolName == "vless-vision" {
		_, err := dispatcher.wrapLink(ctx, newDispatchLinkTestLink())
		return err
	}

	inbound, outbound, err := dispatcher.getLink(ctx)
	if inbound != nil {
		common.Interrupt(inbound.Reader)
		_ = common.Close(inbound.Writer)
	}
	if outbound != nil {
		common.Interrupt(outbound.Reader)
		_ = common.Close(outbound.Writer)
	}
	return err
}

func TestDispatchLinkSharesDeviceLimitAcrossProtocols(t *testing.T) {
	const email = "node|same-user@example.com|1"
	dispatcher := newDispatchLinkTestDispatcher(t, []api.UserInfo{{
		UID: 1, Email: "same-user@example.com", DeviceLimit: 2,
	}})

	for _, connection := range []struct {
		protocol string
		ip       string
	}{
		{protocol: "trojan", ip: "192.0.2.1"},
		{protocol: "vless", ip: "192.0.2.2"},
		// Reusing a device through another protocol must not consume a slot.
		{protocol: "anytls", ip: "192.0.2.1"},
	} {
		if err := admitProtocolConnection(dispatcher, connection.protocol, email, connection.ip); err != nil {
			t.Fatalf("%s from %s was rejected: %v", connection.protocol, connection.ip, err)
		}
	}

	if err := admitProtocolConnection(dispatcher, "vless-vision", email, "192.0.2.3"); err == nil {
		t.Fatal("a third device connected through VLESS Vision")
	}
}

func TestDispatchLinkSeparatesUsers(t *testing.T) {
	const firstEmail = "node|first@example.com|1"
	const secondEmail = "node|second@example.com|2"
	dispatcher := newDispatchLinkTestDispatcher(t, []api.UserInfo{
		{UID: 1, Email: "first@example.com", DeviceLimit: 1},
		{UID: 2, Email: "second@example.com", DeviceLimit: 1},
	})

	if err := admitProtocolConnection(dispatcher, "trojan", firstEmail, "192.0.2.1"); err != nil {
		t.Fatal(err)
	}
	if err := admitProtocolConnection(dispatcher, "vless", secondEmail, "192.0.2.2"); err != nil {
		t.Fatalf("second user's independent slot was rejected: %v", err)
	}
	if err := admitProtocolConnection(dispatcher, "anytls", firstEmail, "192.0.2.3"); err == nil {
		t.Fatal("first user exceeded its own device limit")
	}
	if err := admitProtocolConnection(dispatcher, "vless-vision", secondEmail, "192.0.2.4"); err == nil {
		t.Fatal("second user exceeded its own device limit")
	}
}

func TestDispatchLinkAppliesSharedRateLimitWithoutExtraPipe(t *testing.T) {
	const email = "node|limited@example.com|1"
	dispatcher := newDispatchLinkTestDispatcher(t, []api.UserInfo{{
		UID: 1, Email: "limited@example.com", SpeedLimit: 1024,
	}})

	link, err := dispatcher.wrapLink(dispatchLinkTestContext("vless-vision", email, "192.0.2.1"), newDispatchLinkTestLink())
	if err != nil {
		t.Fatal(err)
	}
	timeoutReader, ok := link.Reader.(*buf.TimeoutWrapperReader)
	if !ok {
		t.Fatalf("unexpected reader wrapper: %T", link.Reader)
	}
	if _, ok := timeoutReader.Reader.(*commonLimiter.Reader); !ok {
		t.Fatalf("VLESS uplink has no rate reader: %T", timeoutReader.Reader)
	}
	if _, ok := link.Writer.(*commonLimiter.Writer); !ok {
		t.Fatalf("VLESS downlink has no rate writer: %T", link.Writer)
	}
}
