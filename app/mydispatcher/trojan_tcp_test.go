package mydispatcher

import (
	"bytes"
	"context"
	"fmt"
	"testing"

	"github.com/liyansum/Xray/api"
	"github.com/liyansum/Xray/common/rule"
	corestats "github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
)

type trojanTestRouter struct {
	routing.Router
	domain, user string
}

func (r *trojanTestRouter) PickRoute(ctx routing.Context) (routing.Route, error) {
	if ctx.GetTargetDomain() != r.domain || ctx.GetUser() != r.user {
		return nil, fmt.Errorf("unexpected route context: domain %s, user %s", ctx.GetTargetDomain(), ctx.GetUser())
	}
	return trojanTestRoute{Context: ctx}, nil
}

type trojanTestRoute struct{ routing.Context }

func (trojanTestRoute) GetOutboundGroupTags() []string { return nil }
func (trojanTestRoute) GetOutboundTag() string         { return "routed" }
func (trojanTestRoute) GetRuleTag() string             { return "test" }

type trojanTestOutbound struct {
	outbound.Handler
	run func(context.Context, *transport.Link)
}

func (h *trojanTestOutbound) Tag() string                                        { return "routed" }
func (h *trojanTestOutbound) Dispatch(ctx context.Context, link *transport.Link) { h.run(ctx, link) }

type trojanTestOutbounds struct {
	outbound.Manager
	handler *trojanTestOutbound
}

func (m *trojanTestOutbounds) GetHandler(tag string) outbound.Handler {
	if tag == "routed" {
		return m.handler
	}
	return nil
}
func (*trojanTestOutbounds) GetDefaultHandler() outbound.Handler {
	panic("sniffed routing was bypassed")
}

func TestTrojanTCPDirectLinkRetainsSniffingRoutingAndStats(t *testing.T) {
	const email = "node|trojan@example.com|1"
	d := newDispatchLinkTestDispatcher(t, []api.UserInfo{{UID: 1, Email: "trojan@example.com", DeviceLimit: 1}})
	d.RuleManager = rule.New()
	manager, err := corestats.NewManager(context.Background(), new(corestats.Config))
	if err != nil {
		t.Fatal(err)
	}
	d.policy, d.stats = visionStatsPolicy{}, manager
	d.router = &trojanTestRouter{domain: "example.com", user: email}
	payload := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	var response bytes.Buffer
	d.ohm = &trojanTestOutbounds{handler: &trojanTestOutbound{run: func(ctx context.Context, link *transport.Link) {
		ob := session.OutboundsFromContext(ctx)[0]
		if ob.Target.Address.String() != "192.0.2.10" || ob.RouteTarget.Address.String() != "example.com" {
			t.Error("route-only sniffing changed dial target or lost sniffed domain")
		}
		var got bytes.Buffer
		if err := buf.Copy(link.Reader, buf.NewWriter(&got)); err != nil {
			t.Error(err)
		}
		if !bytes.Equal(got.Bytes(), payload) {
			t.Error("sniffing lost/duplicated application bytes")
		}
		if err := link.Writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("response"))}); err != nil {
			t.Error(err)
		}
	}}}
	ctx := dispatchLinkTestContext("trojan", email, "192.0.2.1")
	ctx = context.WithValue(ctx, core.XrayKey(1), new(core.Instance))
	ctx = session.ContextWithContent(ctx, &session.Content{SniffingRequest: session.SniffingRequest{Enabled: true, OverrideDestinationForProtocol: []string{"http"}, RouteOnly: true}})
	if err := d.DispatchLink(ctx, net.TCPDestination(net.ParseAddress("192.0.2.10"), 80), &transport.Link{Reader: buf.NewReader(bytes.NewReader(payload)), Writer: buf.NewWriter(&response)}); err != nil {
		t.Fatal(err)
	}
	if response.String() != "response" {
		t.Fatal("response not forwarded")
	}
	for direction, expected := range map[string]int64{"uplink": int64(len(payload)), "downlink": 8} {
		counter := manager.GetCounter("user>>>" + email + ">>>traffic>>>" + direction)
		if counter == nil || counter.Value() != expected {
			t.Fatalf("wrong %s traffic counter: %v", direction, counter)
		}
	}
}
