package controller

import (
	"context"
	"errors"
	"io"
	"reflect"
	"testing"

	"github.com/liyansum/Xray/api"
	"github.com/liyansum/Xray/app/mydispatcher"
	"github.com/liyansum/Xray/common/limiter"
	"github.com/liyansum/Xray/common/rule"
	log "github.com/sirupsen/logrus"
	corestats "github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/features/inbound"
	"github.com/xtls/xray-core/proxy"
)

type syncTestAPI struct {
	api.API
	users    *[]api.UserInfo
	node     *api.NodeInfo
	reported []api.UserTraffic
}

func (*syncTestAPI) ReportNodeStatus(*api.NodeStatus) error { return nil }
func (a *syncTestAPI) ReportUserTraffic(traffic *[]api.UserTraffic) error {
	a.reported = append(a.reported, (*traffic)...)
	return nil
}

func (a *syncTestAPI) GetNodeInfo() (*api.NodeInfo, error) {
	if a.node == nil {
		return nil, errors.New(api.NodeNotModified)
	}
	node := a.node
	a.node = nil
	return node, nil
}
func (a *syncTestAPI) GetUserList() (*[]api.UserInfo, error) {
	if a.users == nil {
		return nil, errors.New(api.UserNotModified)
	}
	users := a.users
	a.users = nil
	return users, nil
}

type syncTestUsers struct {
	proxy.Inbound
	proxy.UserManager
	users               map[string]*protocol.MemoryUser
	failAdd, failRemove string
	adds                map[string]int
}

func (m *syncTestUsers) AddUser(_ context.Context, user *protocol.MemoryUser) error {
	if user.Email == m.failAdd {
		return errors.New("injected add failure")
	}
	if m.users[user.Email] != nil {
		return errors.New("duplicate add")
	}
	m.users[user.Email] = user
	m.adds[user.Email]++
	return nil
}
func (m *syncTestUsers) RemoveUser(_ context.Context, email string) error {
	if email == m.failRemove {
		return errors.New("injected remove failure")
	}
	if m.users[email] == nil {
		return errors.New("already removed")
	}
	delete(m.users, email)
	return nil
}
func (m *syncTestUsers) GetUser(_ context.Context, email string) *protocol.MemoryUser {
	return m.users[email]
}

type syncTestHandler struct {
	inbound.Handler
	manager *syncTestUsers
}

func (h *syncTestHandler) GetInbound() proxy.Inbound { return h.manager }

type syncTestInbounds struct {
	inbound.Manager
	handler *syncTestHandler
}

func (m *syncTestInbounds) GetHandler(context.Context, string) (inbound.Handler, error) {
	return m.handler, nil
}

func newSyncTestController(t *testing.T, old []api.UserInfo) (*Controller, *syncTestUsers, *syncTestAPI) {
	t.Helper()
	stats, err := corestats.NewManager(context.Background(), new(corestats.Config))
	if err != nil {
		t.Fatal(err)
	}
	logger := log.New()
	logger.SetOutput(io.Discard)
	m := &syncTestUsers{users: make(map[string]*protocol.MemoryUser), adds: make(map[string]int)}
	a := new(syncTestAPI)
	node := &api.NodeInfo{NodeType: "Trojan", Port: 443}
	c := &Controller{Tag: "Trojan_127.0.0.1_443", config: &Config{DisableGetRule: true},
		nodeInfo: node, runtimeNode: node, userList: cloneUserList(&old), apiClient: a,
		ibm: &syncTestInbounds{handler: &syncTestHandler{manager: m}}, stm: stats,
		dispatcher: &mydispatcher.DefaultDispatcher{Limiter: limiter.New(), RuleManager: rule.New()}, logger: log.NewEntry(logger)}
	if err := c.AddInboundLimiter(c.Tag, 0, &old, nil); err != nil {
		t.Fatal(err)
	}
	users, err := c.prepareUsers(&old, node)
	if err != nil {
		t.Fatal(err)
	}
	for _, user := range users {
		if err := m.AddUser(context.Background(), user); err != nil {
			t.Fatal(err)
		}
	}
	return c, m, a
}

func pollSync(t *testing.T, c *Controller) {
	t.Helper()
	if err := c.nodeInfoMonitor(); err != nil {
		t.Fatalf("monitor must continue retrying: %v", err)
	}
}

func TestUserSyncRetriesPartialAddAfterNotModified(t *testing.T) {
	old := []api.UserInfo{{UID: 1, Email: "old", UUID: "old"}}
	c, m, a := newSyncTestController(t, old)
	desired := append(append([]api.UserInfo(nil), old...), api.UserInfo{UID: 2, Email: "first", UUID: "first"}, api.UserInfo{UID: 3, Email: "second", UUID: "second"})
	first, second := c.buildUserTag(&desired[1]), c.buildUserTag(&desired[2])
	m.failAdd = second
	a.users = &desired
	pollSync(t, c)
	if !reflect.DeepEqual(*c.userList, old) || c.pendingUsers == nil || m.users[first] == nil {
		t.Fatal("partial failure advanced snapshot or lost progress")
	}
	identity := m.users[first]
	counter, err := c.stm.GetOrRegisterCounter("user>>>" + first + ">>>traffic>>>uplink")
	if err != nil {
		t.Fatal(err)
	}
	counter.Add(123)
	if err := c.userInfoMonitor(); err != nil {
		t.Fatal(err)
	}
	if len(a.reported) != 1 || a.reported[0].UID != 2 || a.reported[0].Upload != 123 {
		t.Fatal("live partial addition was omitted from traffic reporting")
	}
	m.failAdd = ""
	pollSync(t, c) // API now returns NotModified.
	if !reflect.DeepEqual(*c.userList, desired) || c.pendingUsers != nil {
		t.Fatal("NotModified did not retry pending snapshot")
	}
	if m.users[first] != identity || m.adds[first] != 1 || m.users[second] == nil {
		t.Fatal("retry replaced or duplicated a successful addition")
	}
}

func TestUserSyncRetriesDeletionToEmptySnapshot(t *testing.T) {
	old := []api.UserInfo{{UID: 1, Email: "old", UUID: "old"}}
	c, m, a := newSyncTestController(t, old)
	email := c.buildUserTag(&old[0])
	counter, _ := c.stm.RegisterCounter("user>>>" + email + ">>>traffic>>>uplink")
	counter.Add(123)
	m.failRemove = email
	empty := []api.UserInfo{}
	a.users = &empty
	pollSync(t, c)
	if len(*c.userList) != 1 || counter.Value() != 123 {
		t.Fatal("failed removal committed or discarded counters")
	}
	m.failRemove = ""
	pollSync(t, c)
	if len(*c.userList) != 0 || len(m.users) != 0 || c.pendingUsers != nil {
		t.Fatal("empty pending snapshot not applied")
	}
}

func TestUserSyncSupersedesFailedGeneration(t *testing.T) {
	c, m, a := newSyncTestController(t, nil)
	desired := []api.UserInfo{{UID: 1, Email: "partial", UUID: "partial"}, {UID: 2, Email: "fail", UUID: "fail"}}
	m.failAdd = c.buildUserTag(&desired[1])
	a.users = &desired
	pollSync(t, c)
	if len(m.users) != 1 {
		t.Fatal("expected a partially applied generation")
	}
	replacement := []api.UserInfo{{UID: 3, Email: "replacement", UUID: "replacement"}}
	a.users = &replacement
	pollSync(t, c)
	if !reflect.DeepEqual(*c.userList, replacement) || len(m.users) != 1 || m.users[c.buildUserTag(&replacement[0])] == nil {
		t.Fatal("superseded partial users remain authorized")
	}
}

func TestUserSyncRetriesPolicyFailureAndRevertedDeletion(t *testing.T) {
	old := []api.UserInfo{{UID: 1, Email: "old", UUID: "old", DeviceLimit: 1}}
	c, m, a := newSyncTestController(t, old)
	_ = c.DeleteInboundLimiter(c.Tag)
	empty := []api.UserInfo{}
	a.users = &empty
	pollSync(t, c) // Auth removal succeeds; policy removal fails.
	if len(*c.userList) != 1 || len(m.users) != 0 || c.pendingUsers == nil {
		t.Fatal("policy failure advanced snapshot")
	}
	if err := c.AddInboundLimiter(c.Tag, 0, &old, nil); err != nil {
		t.Fatal(err)
	}
	a.users = &old // Panel reverts while a removal is incomplete.
	pollSync(t, c)
	if len(m.users) != 1 || c.pendingUsers != nil {
		t.Fatal("reverted deletion failed to restore user")
	}
	if c.dispatcher.Limiter.CheckDeviceLimit(c.Tag, c.buildUserTag(&old[0]), "192.0.2.1", true) {
		t.Fatal("first device rejected")
	}
	if !c.dispatcher.Limiter.CheckDeviceLimit(c.Tag, c.buildUserTag(&old[0]), "192.0.2.2", true) {
		t.Fatal("restored device policy was lost")
	}
}

func TestUserSyncKeepsIdentityOnPolicyRetryAndSpeedChange(t *testing.T) {
	old := []api.UserInfo{{UID: 1, Email: "old", UUID: "old", DeviceLimit: 1}}
	c, m, a := newSyncTestController(t, old)
	email := c.buildUserTag(&old[0])
	identity := m.users[email]
	_ = c.DeleteInboundLimiter(c.Tag)
	desired := append([]api.UserInfo(nil), old...)
	desired[0].SpeedLimit = 999
	a.users = &desired
	pollSync(t, c)
	if c.pendingUsers == nil || (*c.userList)[0].SpeedLimit != 0 {
		t.Fatal("failed policy update was committed")
	}
	if err := c.AddInboundLimiter(c.Tag, 0, &old, nil); err != nil {
		t.Fatal(err)
	}
	pollSync(t, c)
	if m.users[email] != identity || (*c.userList)[0].SpeedLimit != 999 {
		t.Fatal("policy retry or speed-only update replaced identity")
	}
	desired[0].UUID = "updated"
	desired[0].DeviceLimit = 2
	a.users = &desired
	pollSync(t, c)
	if m.users[email] == identity || m.adds[email] != 2 {
		t.Fatal("credential/device update was not applied")
	}
}

func TestUserSyncRejectsInvalidGenerationBeforeMutations(t *testing.T) {
	old := []api.UserInfo{{UID: 1, Email: "old", UUID: "old"}}
	c, m, a := newSyncTestController(t, old)
	duplicate := []api.UserInfo{{UID: 2, Email: "same", UUID: "first"}, {UID: 2, Email: "SAME", UUID: "second"}}
	a.users = &duplicate
	pollSync(t, c)
	if len(m.users) != 1 || !reflect.DeepEqual(*c.userList, old) {
		t.Fatal("invalid generation mutated live users")
	}
}
