package controller

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/liyansum/Xray/api"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/proxy"
)

func cloneUserList(users *[]api.UserInfo) *[]api.UserInfo {
	copy := append([]api.UserInfo(nil), (*users)...)
	return &copy
}

func sameUser(a, b api.UserInfo) bool {
	a.SpeedLimit, b.SpeedLimit = 0, 0
	return a == b
}

func (c *Controller) userManager() (proxy.UserManager, error) {
	handler, err := c.ibm.GetHandler(context.Background(), c.Tag)
	if err != nil {
		return nil, err
	}
	inbound, ok := handler.(proxy.GetInbound)
	if !ok {
		return nil, fmt.Errorf("handler %s has not implemented proxy.GetInbound", c.Tag)
	}
	manager, ok := inbound.GetInbound().(proxy.UserManager)
	if !ok {
		return nil, fmt.Errorf("handler %s has not implemented proxy.UserManager", c.Tag)
	}
	return manager, nil
}

// Validate the whole generation before changing live users. A builder that
// skipped an invalid account must not silently turn that into a committed list.
func (c *Controller) prepareUsers(users *[]api.UserInfo, node *api.NodeInfo) ([]*protocol.MemoryUser, error) {
	if users == nil {
		return nil, errors.New("nil user snapshot")
	}
	var built []*protocol.User
	switch node.NodeType {
	case "Trojan":
		built = c.buildTrojanUser(users)
	case "Shadowsocks":
		built = c.buildSSUser(users, node.CypherMethod)
	default:
		return nil, fmt.Errorf("unsupported node type: %s", node.NodeType)
	}
	if len(built) != len(*users) {
		return nil, errors.New("user snapshot contains invalid accounts")
	}
	memory := make([]*protocol.MemoryUser, len(built))
	seen := make(map[string]bool, len(built))
	for i, user := range built {
		key := strings.ToLower(user.Email)
		if seen[key] {
			return nil, fmt.Errorf("duplicate user identity: %s", user.Email)
		}
		seen[key] = true
		var err error
		memory[i], err = user.ToMemoryUser()
		if err != nil {
			return nil, err
		}
	}
	return memory, nil
}

// appliedUsers tracks individual successful mutations, including changes from
// a failed generation. This makes retries and a newer superseding generation
// idempotent without replacing unchanged users (and their Vision/XUDP identity).
func (c *Controller) applyUserSnapshot(users *[]api.UserInfo, node *api.NodeInfo) error {
	memory, err := c.prepareUsers(users, node)
	if err != nil {
		return err
	}
	manager, err := c.userManager()
	if err != nil {
		return err
	}
	if c.appliedUsers == nil {
		c.appliedUsers = make(map[string]api.UserInfo)
		if c.userList != nil {
			for _, user := range *c.userList {
				c.appliedUsers[c.buildUserTag(&user)] = user
			}
		}
	}
	desired := make(map[string]api.UserInfo, len(*users))
	for _, user := range *users {
		desired[c.buildUserTag(&user)] = user
	}
	ctx := context.Background()
	if c.removingUsers == nil {
		c.removingUsers = make(map[string]bool)
	}
	for email, previous := range c.appliedUsers {
		if next, keep := desired[email]; keep && sameUser(previous, next) && !c.removingUsers[email] {
			continue
		}
		if manager.GetUser(ctx, email) != nil {
			if err := manager.RemoveUser(ctx, email); err != nil {
				return err
			}
		}
		c.removingUsers[email] = true
		if err := c.unregisterUserCounters(email); err != nil {
			return err
		}
		if err := c.RemoveInboundLimiterUsers(c.Tag, []string{email}); err != nil {
			return err
		}
		delete(c.appliedUsers, email)
		delete(c.removingUsers, email)
	}
	for i, user := range memory {
		if _, exists := c.appliedUsers[user.Email]; exists {
			continue
		}
		if err := manager.AddUser(ctx, user); err != nil {
			return err
		}
		c.appliedUsers[user.Email] = (*users)[i]
	}
	return c.UpdateInboundLimiter(c.Tag, users)
}

func (c *Controller) syncPendingSnapshots() error {
	node, users := c.pendingNode, c.pendingUsers
	if node == nil {
		node = c.nodeInfo
	}
	if users == nil {
		users = c.userList
	}
	if !sameNodeConfig(c.runtimeNode, node) {
		if _, err := c.prepareUsers(users, node); err != nil {
			return err
		}
		// An incomplete rebuild must be retried even if the panel reverts to the
		// previous configuration. Committed nodeInfo is never advanced early.
		c.runtimeNode = nil
		for _, remove := range []func(string) error{c.removeInbound, c.removeOutbound} {
			if err := remove(c.Tag); err != nil && !errors.Is(err, common.ErrNoClue) {
				return err
			}
		}
		c.dispatcher.RuleManager.RemoveRule(c.Tag)
		if c.appliedUsers == nil && c.userList != nil {
			c.appliedUsers = make(map[string]api.UserInfo)
			for _, user := range *c.userList {
				c.appliedUsers[c.buildUserTag(&user)] = user
			}
		}
		for email := range c.appliedUsers {
			if err := c.unregisterUserCounters(email); err != nil {
				return err
			}
		}
		if err := c.DeleteInboundLimiter(c.Tag); err != nil {
			return err
		}
		c.appliedUsers = make(map[string]api.UserInfo)
		c.removingUsers = nil
		c.Tag = c.nodeTag(node)
		if err := c.addNewTag(node); err != nil {
			return err
		}
		if err := c.AddInboundLimiter(c.Tag, node.SpeedLimit, users, c.config.GlobalDeviceLimitConfig); err != nil {
			return err
		}
		c.runtimeNode = node
	}
	if err := c.applyUserSnapshot(users, node); err != nil {
		return err
	}
	c.nodeInfo, c.userList = node, cloneUserList(users)
	c.pendingNode, c.pendingUsers = nil, nil
	return nil
}
