package controller

import (
	"context"
	"fmt"

	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/inbound"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/features/stats"

	"github.com/liyansum/Xray/api"
	"github.com/liyansum/Xray/common/limiter"
)

func (c *Controller) removeInbound(tag string) error {
	err := c.ibm.RemoveHandler(context.Background(), tag)
	return err
}

func (c *Controller) removeOutbound(tag string) error {
	err := c.obm.RemoveHandler(context.Background(), tag)
	return err
}

func (c *Controller) addInbound(config *core.InboundHandlerConfig) error {
	rawHandler, err := core.CreateObject(c.server, config)
	if err != nil {
		return err
	}
	handler, ok := rawHandler.(inbound.Handler)
	if !ok {
		return fmt.Errorf("created object %T is not an inbound handler", rawHandler)
	}
	if err := c.ibm.AddHandler(context.Background(), handler); err != nil {
		return err
	}
	return nil
}

func (c *Controller) addOutbound(config *core.OutboundHandlerConfig) error {
	rawHandler, err := core.CreateObject(c.server, config)
	if err != nil {
		return err
	}
	handler, ok := rawHandler.(outbound.Handler)
	if !ok {
		return fmt.Errorf("created object %T is not an outbound handler", rawHandler)
	}
	if err := c.obm.AddHandler(context.Background(), handler); err != nil {
		return err
	}
	return nil
}

func (c *Controller) unregisterUserCounters(email string) error {
	for _, name := range []string{
		"user>>>" + email + ">>>traffic>>>uplink",
		"user>>>" + email + ">>>traffic>>>downlink",
	} {
		if c.stm.GetCounter(name) == nil {
			continue
		}
		if err := c.stm.UnregisterCounter(name); err != nil {
			return err
		}
	}
	return nil
}

func (c *Controller) getTraffic(email string) (up int64, down int64, upCounter stats.Counter, downCounter stats.Counter) {
	upName := "user>>>" + email + ">>>traffic>>>uplink"
	downName := "user>>>" + email + ">>>traffic>>>downlink"
	upCounter = c.stm.GetCounter(upName)
	downCounter = c.stm.GetCounter(downName)
	up, upCounter = snapshotTrafficCounter(upCounter)
	down, downCounter = snapshotTrafficCounter(downCounter)
	return up, down, upCounter, downCounter
}

func snapshotTrafficCounter(counter stats.Counter) (int64, stats.Counter) {
	if counter == nil {
		return 0, nil
	}
	value := counter.Set(0)
	if value == 0 {
		return 0, nil
	}
	return value, counter
}

type trafficCounterSnapshot struct {
	counter stats.Counter
	value   int64
}

func restoreTraffic(snapshots []trafficCounterSnapshot) {
	for _, snapshot := range snapshots {
		snapshot.counter.Add(snapshot.value)
	}
}

func (c *Controller) AddInboundLimiter(tag string, nodeSpeedLimit uint64, userList *[]api.UserInfo, globalDeviceLimitConfig *limiter.GlobalDeviceLimitConfig) error {
	err := c.dispatcher.Limiter.AddInboundLimiter(tag, nodeSpeedLimit, userList, globalDeviceLimitConfig)
	return err
}

func (c *Controller) UpdateInboundLimiter(tag string, updatedUserList *[]api.UserInfo) error {
	err := c.dispatcher.Limiter.UpdateInboundLimiter(tag, updatedUserList)
	return err
}

func (c *Controller) RemoveInboundLimiterUsers(tag string, emails []string) error {
	return c.dispatcher.Limiter.RemoveInboundUsers(tag, emails)
}

func (c *Controller) DeleteInboundLimiter(tag string) error {
	err := c.dispatcher.Limiter.DeleteInboundLimiter(tag)
	return err
}

func (c *Controller) GetOnlineDevice(tag string) (*[]api.OnlineUser, error) {
	return c.dispatcher.Limiter.GetOnlineDevice(tag)
}

func (c *Controller) UpdateRule(tag string, newRuleList []api.DetectRule) error {
	err := c.dispatcher.RuleManager.UpdateRule(tag, newRuleList)
	return err
}

func (c *Controller) GetDetectResult(tag string) (*[]api.DetectResult, error) {
	return c.dispatcher.RuleManager.GetDetectResult(tag)
}
