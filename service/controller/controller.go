package controller

import (
	"errors"
	"fmt"
	"reflect"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/inbound"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/features/stats"

	"github.com/liyansum/Xray/api"
	"github.com/liyansum/Xray/api/newV2board"
	"github.com/liyansum/Xray/app/mydispatcher"
	"github.com/liyansum/Xray/common/limiter"
	"github.com/liyansum/Xray/common/serverstatus"
)

type Controller struct {
	monitorMu  sync.Mutex
	server     *core.Instance
	config     *Config
	clientInfo api.ClientInfo
	apiClient  api.API
	nodeInfo   *api.NodeInfo
	Tag        string
	userList   *[]api.UserInfo

	// Pending panel generations survive API ETag/NotModified responses. Runtime
	// progress is separate from snapshots committed after a complete sync.
	pendingUsers  *[]api.UserInfo
	pendingNode   *api.NodeInfo
	runtimeNode   *api.NodeInfo
	appliedUsers  map[string]api.UserInfo
	removingUsers map[string]bool
	tasks         []periodicTask
	panelType     string
	ibm           inbound.Manager
	obm           outbound.Manager
	stm           stats.Manager
	dispatcher    *mydispatcher.DefaultDispatcher
	startAt       time.Time
	logger        *log.Entry
}

type periodicTask struct {
	tag string
	*task.Periodic
}

// New return a Controller service with default parameters.
func New(server *core.Instance, api api.API, config *Config, panelType string) *Controller {
	logger := log.NewEntry(log.StandardLogger()).WithFields(log.Fields{
		"Host": api.Describe().APIHost,
		"Type": api.Describe().NodeType,
		"ID":   api.Describe().NodeID,
	})
	controller := &Controller{
		server:     server,
		config:     config,
		apiClient:  api,
		panelType:  panelType,
		ibm:        server.GetFeature(inbound.ManagerType()).(inbound.Manager),
		obm:        server.GetFeature(outbound.ManagerType()).(outbound.Manager),
		stm:        server.GetFeature(stats.ManagerType()).(stats.Manager),
		dispatcher: server.GetFeature(routing.DispatcherType()).(*mydispatcher.DefaultDispatcher),
		startAt:    time.Now(),
		logger:     logger,
	}

	return controller
}

// Start implement the Start() function of the service interface
func (c *Controller) Start() error {
	c.clientInfo = c.apiClient.Describe()
	// First fetch Node Info
	newNodeInfo, err := c.apiClient.GetNodeInfo()
	if err != nil {
		return err
	}
	if newNodeInfo == nil || newNodeInfo.Port == 0 {
		return errors.New("server port must > 0")
	}
	c.nodeInfo = newNodeInfo
	c.Tag = c.buildNodeTag()

	// Add new tag
	err = c.addNewTag(newNodeInfo)
	if err != nil {
		return err
	}
	// Update user
	userInfo, err := c.apiClient.GetUserList()
	if err != nil {
		return err
	}
	if userInfo == nil {
		return errors.New("nil user snapshot")
	}

	// Install device policy before admitting users; commit only after both stages.
	// Add Limiter
	if err := c.AddInboundLimiter(c.Tag, newNodeInfo.SpeedLimit, userInfo, c.config.GlobalDeviceLimitConfig); err != nil {
		return err
	}
	c.appliedUsers = make(map[string]api.UserInfo)
	if err := c.applyUserSnapshot(userInfo, newNodeInfo); err != nil {
		return err
	}
	c.userList = cloneUserList(userInfo)
	c.runtimeNode = newNodeInfo

	// Update alive user list
	if v2b, ok := c.apiClient.(*newV2board.APIClient); ok {
		if v, ok := c.dispatcher.Limiter.InboundInfo.Load(c.Tag); ok {
			inboundinfo := v.(*limiter.InboundInfo)
			inboundinfo.SetAliveList(v2b.AliveMap.Alive)
		}
	}

	// Add Rule Manager
	if !c.config.DisableGetRule {
		if ruleList, err := c.apiClient.GetNodeRule(); err != nil {
			c.logger.Printf("Get rule list filed: %s", err)
		} else if len(*ruleList) > 0 {
			if err := c.UpdateRule(c.Tag, *ruleList); err != nil {
				c.logger.Print(err)
			}
		}
	}

	// Add periodic tasks
	c.tasks = append(c.tasks,
		periodicTask{
			tag: "node monitor",
			Periodic: &task.Periodic{
				Interval: time.Duration(c.config.UpdatePeriodic) * time.Second,
				Execute:  c.nodeInfoMonitor,
			}},
		periodicTask{
			tag: "user monitor",
			Periodic: &task.Periodic{
				Interval: time.Duration(c.config.UpdatePeriodic) * time.Second,
				Execute:  c.userInfoMonitor,
			}},
	)

	// Start periodic tasks
	for i := range c.tasks {
		c.logger.Printf("Start %s periodic task", c.tasks[i].tag)
		periodic := &c.tasks[i]
		go func() {
			if err := periodic.Start(); err != nil {
				c.logger.Printf("%s periodic task stopped: %s", periodic.tag, err)
			}
		}()
	}

	return nil
}

// Close implement the Close() function of the service interface
func (c *Controller) Close() error {
	var closeErr error
	for i := range c.tasks {
		if c.tasks[i].Periodic != nil {
			if err := c.tasks[i].Periodic.Close(); err != nil {
				closeErr = errors.Join(closeErr, fmt.Errorf("%s periodic task close failed: %w", c.tasks[i].tag, err))
			}
		}
	}
	// Periodic.Close prevents the next run but does not wait for an Execute that
	// is already in progress. Wait for it before tearing down shared state.
	c.monitorMu.Lock()
	defer c.monitorMu.Unlock()
	if c.Tag != "" {
		closeErr = errors.Join(closeErr, c.DeleteInboundLimiter(c.Tag))
		c.dispatcher.RuleManager.RemoveRule(c.Tag)
	}
	if c.userList != nil {
		for _, user := range *c.userList {
			closeErr = errors.Join(closeErr, c.unregisterUserCounters(c.buildUserTag(&user)))
		}
	}
	for email := range c.appliedUsers {
		closeErr = errors.Join(closeErr, c.unregisterUserCounters(email))
	}
	return closeErr
}

func (c *Controller) nodeInfoMonitor() (err error) {
	// delay to start
	if time.Since(c.startAt) < time.Duration(c.config.UpdatePeriodic)*time.Second {
		return nil
	}
	c.monitorMu.Lock()
	defer c.monitorMu.Unlock()

	// A fetched generation is not an applied generation. In particular, APIs
	// cache ETags before we have finished updating the authenticator and policy.
	if node, err := c.apiClient.GetNodeInfo(); err == nil {
		if node == nil || node.Port == 0 {
			c.logger.Print("invalid node snapshot: server port must > 0")
			return nil
		}
		c.pendingNode = node
	} else if err.Error() != api.NodeNotModified {
		c.logger.Print(err)
		return nil
	}
	if users, err := c.apiClient.GetUserList(); err == nil {
		if users == nil {
			c.logger.Print("invalid nil user snapshot")
			return nil
		}
		c.pendingUsers = cloneUserList(users)
	} else if err.Error() != api.UserNotModified {
		c.logger.Print(err)
		return nil
	}
	if c.pendingNode != nil || c.pendingUsers != nil {
		if err := c.syncPendingSnapshots(); err != nil {
			// Returning an error stops task.Periodic permanently. Retain pending
			// state and retry on the next poll, including a NotModified response.
			c.logger.Printf("Panel snapshot not applied; will retry: %s", err)
			return nil
		}
	}

	if v2b, ok := c.apiClient.(*newV2board.APIClient); ok {
		if v, ok := c.dispatcher.Limiter.InboundInfo.Load(c.Tag); ok {
			v.(*limiter.InboundInfo).SetAliveList(v2b.AliveMap.Alive)
		}
	}

	// Check Rule
	if !c.config.DisableGetRule {
		if ruleList, err := c.apiClient.GetNodeRule(); err != nil {
			if err.Error() != api.RuleNotModified {
				c.logger.Printf("Get rule list filed: %s", err)
			}
		} else if len(*ruleList) > 0 {
			if err := c.UpdateRule(c.Tag, *ruleList); err != nil {
				c.logger.Print(err)
			}
		}
	}

	return nil
}

func (c *Controller) addNewTag(newNodeInfo *api.NodeInfo) (err error) {
	inboundConfig, err := InboundBuilder(c.config, newNodeInfo, c.Tag)
	if err != nil {
		return err
	}
	outboundConfig, err := OutboundBuilder(c.config, newNodeInfo, c.Tag)
	if err != nil {
		return err
	}
	if err := c.addInbound(inboundConfig); err != nil {
		return err
	}
	if err := c.addOutbound(outboundConfig); err != nil {
		return errors.Join(err, c.removeInbound(c.Tag))
	}
	return nil
}

// Speed fields remain part of panel snapshots for compatibility, but changing
// them must not restart a listener or replace an authenticated user's identity.
func sameNodeConfig(a, b *api.NodeInfo) bool {
	if a == nil || b == nil {
		return a == b
	}
	left, right := *a, *b
	left.SpeedLimit, right.SpeedLimit = 0, 0
	return reflect.DeepEqual(left, right)
}

func compareUserList(old, new *[]api.UserInfo) (deleted, added []api.UserInfo) {
	oldSet := make(map[api.UserInfo]api.UserInfo, len(*old))
	newSet := make(map[api.UserInfo]api.UserInfo, len(*new))
	for _, v := range *old {
		key := v
		key.SpeedLimit = 0
		oldSet[key] = v
	}
	for _, v := range *new {
		key := v
		key.SpeedLimit = 0
		newSet[key] = v
	}
	for key, v := range oldSet {
		if _, exists := newSet[key]; !exists {
			deleted = append(deleted, v)
		}
	}
	for key, v := range newSet {
		if _, exists := oldSet[key]; !exists {
			added = append(added, v)
		}
	}
	return deleted, added
}

func (c *Controller) userInfoMonitor() (err error) {
	// delay to start
	if time.Since(c.startAt) < time.Duration(c.config.UpdatePeriodic)*time.Second {
		return nil
	}
	c.monitorMu.Lock()
	defer c.monitorMu.Unlock()

	// Get server status
	CPU, Mem, Disk, Uptime, err := serverstatus.GetSystemInfo()
	if err != nil {
		c.logger.Print(err)
	}
	err = c.apiClient.ReportNodeStatus(
		&api.NodeStatus{
			CPU:    CPU,
			Mem:    Mem,
			Disk:   Disk,
			Uptime: Uptime,
		})
	if err != nil {
		c.logger.Print(err)
	}
	// Get User traffic
	var userTraffic []api.UserTraffic
	var trafficSnapshots []trafficCounterSnapshot
	collectTraffic := func(user api.UserInfo) {
		up, down, upCounter, downCounter := c.getTraffic(c.buildUserTag(&user))
		if up > 0 || down > 0 {
			userTraffic = append(userTraffic, api.UserTraffic{
				UID:      user.UID,
				Email:    user.Email,
				Upload:   up,
				Download: down})

			if upCounter != nil {
				trafficSnapshots = append(trafficSnapshots, trafficCounterSnapshot{counter: upCounter, value: up})
			}
			if downCounter != nil {
				trafficSnapshots = append(trafficSnapshots, trafficCounterSnapshot{counter: downCounter, value: down})
			}
		}
	}

	// A failed generation can already contain successfully added live users.
	// Account for those users while keeping the committed snapshot unchanged.
	if c.appliedUsers != nil {
		for _, user := range c.appliedUsers {
			collectTraffic(user)
		}
	} else if c.userList != nil {
		for _, user := range *c.userList {
			collectTraffic(user)
		}
	}

	if len(userTraffic) > 0 {
		var err error // Define an empty error
		if !c.config.DisableUploadTraffic {
			err = c.apiClient.ReportUserTraffic(&userTraffic)
		}
		// The counters were atomically snapshotted before reporting. Restore only
		// the snapshot on failure; traffic generated during the request remains in
		// the live counters for the next report.
		if err != nil {
			restoreTraffic(trafficSnapshots)
			c.logger.Print(err)
		}
	}

	// Report Online info
	if onlineDevice, err := c.GetOnlineDevice(c.Tag); err != nil {
		c.logger.Print(err)
	} else if len(*onlineDevice) > 0 {
		// Only report user has traffic > 100kb to allow ping test
		var result []api.OnlineUser
		var nocountUID = make(map[int]struct{})
		for _, traffic := range userTraffic {
			total := traffic.Upload + traffic.Download
			if total < int64(c.config.DeviceOnlineMinTraffic*1000) {
				nocountUID[traffic.UID] = struct{}{}
			}
		}
		for _, online := range *onlineDevice {
			if _, ok := nocountUID[online.UID]; !ok {
				result = append(result, online)
			}
		}

		if err = c.apiClient.ReportNodeOnlineUsers(&result); err != nil {
			log.Print(err)
		} else {
			log.Printf("Total %d online users, %d Reported", len(*onlineDevice), len(result))
		}
	}

	// Report Illegal user
	if detectResult, err := c.GetDetectResult(c.Tag); err != nil {
		c.logger.Print(err)
	} else if len(*detectResult) > 0 {
		if err = c.apiClient.ReportIllegal(detectResult); err != nil {
			c.logger.Print(err)
		} else {
			c.logger.Printf("Report %d illegal behaviors", len(*detectResult))
		}

	}
	return nil
}

func (c *Controller) buildNodeTag() string {
	return c.nodeTag(c.nodeInfo)
}

func (c *Controller) nodeTag(node *api.NodeInfo) string {
	return fmt.Sprintf("%s_%s_%d", node.NodeType, c.config.ListenIP, node.Port)
}

// func (c *Controller) logPrefix() string {
// 	return fmt.Sprintf("[%s] %s(ID=%d)", c.clientInfo.APIHost, c.nodeInfo.NodeType, c.nodeInfo.NodeID)
// }
