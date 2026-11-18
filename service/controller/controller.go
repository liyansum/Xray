package controller

import (
	"errors"
	"fmt"
	"reflect"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/xtls/xray-core/common/protocol"
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
	tasks      []periodicTask
	panelType  string
	ibm        inbound.Manager
	obm        outbound.Manager
	stm        stats.Manager
	dispatcher *mydispatcher.DefaultDispatcher
	startAt    time.Time
	logger     *log.Entry
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
	if newNodeInfo.Port == 0 {
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

	// sync controller userList
	c.userList = userInfo

	err = c.addNewUser(userInfo, newNodeInfo)
	if err != nil {
		return err
	}

	// Add Limiter
	if err := c.AddInboundLimiter(c.Tag, newNodeInfo.SpeedLimit, userInfo, c.config.GlobalDeviceLimitConfig); err != nil {
		c.logger.Print(err)
	}

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
	return closeErr
}

func (c *Controller) nodeInfoMonitor() (err error) {
	// delay to start
	if time.Since(c.startAt) < time.Duration(c.config.UpdatePeriodic)*time.Second {
		return nil
	}
	c.monitorMu.Lock()
	defer c.monitorMu.Unlock()

	// First fetch Node Info
	var nodeInfoChanged = true
	newNodeInfo, err := c.apiClient.GetNodeInfo()
	if err != nil {
		if err.Error() == api.NodeNotModified {
			nodeInfoChanged = false
			newNodeInfo = c.nodeInfo
		} else {
			c.logger.Print(err)
			return nil
		}
	}
	if newNodeInfo.Port == 0 {
		return errors.New("server port must > 0")
	}

	// Update User
	var usersChanged = true
	newUserInfo, err := c.apiClient.GetUserList()

	// Update alive user list
	if v2b, ok := c.apiClient.(*newV2board.APIClient); ok {
		if v, ok := c.dispatcher.Limiter.InboundInfo.Load(c.Tag); ok {
			inboundinfo := v.(*limiter.InboundInfo)
			inboundinfo.SetAliveList(v2b.AliveMap.Alive)
		}
	}
	if err != nil {
		if err.Error() == api.UserNotModified {
			usersChanged = false
			newUserInfo = c.userList
		} else {
			c.logger.Print(err)
			return nil
		}
	}

	// If nodeInfo changed
	if nodeInfoChanged {
		if !sameNodeConfig(c.nodeInfo, newNodeInfo) {
			// Remove old tag
			oldTag := c.Tag
			err := c.removeOldTag(oldTag)
			if err != nil {
				c.logger.Print(err)
				return nil
			}
			if c.userList != nil {
				for _, user := range *c.userList {
					oldEmail := fmt.Sprintf("%s|%s|%d", oldTag, user.Email, user.UID)
					if err := c.unregisterUserCounters(oldEmail); err != nil {
						c.logger.Print(err)
					}
				}
			}
			// Add new tag
			c.nodeInfo = newNodeInfo
			c.Tag = c.buildNodeTag()
			err = c.addNewTag(newNodeInfo)
			if err != nil {
				c.logger.Print(err)
				return nil
			}
			nodeInfoChanged = true
			// Remove Old limiter
			if err = c.DeleteInboundLimiter(oldTag); err != nil {
				c.logger.Print(err)
				return nil
			}
		} else {
			nodeInfoChanged = false
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

	if nodeInfoChanged {
		err = c.addNewUser(newUserInfo, newNodeInfo)
		if err != nil {
			c.logger.Print(err)
			return nil
		}

		// Add Limiter
		if err := c.AddInboundLimiter(c.Tag, newNodeInfo.SpeedLimit, newUserInfo, c.config.GlobalDeviceLimitConfig); err != nil {
			c.logger.Print(err)
			return nil
		}

	} else {
		var deleted, added []api.UserInfo
		if usersChanged {
			deleted, added = compareUserList(c.userList, newUserInfo)
			if len(deleted) > 0 {
				deletedEmail := make([]string, len(deleted))
				for i, u := range deleted {
					deletedEmail[i] = fmt.Sprintf("%s|%s|%d", c.Tag, u.Email, u.UID)
				}
				if err := c.removeUsers(deletedEmail, c.Tag); err != nil {
					c.logger.Print(err)
				}
				if err := c.RemoveInboundLimiterUsers(c.Tag, deletedEmail); err != nil {
					c.logger.Print(err)
				}
			}
			if len(added) > 0 {
				err = c.addNewUser(&added, c.nodeInfo)
				if err != nil {
					c.logger.Print(err)
				}
				// Update Limiter
				if err := c.UpdateInboundLimiter(c.Tag, &added); err != nil {
					c.logger.Print(err)
				}
			}
		}
		c.logger.Printf("%d user deleted, %d user added", len(deleted), len(added))
	}
	c.userList = newUserInfo
	return nil
}

func (c *Controller) removeOldTag(oldTag string) (err error) {
	err = c.removeInbound(oldTag)
	if err != nil {
		return err
	}
	err = c.removeOutbound(oldTag)
	if err != nil {
		return err
	}
	c.dispatcher.RuleManager.RemoveRule(oldTag)
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

func (c *Controller) addNewUser(userInfo *[]api.UserInfo, nodeInfo *api.NodeInfo) (err error) {
	var users []*protocol.User
	switch nodeInfo.NodeType {
	case "Trojan":
		users = c.buildTrojanUser(userInfo)
	case "Shadowsocks":
		users = c.buildSSUser(userInfo, nodeInfo.CypherMethod)
	default:
		return fmt.Errorf("unsupported node type: %s", nodeInfo.NodeType)
	}

	err = c.addUsers(users, c.Tag)
	if err != nil {
		return err
	}
	c.logger.Printf("Added %d new users", len(*userInfo))
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
	for _, user := range *c.userList {
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
	return fmt.Sprintf("%s_%s_%d", c.nodeInfo.NodeType, c.config.ListenIP, c.nodeInfo.Port)
}

// func (c *Controller) logPrefix() string {
// 	return fmt.Sprintf("[%s] %s(ID=%d)", c.clientInfo.APIHost, c.nodeInfo.NodeType, c.nodeInfo.NodeID)
// }
