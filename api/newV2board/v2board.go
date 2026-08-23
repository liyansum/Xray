package newV2board

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/bitly/go-simplejson"
	"github.com/go-resty/resty/v2"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/infra/conf"

	"github.com/liyansum/Xray/api"
)

// APIClient create an api client to the panel.
type APIClient struct {
	client        *resty.Client
	APIHost       string
	NodeID        int
	Key           string
	NodeType      string
	SpeedLimit    float64
	DeviceLimit   int
	LocalRuleList []api.DetectRule
	resp          atomic.Value
	eTags         map[string]string
	AliveMap      *AliveMap
	aliveSource   aliveSource
	lastUserList  []api.UserInfo
}

type aliveSource uint8

const (
	aliveSourceUnknown aliveSource = iota
	aliveSourceUserList
	aliveSourceEndpoint
)

// New create an api instance
func New(apiConfig *api.Config) *APIClient {
	client := api.NewPanelHTTPClient(apiConfig)
	client.SetBaseURL(apiConfig.APIHost)

	// Create Key for each requests
	client.SetQueryParams(map[string]string{
		"node_id":   strconv.Itoa(apiConfig.NodeID),
		"node_type": strings.ToLower(apiConfig.NodeType),
		"token":     apiConfig.Key,
	})
	// Read local rule list
	localRuleList := api.ReadLocalRuleList(apiConfig.RuleListPath)
	apiClient := &APIClient{
		client:        client,
		NodeID:        apiConfig.NodeID,
		Key:           apiConfig.Key,
		APIHost:       apiConfig.APIHost,
		NodeType:      apiConfig.NodeType,
		SpeedLimit:    apiConfig.SpeedLimit,
		DeviceLimit:   apiConfig.DeviceLimit,
		LocalRuleList: localRuleList,
		eTags:         make(map[string]string),
		AliveMap:      &AliveMap{},
	}
	return apiClient
}

// Describe return a description of the client
func (c *APIClient) Describe() api.ClientInfo {
	return api.ClientInfo{APIHost: c.APIHost, NodeID: c.NodeID, Key: c.Key, NodeType: c.NodeType}
}

// Debug set the client debug for client
func (c *APIClient) Debug() {
	api.EnableSafeDebug(c.client)
}

func (c *APIClient) assembleURL(path string) string {
	return c.APIHost + path
}

func (c *APIClient) parseResponse(res *resty.Response, path string, err error) (*simplejson.Json, error) {
	return api.ParseJSONResponse(res, c.assembleURL(path), err, 399)
}

// GetNodeInfo will pull NodeInfo Config from panel
func (c *APIClient) GetNodeInfo() (nodeInfo *api.NodeInfo, err error) {
	server := new(serverConfig)
	path := "/api/v1/server/UniProxy/config"

	res, err := c.client.R().
		SetHeader("If-None-Match", c.eTags["node"]).
		ForceContentType("application/json").
		Get(path)

	// Etag identifier for a specific version of a resource. StatusCode = 304 means no changed
	if res.StatusCode() == 304 {
		return nil, errors.New(api.NodeNotModified)
	}
	// update etag
	if res.Header().Get("Etag") != "" && res.Header().Get("Etag") != c.eTags["node"] {
		c.eTags["node"] = res.Header().Get("Etag")
	}

	nodeInfoResp, err := c.parseResponse(res, path, err)
	if err != nil {
		return nil, err
	}
	b, _ := nodeInfoResp.Encode()
	json.Unmarshal(b, server)

	if server.ServerPort == 0 {
		return nil, errors.New("server port must > 0")
	}

	c.resp.Store(server)

	switch c.NodeType {
	case "Trojan":
		nodeInfo, err = c.parseTrojanNodeResponse(server)
	case "Shadowsocks":
		nodeInfo, err = c.parseSSNodeResponse(server)
	default:
		return nil, fmt.Errorf("unsupported node type: %s", c.NodeType)
	}

	if err != nil {
		return nil, fmt.Errorf("parse node info failed: %s, \nError: %s", api.SanitizeResponse(res), api.RedactText(err.Error()))
	}

	return nodeInfo, nil
}

// GetUserList will pull user form panel
func (c *APIClient) GetUserList() (UserList *[]api.UserInfo, err error) {
	var users []*user
	path := "/api/v1/server/UniProxy/user"

	switch c.NodeType {
	case "Trojan", "Shadowsocks":
		break
	default:
		return nil, fmt.Errorf("unsupported node type: %s", c.NodeType)
	}

	res, err := c.client.R().
		SetHeader("If-None-Match", c.eTags["users"]).
		ForceContentType("application/json").
		Get(path)

	// Etag identifier for a specific version of a resource. StatusCode = 304 means no changed
	if err == nil && res != nil && res.StatusCode() == 304 {
		// New panels keep online counts in a separate resource, so it must still
		// be refreshed when the user resource itself is unchanged. On old panels
		// alive_ip participates in the user ETag and the previous snapshot remains
		// valid for a 304 response.
		if c.aliveSource != aliveSourceUserList {
			_, _ = c.GetUserAlive()
		}
		return nil, errors.New(api.UserNotModified)
	}
	if err != nil || res == nil {
		_, parseErr := c.parseResponse(res, path, err)
		return nil, parseErr
	}
	// update etag
	if res.Header().Get("Etag") != "" && res.Header().Get("Etag") != c.eTags["users"] {
		c.eTags["users"] = res.Header().Get("Etag")
	}

	usersResp, err := c.parseResponse(res, path, err)
	if err != nil {
		return nil, err
	}
	b, err := usersResp.Get("users").Encode()
	if err != nil {
		return nil, fmt.Errorf("encode users response: %w", err)
	}
	if err := json.Unmarshal(b, &users); err != nil {
		return nil, fmt.Errorf("unmarshal users response: %w", err)
	}
	if len(users) == 0 {
		return nil, errors.New("users is null")
	}

	var deviceLimit int
	userList := make([]api.UserInfo, 0, len(users))
	embeddedAlive := make(map[int]int)
	hasEmbeddedAlive := false
	for _, user := range users {
		u := api.UserInfo{
			UID:  user.Id,
			UUID: user.Uuid,
		}
		// Support 1.7.1 speed limit
		if c.SpeedLimit > 0 {
			u.SpeedLimit = uint64(c.SpeedLimit * 1000000 / 8)
		} else {
			u.SpeedLimit = uint64(user.SpeedLimit * 1000000 / 8)
		}
		//Prefer local config
		if c.DeviceLimit > 0 {
			deviceLimit = c.DeviceLimit
		} else {
			deviceLimit = user.DeviceLimit
		}

		u.DeviceLimit = deviceLimit
		if user.AliveIP != nil {
			hasEmbeddedAlive = true
			embeddedAlive[user.Id] = max(*user.AliveIP, 0)
		}
		u.Email = u.UUID + "@v2board.user"
		if c.NodeType == "Shadowsocks" {
			u.Passwd = u.UUID
		}

		userList = append(userList, u)
	}

	if hasEmbeddedAlive {
		// Legacy panel: alive_ip is part of /user. Do not probe an endpoint that
		// does not exist on those releases.
		c.setAliveMap(embeddedAlive)
		c.aliveSource = aliveSourceUserList
	} else {
		// This also permits a running panel to be upgraded from the embedded
		// format: the first response without alive_ip probes the new endpoint.
		if c.aliveSource == aliveSourceUserList {
			c.aliveSource = aliveSourceUnknown
		}
		_, _ = c.GetUserAlive()
	}

	if slices.Equal(c.lastUserList, userList) {
		// Old panels include alive_ip in the user ETag. Avoid rebuilding users and
		// counters when only the online-device snapshot changed.
		return nil, errors.New(api.UserNotModified)
	}
	c.lastUserList = append(c.lastUserList[:0], userList...)

	return &userList, nil
}

func (c *APIClient) setAliveMap(alive map[int]int) {
	for uid, count := range alive {
		alive[uid] = max(count, 0)
	}
	// Both callers pass a freshly decoded or newly built map. Publish it as an
	// immutable snapshot; the limiter makes its own copy at the API boundary.
	c.AliveMap = &AliveMap{Alive: alive}
}

// GetUserAlive will fetch the alive_ip count for users
func (c *APIClient) GetUserAlive() (map[int]int, error) {
	const path = "/api/v1/server/UniProxy/alivelist"
	r, err := c.client.R().
		ForceContentType("application/json").
		Get(path)
	if err != nil {
		return c.AliveMap.Alive, err
	}
	if r == nil {
		return c.AliveMap.Alive, fmt.Errorf("received nil response")
	}
	if r.StatusCode() > 399 {
		// Preserve the last known snapshot on a transient panel error. Clearing it
		// would temporarily disable device limits.
		return c.AliveMap.Alive, fmt.Errorf("alive list endpoint returned status %d", r.StatusCode())
	}
	alive := &AliveMap{}
	if err := json.Unmarshal(r.Body(), alive); err != nil {
		return nil, fmt.Errorf("unmarshal user alive list error: %s", err)
	}
	if alive.Alive == nil {
		alive.Alive = make(map[int]int)
	}
	c.setAliveMap(alive.Alive)
	c.aliveSource = aliveSourceEndpoint

	return c.AliveMap.Alive, nil
}

// ReportUserTraffic reports the user traffic
func (c *APIClient) ReportUserTraffic(userTraffic *[]api.UserTraffic) error {
	path := "/api/v1/server/UniProxy/push"

	// json structure: {uid1: [u, d], uid2: [u, d], uid1: [u, d], uid3: [u, d]}
	data := make(map[int][]int64, len(*userTraffic))
	for _, traffic := range *userTraffic {
		data[traffic.UID] = []int64{traffic.Upload, traffic.Download}
	}

	res, err := c.client.R().SetBody(data).ForceContentType("application/json").Post(path)
	_, err = c.parseResponse(res, path, err)
	if err != nil {
		return err
	}

	return nil
}

// GetNodeRule implements the API interface
func (c *APIClient) GetNodeRule() (*[]api.DetectRule, error) {
	routes := c.resp.Load().(*serverConfig).Routes

	ruleList := c.LocalRuleList

	for i := range routes {
		if routes[i].Action == "block" {
			ruleList = append(ruleList, api.DetectRule{
				ID:      i,
				Pattern: regexp.MustCompile(strings.Join(routes[i].Match, "|")),
			})
		}
	}

	return &ruleList, nil
}

// ReportNodeStatus implements the API interface
func (c *APIClient) ReportNodeStatus(nodeStatus *api.NodeStatus) (err error) {
	return nil
}

// ReportNodeOnlineUsers implements the API interface
func (c *APIClient) ReportNodeOnlineUsers(onlineUserList *[]api.OnlineUser) error {
	data := make(map[int][]string)
	for _, onlineuser := range *onlineUserList {
		// json structure: { UID1:["ip1","ip2"],UID2:["ip3","ip4"] }
		data[onlineuser.UID] = append(data[onlineuser.UID], onlineuser.IP)
	}

	path := "/api/v1/server/UniProxy/alive"
	res, err := c.client.R().SetBody(data).ForceContentType("application/json").Post(path)
	_, err = c.parseResponse(res, path, err)
	// 面板无对应接口时先不报错
	if err != nil {
		return nil
	}

	return nil
}

// ReportIllegal implements the API interface
func (c *APIClient) ReportIllegal(detectResultList *[]api.DetectResult) error {
	return nil
}

// parseTrojanNodeResponse parse the response for the given nodeInfo format
func (c *APIClient) parseTrojanNodeResponse(s *serverConfig) (*api.NodeInfo, error) {
	return &api.NodeInfo{
		NodeType:          c.NodeType,
		NodeID:            c.NodeID,
		Port:              uint32(s.ServerPort),
		TransportProtocol: "tcp",
		EnableTLS:         true,
		NameServerConfig:  s.parseDNSConfig(),
	}, nil
}

// parseSSNodeResponse parse the response for the given nodeInfo format
func (c *APIClient) parseSSNodeResponse(s *serverConfig) (*api.NodeInfo, error) {
	var header json.RawMessage

	if s.Obfs == "http" {
		path := "/"
		if p := s.ObfsSettings.Path; p != "" {
			if strings.HasPrefix(p, "/") {
				path = p
			} else {
				path += p
			}
		}
		h := simplejson.New()
		h.Set("type", "http")
		h.SetPath([]string{"request", "path"}, path)
		header, _ = h.Encode()
	}
	// Create GeneralNodeInfo
	return &api.NodeInfo{
		NodeType:          c.NodeType,
		NodeID:            c.NodeID,
		Port:              uint32(s.ServerPort),
		TransportProtocol: "tcp",
		CypherMethod:      s.Cipher,
		ServerKey:         s.ServerKey, // shadowsocks2022 share key
		NameServerConfig:  s.parseDNSConfig(),
		Header:            header,
	}, nil
}

func (s *serverConfig) parseDNSConfig() (nameServerList []*conf.NameServerConfig) {
	for i := range s.Routes {
		if s.Routes[i].Action == "dns" {
			nameServerList = append(nameServerList, &conf.NameServerConfig{
				Address: &conf.Address{Address: net.ParseAddress(s.Routes[i].ActionValue)},
				Domains: s.Routes[i].Match,
			})
		}
	}

	return
}
