// Package limiter is to control the links that go into the dispatcher
package limiter

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/eko/gocache/lib/v4/cache"
	"github.com/eko/gocache/lib/v4/marshaler"
	"github.com/eko/gocache/lib/v4/store"
	goCacheStore "github.com/eko/gocache/store/go_cache/v4"
	redisStore "github.com/eko/gocache/store/redis/v4"
	"github.com/liyansum/Xray/api"
	goCache "github.com/patrickmn/go-cache"
	"github.com/redis/go-redis/v9"
	log "github.com/sirupsen/logrus"
	"golang.org/x/time/rate"
)

type UserInfo struct {
	UID         int
	SpeedLimit  uint64
	DeviceLimit int
}

type deviceIdentity struct {
	uid int
	ip  string
}

// userDeviceState separates devices already represented by the panel's
// previous-period count from devices first seen in the current period.
// A per-user lock keeps concurrent connection attempts from exceeding the
// configured limit without serializing authentication for unrelated users.
type userDeviceState struct {
	mu      sync.Mutex
	current map[string]int
	added   map[string]struct{}
}

func newUserDeviceState() *userDeviceState {
	return &userDeviceState{
		current: make(map[string]int),
		added:   make(map[string]struct{}),
	}
}

func (s *userDeviceState) hasCurrent() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.current) != 0
}

func (s *userDeviceState) snapshotAndReset() map[string]int {
	s.mu.Lock()
	defer s.mu.Unlock()
	current := s.current
	s.current = make(map[string]int)
	s.added = make(map[string]struct{})
	return current
}

type InboundInfo struct {
	Tag            string
	NodeSpeedLimit uint64
	userInfo       atomic.Pointer[map[string]UserInfo] // Immutable; key: Email
	BucketHub      *sync.Map                           // key: Email, value: *rate.Limiter
	userDevices    *sync.Map                           // Key: Email, value: *userDeviceState
	GlobalLimit    struct {
		config         *GlobalDeviceLimitConfig
		globalOnlineIP *marshaler.Marshaler
		redisClient    *redis.Client
		keyLocks       sync.Map // key: cache key, value: *sync.Mutex
	}
	aliveList    atomic.Pointer[map[int]int]                 // Key: Uid, value: alive_ip
	oldOnlineSet atomic.Pointer[map[deviceIdentity]struct{}] // Previous reporting period
}

type Limiter struct {
	InboundInfo *sync.Map // Key: Tag, Value: *InboundInfo
}

func New() *Limiter {
	return &Limiter{
		InboundInfo: new(sync.Map),
	}
}

// SetAliveList atomically publishes the latest immutable alive-device map.
// API clients replace this map after decoding instead of mutating it in place.
func (i *InboundInfo) SetAliveList(alive map[int]int) {
	snapshot := make(map[int]int, len(alive))
	for uid, count := range alive {
		snapshot[uid] = max(count, 0)
	}
	i.aliveList.Store(&snapshot)
}

func (i *InboundInfo) aliveCount(uid int) int {
	alive := i.aliveList.Load()
	if alive == nil {
		return 0
	}
	return (*alive)[uid]
}

func (i *InboundInfo) wasOnline(uid int, ip string) bool {
	previous := i.oldOnlineSet.Load()
	if previous == nil {
		return false
	}
	_, found := (*previous)[deviceIdentity{uid: uid, ip: ip}]
	return found
}

func (i *InboundInfo) deviceState(email string) *userDeviceState {
	if state, found := i.userDevices.Load(email); found {
		return state.(*userDeviceState)
	}
	state := newUserDeviceState()
	actual, _ := i.userDevices.LoadOrStore(email, state)
	return actual.(*userDeviceState)
}

func (i *InboundInfo) registerDevice(email string, uid int, ip string, deviceLimit int) bool {
	state := i.deviceState(email)
	state.mu.Lock()
	defer state.mu.Unlock()

	if _, found := state.current[ip]; found {
		return false
	}

	// Devices seen in the preceding report are already included in aliveCount;
	// accepting them again must not consume another slot.
	if i.wasOnline(uid, ip) {
		state.current[ip] = uid
		return false
	}

	if deviceLimit > 0 && i.aliveCount(uid)+len(state.added) >= deviceLimit {
		return true
	}
	state.current[ip] = uid
	state.added[ip] = struct{}{}
	return false
}

func buildUserInfoMap(tag string, users []api.UserInfo) *map[string]UserInfo {
	userMap := make(map[string]UserInfo, len(users))
	for _, user := range users {
		userMap[fmt.Sprintf("%s|%s|%d", tag, user.Email, user.UID)] = UserInfo{
			UID:         user.UID,
			SpeedLimit:  user.SpeedLimit,
			DeviceLimit: user.DeviceLimit,
		}
	}
	return &userMap
}

func (i *InboundInfo) updateUsers(tag string, users []api.UserInfo) {
	for {
		current := i.userInfo.Load()
		next := make(map[string]UserInfo, len(users))
		if current != nil {
			next = make(map[string]UserInfo, len(*current)+len(users))
			for email, info := range *current {
				next[email] = info
			}
		}
		for _, user := range users {
			next[fmt.Sprintf("%s|%s|%d", tag, user.Email, user.UID)] = UserInfo{
				UID:         user.UID,
				SpeedLimit:  user.SpeedLimit,
				DeviceLimit: user.DeviceLimit,
			}
		}
		if i.userInfo.CompareAndSwap(current, &next) {
			return
		}
	}
}

func (i *InboundInfo) removeUsers(emails []string) {
	removed := make(map[string]struct{}, len(emails))
	removedUIDs := make(map[int]struct{}, len(emails))
	removedGlobalKeys := make(map[string]struct{}, len(emails))
	for _, email := range emails {
		removed[email] = struct{}{}
	}
	for {
		current := i.userInfo.Load()
		if current == nil {
			break
		}
		next := make(map[string]UserInfo, len(*current))
		for email, info := range *current {
			if _, found := removed[email]; found {
				removedUIDs[info.UID] = struct{}{}
				removedGlobalKeys[strings.Replace(email, i.Tag, strconv.Itoa(info.DeviceLimit), 1)] = struct{}{}
				continue
			}
			next[email] = info
		}
		if i.userInfo.CompareAndSwap(current, &next) {
			break
		}
	}
	for email := range removed {
		i.BucketHub.Delete(email)
		i.userDevices.Delete(email)
	}
	for key := range removedGlobalKeys {
		i.GlobalLimit.keyLocks.Delete(key)
	}
	for {
		current := i.oldOnlineSet.Load()
		if current == nil {
			break
		}
		next := make(map[deviceIdentity]struct{}, len(*current))
		for identity := range *current {
			if _, found := removedUIDs[identity.uid]; !found {
				next[identity] = struct{}{}
			}
		}
		if i.oldOnlineSet.CompareAndSwap(current, &next) {
			break
		}
	}
}

func (i *InboundInfo) close() error {
	if i.GlobalLimit.redisClient != nil {
		return i.GlobalLimit.redisClient.Close()
	}
	return nil
}

func (l *Limiter) AddInboundLimiter(tag string, nodeSpeedLimit uint64, userList *[]api.UserInfo, globalLimit *GlobalDeviceLimitConfig) error {
	inboundInfo := &InboundInfo{
		Tag:            tag,
		NodeSpeedLimit: nodeSpeedLimit,
		BucketHub:      new(sync.Map),
		userDevices:    new(sync.Map),
	}
	emptyOldOnline := make(map[deviceIdentity]struct{})
	inboundInfo.oldOnlineSet.Store(&emptyOldOnline)

	if globalLimit != nil && globalLimit.Enable {
		inboundInfo.GlobalLimit.config = globalLimit

		// init local store
		gs := goCacheStore.NewGoCache(goCache.New(time.Duration(globalLimit.Expiry)*time.Second, 1*time.Minute))

		// init redis store
		redisClient := redis.NewClient(
			&redis.Options{
				Network:  globalLimit.RedisNetwork,
				Addr:     globalLimit.RedisAddr,
				Username: globalLimit.RedisUsername,
				Password: globalLimit.RedisPassword,
				DB:       globalLimit.RedisDB,
			})
		inboundInfo.GlobalLimit.redisClient = redisClient
		rs := redisStore.NewRedis(redisClient,
			store.WithExpiration(time.Duration(globalLimit.Expiry)*time.Second))

		// init chained cache. First use local go-cache, if go-cache is nil, then use redis cache
		cacheManager := cache.NewChain[any](
			cache.New[any](gs), // go-cache is priority
			cache.New[any](rs),
		)
		inboundInfo.GlobalLimit.globalOnlineIP = marshaler.New(cacheManager)
	}

	inboundInfo.userInfo.Store(buildUserInfoMap(tag, *userList))
	if old, loaded := l.InboundInfo.Swap(tag, inboundInfo); loaded {
		if err := old.(*InboundInfo).close(); err != nil {
			return err
		}
	}
	return nil
}

func (l *Limiter) UpdateInboundLimiter(tag string, updatedUserList *[]api.UserInfo) error {
	if value, ok := l.InboundInfo.Load(tag); ok {
		inboundInfo := value.(*InboundInfo)
		// Publish all user changes as one immutable snapshot. CAS avoids losing
		// concurrent updates from the node and traffic monitor tasks.
		inboundInfo.updateUsers(tag, *updatedUserList)
		for _, u := range *updatedUserList {
			// Update old limiter bucket
			limit := determineRate(inboundInfo.NodeSpeedLimit, u.SpeedLimit)
			if limit > 0 {
				if bucket, ok := inboundInfo.BucketHub.Load(fmt.Sprintf("%s|%s|%d", tag, u.Email, u.UID)); ok {
					limiter := bucket.(*rate.Limiter)
					limiter.SetLimit(rate.Limit(limit))
					limiter.SetBurst(int(limit))
				}
			} else {
				inboundInfo.BucketHub.Delete(fmt.Sprintf("%s|%s|%d", tag, u.Email, u.UID))
			}
		}
	} else {
		return fmt.Errorf("no such inbound in limiter: %s", tag)
	}
	return nil
}

func (l *Limiter) DeleteInboundLimiter(tag string) error {
	if value, loaded := l.InboundInfo.LoadAndDelete(tag); loaded {
		return value.(*InboundInfo).close()
	}
	return nil
}

func (l *Limiter) RemoveInboundUsers(tag string, emails []string) error {
	if value, ok := l.InboundInfo.Load(tag); ok {
		value.(*InboundInfo).removeUsers(emails)
		return nil
	}
	return fmt.Errorf("no such inbound in limiter: %s", tag)
}

func (l *Limiter) GetOnlineDevice(tag string) (*[]api.OnlineUser, error) {
	var onlineUser []api.OnlineUser

	if value, ok := l.InboundInfo.Load(tag); ok {
		inboundInfo := value.(*InboundInfo)
		nextOldOnline := make(map[deviceIdentity]struct{})
		// Clear Speed Limiter bucket for users who are not online
		inboundInfo.BucketHub.Range(func(key, value interface{}) bool {
			email := key.(string)
			stateValue, exists := inboundInfo.userDevices.Load(email)
			if !exists || !stateValue.(*userDeviceState).hasCurrent() {
				inboundInfo.BucketHub.Delete(email)
			}
			return true
		})
		inboundInfo.userDevices.Range(func(_, value interface{}) bool {
			for ip, uid := range value.(*userDeviceState).snapshotAndReset() {
				nextOldOnline[deviceIdentity{uid: uid, ip: ip}] = struct{}{}
				onlineUser = append(onlineUser, api.OnlineUser{UID: uid, IP: ip})
			}
			return true
		})
		// Publish one immutable generation so connection checks never observe a
		// partially rebuilt previous-period set.
		inboundInfo.oldOnlineSet.Store(&nextOldOnline)
	} else {
		return nil, fmt.Errorf("no such inbound in limiter: %s", tag)
	}

	return &onlineUser, nil
}

func (l *Limiter) GetUserBucket(tag string, email string, ip string, isSourceTCP bool) (limiter *rate.Limiter, SpeedLimit bool, Reject bool) {
	if value, ok := l.InboundInfo.Load(tag); ok {
		var (
			userLimit        uint64 = 0
			deviceLimit, uid int
			knownUser        bool
		)

		inboundInfo := value.(*InboundInfo)
		nodeLimit := inboundInfo.NodeSpeedLimit

		users := inboundInfo.userInfo.Load()
		if users != nil {
			u, ok := (*users)[email]
			if ok {
				knownUser = true
				uid = u.UID
				userLimit = u.SpeedLimit
				deviceLimit = u.DeviceLimit
			}
		}

		// Device limits apply only to TCP source connections. The user-specific
		// state makes admission atomic while allowing unrelated users to connect
		// concurrently.
		if knownUser && isSourceTCP && inboundInfo.registerDevice(email, uid, ip, deviceLimit) {
			return nil, false, true
		}

		// GlobalLimit
		if knownUser && deviceLimit > 0 && inboundInfo.GlobalLimit.config != nil && inboundInfo.GlobalLimit.config.Enable {
			if reject := globalLimit(inboundInfo, email, uid, ip, deviceLimit); reject {
				return nil, false, true
			}
		}

		// Speed limit
		limit := determineRate(nodeLimit, userLimit) // Determine the speed limit rate
		if limit > 0 {
			if v, ok := inboundInfo.BucketHub.Load(email); ok {
				return v.(*rate.Limiter), true, false
			}
			newLimiter := rate.NewLimiter(rate.Limit(limit), int(limit)) // Byte/s
			actual, _ := inboundInfo.BucketHub.LoadOrStore(email, newLimiter)
			return actual.(*rate.Limiter), true, false
		} else {
			return nil, false, false
		}
	} else {
		log.Error("Get Inbound Limiter information failed")
		return nil, false, false
	}
}

// Global device limit
func globalLimit(inboundInfo *InboundInfo, email string, uid int, ip string, deviceLimit int) bool {
	// reformat email for unique key
	uniqueKey := strings.Replace(email, inboundInfo.Tag, strconv.Itoa(deviceLimit), 1)
	lockValue, _ := inboundInfo.GlobalLimit.keyLocks.LoadOrStore(uniqueKey, new(sync.Mutex))
	lock := lockValue.(*sync.Mutex)
	lock.Lock()
	defer lock.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(inboundInfo.GlobalLimit.config.Timeout)*time.Second)
	defer cancel()

	v, err := inboundInfo.GlobalLimit.globalOnlineIP.Get(ctx, uniqueKey, new(map[string]int))
	if err != nil {
		if _, ok := err.(*store.NotFound); ok {
			// If the email is a new device
			pushIP(inboundInfo, uniqueKey, &map[string]int{ip: uid})
		} else {
			log.Error("cache service", err)
		}
		return false
	}

	cached := *v.(*map[string]int)
	if _, ok := cached[ip]; ok {
		return false
	}
	// The candidate IP itself consumes the next slot, so equality is already
	// full. The old strict-greater check admitted one device too many.
	if deviceLimit > 0 && len(cached) >= deviceLimit {
		return true
	}

	// Never mutate a map owned by a cache implementation. A copy avoids data
	// races with readers and is published before releasing this user's lock.
	ipMap := make(map[string]int, len(cached)+1)
	for cachedIP, cachedUID := range cached {
		ipMap[cachedIP] = cachedUID
	}
	ipMap[ip] = uid
	pushIP(inboundInfo, uniqueKey, &ipMap)

	return false
}

// push the ip to cache
func pushIP(inboundInfo *InboundInfo, uniqueKey string, ipMap *map[string]int) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(inboundInfo.GlobalLimit.config.Timeout)*time.Second)
	defer cancel()

	if err := inboundInfo.GlobalLimit.globalOnlineIP.Set(ctx, uniqueKey, ipMap); err != nil {
		log.Error("cache service", err)
	}
}

// determineRate returns the minimum non-zero rate
func determineRate(nodeLimit, userLimit uint64) (limit uint64) {
	if nodeLimit == 0 || userLimit == 0 {
		if nodeLimit > userLimit {
			return nodeLimit
		} else if nodeLimit < userLimit {
			return userLimit
		} else {
			return 0
		}
	} else {
		if nodeLimit > userLimit {
			return userLimit
		} else if nodeLimit < userLimit {
			return nodeLimit
		} else {
			return nodeLimit
		}
	}
}
