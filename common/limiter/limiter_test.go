package limiter

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/liyansum/Xray/api"
	"github.com/xtls/xray-core/common/buf"
	"golang.org/x/time/rate"
)

func TestRemoveInboundUsersReclaimsState(t *testing.T) {
	users := []api.UserInfo{
		{UID: 1, Email: "first@example.com", SpeedLimit: 100, DeviceLimit: 1},
		{UID: 2, Email: "second@example.com", SpeedLimit: 200, DeviceLimit: 2},
	}
	limiter := New()
	if err := limiter.AddInboundLimiter("node", 0, &users, nil); err != nil {
		t.Fatal(err)
	}
	value, _ := limiter.InboundInfo.Load("node")
	inbound := value.(*InboundInfo)
	removedEmail := "node|first@example.com|1"
	inbound.BucketHub.Store(removedEmail, rate.NewLimiter(1, 1))
	state := newUserDeviceState()
	state.current["192.0.2.1"] = 1
	inbound.userDevices.Store(removedEmail, state)
	oldOnline := map[deviceIdentity]struct{}{{uid: 1, ip: "192.0.2.1"}: {}}
	inbound.oldOnlineSet.Store(&oldOnline)

	if err := limiter.RemoveInboundUsers("node", []string{removedEmail}); err != nil {
		t.Fatal(err)
	}
	if _, found := (*inbound.userInfo.Load())[removedEmail]; found {
		t.Fatal("removed user remains in limiter snapshot")
	}
	if _, found := inbound.BucketHub.Load(removedEmail); found {
		t.Fatal("removed user's rate bucket remains")
	}
	if _, found := inbound.userDevices.Load(removedEmail); found {
		t.Fatal("removed user's online IP state remains")
	}
	if inbound.wasOnline(1, "192.0.2.1") {
		t.Fatal("removed user's historical IP remains")
	}
	if _, found := (*inbound.userInfo.Load())["node|second@example.com|2"]; !found {
		t.Fatal("active user was removed")
	}
}

func TestOldUserOnlineIsReplacedEachReport(t *testing.T) {
	users := []api.UserInfo{{UID: 1, Email: "user@example.com"}}
	limiter := New()
	if err := limiter.AddInboundLimiter("node", 0, &users, nil); err != nil {
		t.Fatal(err)
	}
	value, _ := limiter.InboundInfo.Load("node")
	inbound := value.(*InboundInfo)
	oldOnline := map[deviceIdentity]struct{}{{uid: 1, ip: "192.0.2.1"}: {}}
	inbound.oldOnlineSet.Store(&oldOnline)
	state := newUserDeviceState()
	state.current["192.0.2.2"] = 1
	inbound.userDevices.Store("node|user@example.com|1", state)
	if _, err := limiter.GetOnlineDevice("node"); err != nil {
		t.Fatal(err)
	}
	if inbound.wasOnline(1, "192.0.2.1") {
		t.Fatal("previous reporting period remains")
	}
	if !inbound.wasOnline(1, "192.0.2.2") {
		t.Fatal("current reporting period was not retained")
	}
}

func TestDeviceLimitCountsPanelBaselineAndCurrentPeriod(t *testing.T) {
	users := []api.UserInfo{{UID: 1, Email: "user@example.com", DeviceLimit: 2}}
	limiter := New()
	if err := limiter.AddInboundLimiter("node", 0, &users, nil); err != nil {
		t.Fatal(err)
	}
	value, _ := limiter.InboundInfo.Load("node")
	inbound := value.(*InboundInfo)
	inbound.SetAliveList(map[int]int{1: 1})
	email := "node|user@example.com|1"

	if _, _, reject := limiter.GetUserBucket("node", email, "192.0.2.1", true); reject {
		t.Fatal("first current-period device was rejected")
	}
	if _, _, reject := limiter.GetUserBucket("node", email, "192.0.2.2", true); !reject {
		t.Fatal("device exceeding panel baseline plus local additions was accepted")
	}
	if _, _, reject := limiter.GetUserBucket("node", email, "192.0.2.1", true); reject {
		t.Fatal("an already accepted device consumed another slot")
	}
}

func TestPreviousPeriodDeviceDoesNotConsumeAnotherSlot(t *testing.T) {
	users := []api.UserInfo{{UID: 1, Email: "user@example.com", DeviceLimit: 2}}
	limiter := New()
	if err := limiter.AddInboundLimiter("node", 0, &users, nil); err != nil {
		t.Fatal(err)
	}
	email := "node|user@example.com|1"
	if _, _, reject := limiter.GetUserBucket("node", email, "192.0.2.1", true); reject {
		t.Fatal("initial device was rejected")
	}
	if _, err := limiter.GetOnlineDevice("node"); err != nil {
		t.Fatal(err)
	}
	value, _ := limiter.InboundInfo.Load("node")
	value.(*InboundInfo).SetAliveList(map[int]int{1: 1})

	if _, _, reject := limiter.GetUserBucket("node", email, "192.0.2.1", true); reject {
		t.Fatal("previous-period device was counted twice")
	}
	if _, _, reject := limiter.GetUserBucket("node", email, "192.0.2.2", true); reject {
		t.Fatal("one genuinely new device should fit the remaining slot")
	}
	if _, _, reject := limiter.GetUserBucket("node", email, "192.0.2.3", true); !reject {
		t.Fatal("third device was accepted")
	}
}

func TestConcurrentDeviceAdmissionDoesNotExceedLimit(t *testing.T) {
	const deviceLimit = 10
	users := []api.UserInfo{{UID: 1, Email: "user@example.com", DeviceLimit: deviceLimit}}
	limiter := New()
	if err := limiter.AddInboundLimiter("node", 0, &users, nil); err != nil {
		t.Fatal(err)
	}
	email := "node|user@example.com|1"
	var accepted atomic.Int32
	var wg sync.WaitGroup
	for i := range 100 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, _, reject := limiter.GetUserBucket("node", email, fmt.Sprintf("192.0.2.%d", i), true); !reject {
				accepted.Add(1)
			}
		}()
	}
	wg.Wait()
	if got := accepted.Load(); got != deviceLimit {
		t.Fatalf("accepted %d devices, want %d", got, deviceLimit)
	}
}

func TestRateReaderSplitsWithoutLosingData(t *testing.T) {
	payload := []byte("0123456789")
	reader := New().RateReader(context.Background(), buf.NewReader(bytes.NewReader(payload)), rate.NewLimiter(rate.Inf, 4))
	var received []byte
	var chunkSizes []int32
	for {
		mb, err := reader.ReadMultiBuffer()
		if !mb.IsEmpty() {
			chunkSizes = append(chunkSizes, mb.Len())
			chunk := make([]byte, mb.Len())
			mb.Copy(chunk)
			received = append(received, chunk...)
			buf.ReleaseMulti(mb)
		}
		if err != nil {
			if err != io.EOF {
				t.Fatal(err)
			}
			break
		}
	}
	if !bytes.Equal(received, payload) {
		t.Fatalf("rate reader changed payload: got %q want %q", received, payload)
	}
	if fmt.Sprint(chunkSizes) != "[4 4 2]" {
		t.Fatalf("unexpected rate-limited chunks: %v", chunkSizes)
	}
}

func TestUserRateBucketIsSharedAcrossConnections(t *testing.T) {
	users := []api.UserInfo{{UID: 1, Email: "user@example.com", SpeedLimit: 1024}}
	limiter := New()
	if err := limiter.AddInboundLimiter("node", 0, &users, nil); err != nil {
		t.Fatal(err)
	}
	email := "node|user@example.com|1"
	first, limited, reject := limiter.GetUserBucket("node", email, "192.0.2.1", true)
	if reject || !limited || first == nil {
		t.Fatalf("first bucket: limited=%v reject=%v bucket=%v", limited, reject, first)
	}
	second, limited, reject := limiter.GetUserBucket("node", email, "192.0.2.2", true)
	if reject || !limited || second != first {
		t.Fatalf("second connection did not share the user bucket: limited=%v reject=%v", limited, reject)
	}
}

func TestDeleteInboundLimiterClosesRedisClient(t *testing.T) {
	users := []api.UserInfo{}
	limiter := New()
	config := &GlobalDeviceLimitConfig{
		Enable:       true,
		RedisNetwork: "tcp",
		RedisAddr:    "127.0.0.1:1",
		Timeout:      1,
		Expiry:       60,
	}
	if err := limiter.AddInboundLimiter("node", 0, &users, config); err != nil {
		t.Fatal(err)
	}
	value, _ := limiter.InboundInfo.Load("node")
	client := value.(*InboundInfo).GlobalLimit.redisClient
	if err := limiter.DeleteInboundLimiter("node"); err != nil {
		t.Fatal(err)
	}
	if err := client.Ping(context.Background()).Err(); err == nil {
		t.Fatal("redis client remains usable after limiter deletion")
	}
}
