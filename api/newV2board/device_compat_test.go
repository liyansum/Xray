package newV2board

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/liyansum/Xray/api"
)

const deviceTestUUID = "550e8400-e29b-41d4-a716-446655440000"

func newDeviceTestClient(server *httptest.Server) *APIClient {
	return New(&api.Config{
		APIHost:  server.URL,
		Key:      "test-token",
		NodeID:   1,
		NodeType: "Trojan",
		Timeout:  1,
	})
}

func TestLegacyUserAliveIPSkipsAliveListEndpoint(t *testing.T) {
	var userRequests atomic.Int32
	var aliveRequests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/api/v1/server/UniProxy/user":
			requestNumber := userRequests.Add(1)
			alive := requestNumber - 1
			writer.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(writer, `{"users":[{"id":1,"uuid":%q,"speed_limit":0,"device_limit":2,"alive_ip":%d}]}`, deviceTestUUID, alive)
		case "/api/v1/server/UniProxy/alivelist":
			aliveRequests.Add(1)
			http.Error(writer, "method alivelist does not exist", http.StatusInternalServerError)
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()

	client := newDeviceTestClient(server)
	users, err := client.GetUserList()
	if err != nil || len(*users) != 1 {
		t.Fatalf("first legacy user request failed: users=%v err=%v", users, err)
	}
	if got := client.AliveMap.Alive[1]; got != 0 {
		t.Fatalf("legacy zero alive count was not preserved: %d", got)
	}

	users, err = client.GetUserList()
	if err == nil || err.Error() != api.UserNotModified || users != nil {
		t.Fatalf("alive-only legacy update rebuilt users: users=%v err=%v", users, err)
	}
	if got := client.AliveMap.Alive[1]; got != 1 {
		t.Fatalf("legacy alive count was not refreshed: %d", got)
	}
	if got := aliveRequests.Load(); got != 0 {
		t.Fatalf("legacy panel received %d unsupported alivelist requests", got)
	}
}

func TestNewPanelRefreshesAliveListOnUser304(t *testing.T) {
	var aliveRequests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/api/v1/server/UniProxy/user":
			if request.Header.Get("If-None-Match") == `"users-v1"` {
				writer.WriteHeader(http.StatusNotModified)
				return
			}
			writer.Header().Set("Content-Type", "application/json")
			writer.Header().Set("ETag", `"users-v1"`)
			fmt.Fprintf(writer, `{"users":[{"id":1,"uuid":%q,"speed_limit":0,"device_limit":2}]}`, deviceTestUUID)
		case "/api/v1/server/UniProxy/alivelist":
			count := aliveRequests.Add(1)
			writer.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(writer, `{"alive":{"1":%d}}`, count)
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()

	client := newDeviceTestClient(server)
	if _, err := client.GetUserList(); err != nil {
		t.Fatal(err)
	}
	if got := client.AliveMap.Alive[1]; got != 1 {
		t.Fatalf("first endpoint alive count = %d", got)
	}
	if _, err := client.GetUserList(); err == nil || err.Error() != api.UserNotModified {
		t.Fatalf("user 304 was not propagated: %v", err)
	}
	if got := client.AliveMap.Alive[1]; got != 2 {
		t.Fatalf("alive endpoint was not refreshed after user 304: %d", got)
	}
}

func TestAliveEndpointFailurePreservesLastSnapshot(t *testing.T) {
	var fail atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/api/v1/server/UniProxy/alivelist" {
			http.NotFound(writer, request)
			return
		}
		if fail.Load() {
			http.Error(writer, "temporary panel failure", http.StatusServiceUnavailable)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		fmt.Fprint(writer, `{"alive":{"1":2}}`)
	}))
	defer server.Close()

	client := newDeviceTestClient(server)
	if _, err := client.GetUserAlive(); err != nil {
		t.Fatal(err)
	}
	fail.Store(true)
	if _, err := client.GetUserAlive(); err == nil {
		t.Fatal("temporary endpoint failure was not reported")
	}
	if got := client.AliveMap.Alive[1]; got != 2 {
		t.Fatalf("temporary failure cleared last alive snapshot: %d", got)
	}
}

func TestInvalidPanelRuleReturnsError(t *testing.T) {
	server := httptest.NewServer(http.NotFoundHandler())
	defer server.Close()
	client := newDeviceTestClient(server)
	client.resp.Store(&serverConfig{Routes: []route{{Action: "block", Match: []string{"[invalid"}}}})
	if _, err := client.GetNodeRule(); err == nil {
		t.Fatal("invalid panel regular expression caused no error")
	}
}

func TestOnlineReportCompatibilityAndFailures(t *testing.T) {
	for _, test := range []struct {
		name       string
		statusCode int
		wantError  bool
	}{
		{name: "legacy missing endpoint", statusCode: http.StatusNotFound},
		{name: "panel server failure", statusCode: http.StatusServiceUnavailable, wantError: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				http.Error(writer, http.StatusText(test.statusCode), test.statusCode)
			}))
			defer server.Close()
			client := newDeviceTestClient(server)
			online := []api.OnlineUser{{UID: 1, IP: "192.0.2.1"}}
			err := client.ReportNodeOnlineUsers(&online)
			if (err != nil) != test.wantError {
				t.Fatalf("error=%v, wantError=%v", err, test.wantError)
			}
		})
	}
}
