package controller

import (
	"testing"

	"github.com/liyansum/Xray/api"
)

func TestCompareUserListRevokesAllUsers(t *testing.T) {
	oldUsers := []api.UserInfo{
		{UID: 1, Email: "one@example.com", UUID: "550e8400-e29b-41d4-a716-446655440000"},
		{UID: 2, Email: "two@example.com", UUID: "6ba7b810-9dad-11d1-80b4-00c04fd430c8"},
	}
	emptyUsers := []api.UserInfo{}

	deleted, added := compareUserList(&oldUsers, &emptyUsers)
	if len(deleted) != len(oldUsers) {
		t.Fatalf("deleted %d users, want %d", len(deleted), len(oldUsers))
	}
	if len(added) != 0 {
		t.Fatalf("added %d users while applying an empty snapshot", len(added))
	}
}

func TestSpeedOnlyChangesDoNotRecreateUsersOrNode(t *testing.T) {
	oldUsers := []api.UserInfo{{UID: 1, Email: "user@example.com", UUID: "original", SpeedLimit: 1, DeviceLimit: 2}}
	newUsers := append([]api.UserInfo(nil), oldUsers...)
	newUsers[0].SpeedLimit = 99999
	deleted, added := compareUserList(&oldUsers, &newUsers)
	if len(deleted) != 0 || len(added) != 0 {
		t.Fatal("speed update replaced authenticated user")
	}
	newUsers[0].DeviceLimit = 3
	deleted, added = compareUserList(&oldUsers, &newUsers)
	if len(deleted) != 1 || len(added) != 1 || added[0].SpeedLimit != 99999 {
		t.Fatal("device policy update was lost")
	}
	newUsers = append([]api.UserInfo(nil), oldUsers...)
	newUsers[0].UUID = "new-credential"
	deleted, added = compareUserList(&oldUsers, &newUsers)
	if len(deleted) != 1 || len(added) != 1 {
		t.Fatal("credential update was lost")
	}
	left := &api.NodeInfo{Port: 443, SpeedLimit: 1}
	right := &api.NodeInfo{Port: 443, SpeedLimit: 99999}
	if !sameNodeConfig(left, right) {
		t.Fatal("speed update recreated listener")
	}
	if left.SpeedLimit != 1 || right.SpeedLimit != 99999 {
		t.Fatal("comparison mutated panel snapshot")
	}
	right.Port = 8443
	if sameNodeConfig(left, right) {
		t.Fatal("listener update was lost")
	}
}
