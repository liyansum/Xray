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
