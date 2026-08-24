package controller

import (
	"testing"

	"github.com/liyansum/Xray/api"
)

func TestBuildSSUserSkipsInvalid2022KeysWithoutNilEntries(t *testing.T) {
	controller := &Controller{Tag: "node", panelType: "NewV2board"}
	users := []api.UserInfo{
		{UID: 1, Email: "invalid@example.com", Passwd: "short"},
		{UID: 2, Email: "valid@example.com", Passwd: "0123456789abcdef"},
	}
	built := controller.buildSSUser(&users, "2022-blake3-aes-128-gcm")
	if len(built) != 1 || built[0] == nil || built[0].Email != "node|valid@example.com|2" {
		t.Fatalf("unexpected built users: %#v", built)
	}
}
