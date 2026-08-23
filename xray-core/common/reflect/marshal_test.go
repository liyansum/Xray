package reflect_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/xtls/xray-core/common/protocol"
	. "github.com/xtls/xray-core/common/reflect"
	cserial "github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/proxy/shadowsocks"
)

func TestMashalAccount(t *testing.T) {
	account := &shadowsocks.Account{
		Password:   "shadowsocks-password",
		CipherType: shadowsocks.CipherType_CHACHA20_POLY1305,
	}

	user := &protocol.User{
		Level:   0,
		Email:   "love@v2ray.com",
		Account: cserial.ToTypedMessage(account),
	}

	j, ok := MarshalToJson(user, false)
	if !ok || strings.Contains(j, "_TypedMessage_") {
		t.Error("marshal account failed")
	}

	kws := []string{"CHACHA20_POLY1305", "cipherType", "shadowsocks-password"}
	for _, kw := range kws {
		if !strings.Contains(j, kw) {
			t.Error("marshal account failed")
		}
	}
}

func TestMashalStruct(t *testing.T) {
	type Foo = struct {
		N   int                             `json:"n"`
		Np  *int                            `json:"np"`
		S   string                          `json:"s"`
		Arr *[]map[string]map[string]string `json:"arr"`
	}

	n := 1
	np := &n
	arr := make([]map[string]map[string]string, 0)
	m1 := make(map[string]map[string]string, 0)
	m2 := make(map[string]string, 0)
	m2["hello"] = "world"
	m1["foo"] = m2
	arr = append(arr, m1)

	f1 := Foo{N: n, Np: np, S: "hello", Arr: &arr}
	s, ok1 := MarshalToJson(f1, true)
	sp, ok2 := MarshalToJson(&f1, true)
	if !ok1 || !ok2 || s != sp {
		t.Error("marshal failed")
	}

	f2 := Foo{}
	if json.Unmarshal([]byte(s), &f2) != nil {
		t.Error("json unmarshal failed")
	}

	v := (*f2.Arr)[0]["foo"]["hello"]
	if f1.N != f2.N || *f1.Np != *f2.Np || f1.S != f2.S || v != "world" {
		t.Error("f1 not equal to f2")
	}
}
