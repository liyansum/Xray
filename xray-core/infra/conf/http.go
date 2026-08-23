package conf

import (
	"github.com/xtls/xray-core/proxy/http"
	"google.golang.org/protobuf/proto"
)

type HTTPAccount struct {
	Username string `json:"user"`
	Password string `json:"pass"`
}

type HTTPServerConfig struct {
	Users       []*HTTPAccount `json:"users"`
	Accounts    []*HTTPAccount `json:"accounts"`
	Transparent bool           `json:"allowTransparent"`
	UserLevel   uint32         `json:"userLevel"`
}

func (c *HTTPServerConfig) Build() (proto.Message, error) {
	config := &http.ServerConfig{
		AllowTransparent: c.Transparent,
		UserLevel:        c.UserLevel,
	}

	if c.Accounts != nil {
		c.Users = c.Accounts
	}
	// TODO: PB
	if len(c.Users) > 0 {
		config.Accounts = make(map[string]string)
		for _, account := range c.Users {
			config.Accounts[account.Username] = account.Password
		}
	}

	return config, nil
}
