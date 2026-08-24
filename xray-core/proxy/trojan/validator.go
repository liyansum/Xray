package trojan

import (
	"strings"
	"sync"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol"
)

// Validator stores valid trojan users.
type Validator struct {
	email sync.Map
}

// Add a trojan user, Email must be empty or unique.
func (v *Validator) Add(u *protocol.MemoryUser) error {
	if u.Email != "" {
		_, loaded := v.email.LoadOrStore(strings.ToLower(u.Email), u)
		if loaded {
			return errors.New("User ", u.Email, " already exists.")
		}
	}
	return nil
}

// Del a trojan user with a non-empty Email.
func (v *Validator) Del(e string) error {
	if e == "" {
		return errors.New("Email must not be empty.")
	}
	le := strings.ToLower(e)
	u, _ := v.email.Load(le)
	if u == nil {
		return errors.New("User ", e, " not found.")
	}
	v.email.Delete(le)
	return nil
}

// GetByEmail returns a Trojan user by its case-insensitive email.
func (v *Validator) GetByEmail(email string) *protocol.MemoryUser {
	email = strings.ToLower(email)
	u, _ := v.email.Load(email)
	if u != nil {
		return u.(*protocol.MemoryUser)
	}
	return nil
}

// Get all users
func (v *Validator) GetAll() []*protocol.MemoryUser {
	u := make([]*protocol.MemoryUser, 0, 100)
	v.email.Range(func(key, value interface{}) bool {
		u = append(u, value.(*protocol.MemoryUser))
		return true
	})
	return u
}

// Get users count
func (v *Validator) GetCount() int64 {
	var c int64 = 0
	v.email.Range(func(key, value interface{}) bool {
		c++
		return true
	})
	return c
}
