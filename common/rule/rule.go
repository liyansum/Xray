// Package rule is to control the audit rule behaviors
package rule

import (
	"fmt"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/liyansum/Xray/api"
	log "github.com/sirupsen/logrus"
)

type Manager struct {
	InboundRule         *sync.Map // Key: Tag, Value: []api.DetectRule
	InboundDetectResult *sync.Map // key: Tag, value: *detectResultState
}

type detectResultState struct {
	mu      sync.Mutex
	results map[api.DetectResult]struct{}
}

func New() *Manager {
	return &Manager{
		InboundRule:         new(sync.Map),
		InboundDetectResult: new(sync.Map),
	}
}

func (r *Manager) UpdateRule(tag string, newRuleList []api.DetectRule) error {
	newRuleList = slices.Clone(newRuleList)
	if value, ok := r.InboundRule.LoadOrStore(tag, newRuleList); ok {
		oldRuleList := value.([]api.DetectRule)
		if !reflect.DeepEqual(oldRuleList, newRuleList) {
			r.InboundRule.Store(tag, newRuleList)
		}
	}
	return nil
}

func (r *Manager) RemoveRule(tag string) {
	r.InboundRule.Delete(tag)
	r.InboundDetectResult.Delete(tag)
}

func (r *Manager) GetDetectResult(tag string) (*[]api.DetectResult, error) {
	detectResult := make([]api.DetectResult, 0)
	if value, ok := r.InboundDetectResult.Load(tag); ok {
		state := value.(*detectResultState)
		state.mu.Lock()
		detectResult = make([]api.DetectResult, 0, len(state.results))
		for result := range state.results {
			detectResult = append(detectResult, result)
		}
		clear(state.results)
		state.mu.Unlock()
	}
	return &detectResult, nil
}

func (r *Manager) Detect(tag string, destination string, email string) (reject bool) {
	reject = false
	var hitRuleID = -1
	// If we have some rule for this inbound
	if value, ok := r.InboundRule.Load(tag); ok {
		ruleList := value.([]api.DetectRule)
		for _, r := range ruleList {
			if r.Pattern.Match([]byte(destination)) {
				hitRuleID = r.ID
				reject = true
				break
			}
		}
		// If we hit some rule
		if reject && hitRuleID != -1 {
			l := strings.Split(email, "|")
			uid, err := strconv.Atoi(l[len(l)-1])
			if err != nil {
				log.Debug(fmt.Sprintf("Record illegal behavior failed! Cannot find user's uid: %s", email))
				return reject
			}
			newState := &detectResultState{results: make(map[api.DetectResult]struct{})}
			value, _ := r.InboundDetectResult.LoadOrStore(tag, newState)
			state := value.(*detectResultState)
			state.mu.Lock()
			state.results[api.DetectResult{UID: uid, RuleID: hitRuleID}] = struct{}{}
			state.mu.Unlock()
		}
	}
	return reject
}
