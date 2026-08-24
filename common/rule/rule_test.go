package rule

import (
	"fmt"
	"regexp"
	"sync"
	"testing"
	"time"

	"github.com/liyansum/Xray/api"
)

func TestConcurrentDetectAndSnapshotDoesNotLoseResults(t *testing.T) {
	const users = 1000
	manager := New()
	if err := manager.UpdateRule("node", []api.DetectRule{{ID: 7, Pattern: regexp.MustCompile(`blocked`)}}); err != nil {
		t.Fatal(err)
	}

	collected := make(map[api.DetectResult]struct{}, users)
	var collectedMu sync.Mutex
	stop := make(chan struct{})
	reporterDone := make(chan struct{})
	go func() {
		defer close(reporterDone)
		for {
			select {
			case <-stop:
				return
			default:
				results, _ := manager.GetDetectResult("node")
				collectedMu.Lock()
				for _, result := range *results {
					collected[result] = struct{}{}
				}
				collectedMu.Unlock()
			}
		}
	}()

	var writers sync.WaitGroup
	for uid := 1; uid <= users; uid++ {
		writers.Add(1)
		go func() {
			defer writers.Done()
			manager.Detect("node", "blocked.example:443", fmt.Sprintf("node|user|%d", uid))
		}()
	}
	writers.Wait()
	close(stop)
	select {
	case <-reporterDone:
	case <-time.After(time.Second):
		t.Fatal("result reporter did not stop")
	}
	remaining, _ := manager.GetDetectResult("node")
	for _, result := range *remaining {
		collected[result] = struct{}{}
	}
	if len(collected) != users {
		t.Fatalf("collected %d results, want %d", len(collected), users)
	}
}
