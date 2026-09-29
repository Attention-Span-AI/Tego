// SPDX-License-Identifier: Apache-2.0

//go:build integration

package uprobe

import (
	"fmt"
	"sync"
	"testing"
)

// TestConcurrentFirstLoadsOfTheCaptureObjectAllSucceed: the first runs of a build that start capturing together
// each load the capture object, and all of them get it. cilium/ebpf opens a pinned map and creates and pins one
// that is not; one load could pin a name between another's lookup and its pin, whose pin then failed with EEXIST,
// and that run was refused [capture-unavailable] (TestTier2ConcurrentRunsOfOneBuild's round of 2, on a starved
// guest). Each round starts from a build with no capture map pinned.
func TestConcurrentFirstLoadsOfTheCaptureObjectAllSucceed(t *testing.T) {
	requireObjects(t)
	requireRoot(t)
	const loads, rounds = 8, 6
	for round := range rounds {
		hash := fmt.Sprintf("firstload%d", round)
		root, _ := bpffsPinRoot(t, hash)
		var (
			wg   sync.WaitGroup
			mu   sync.Mutex
			errs []error
		)
		start := make(chan struct{})
		for range loads {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				coll, err := LoadCollection(root, hash)
				if err != nil {
					mu.Lock()
					errs = append(errs, err)
					mu.Unlock()
					return
				}
				coll.Close()
			}()
		}
		close(start)
		wg.Wait()
		for _, err := range errs {
			t.Errorf("round %d: a first load of the build's capture object failed: %v", round, err)
		}
	}
}
