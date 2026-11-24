// SPDX-License-Identifier: Apache-2.0

package testutil

import (
	"os"
	"path/filepath"
	"sync"
	"time"
)

// StalledDisk is how long a small durable write may take for a disk to count as stalled: a second, where this host's
// takes a few milliseconds (a stall of 18.8 s was measured on a 98 percent full disk under other jobs' writes).
const StalledDisk = time.Second

// DurableWrite is one small durable write in dir: a file written, synced and renamed, and the directory synced. It is
// the kind of write a Save makes (write, fsync, rename), which a disk whose journal commits stall holds in the kernel
// for as long as the stall lasts, whatever the CPU priorities are.
func DurableWrite(dir string) error {
	name := filepath.Join(dir, "probe")
	f, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	_, err = f.Write(make([]byte, 4096))
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if err := os.Rename(name, name+".done"); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }()
	return d.Sync()
}

// ProbeDurableWrites makes write in dir over and over, ten times a second, until the returned function is called, which
// stops it and returns the longest one took (the longest still running counts as far as it has run, and is not waited
// for). A test whose own durable write missed a deadline asks it whether the disk stalled beside it: an independent
// measurement of the host, like a quiet-host check, never a reason to pass a test whose disk was quiet. dir must be
// in the same filesystem as the write under test, and must not be a directory the test lists.
func ProbeDurableWrites(dir string, write func(dir string) error) (end func() time.Duration) {
	var (
		mu      sync.Mutex
		worst   time.Duration
		current time.Time
		done    = make(chan struct{})
	)
	go func() {
		for {
			mu.Lock()
			current = time.Now()
			mu.Unlock()
			_ = write(dir)
			mu.Lock()
			worst = max(worst, time.Since(current))
			current = time.Time{}
			mu.Unlock()
			select {
			case <-done:
				return
			case <-time.After(100 * time.Millisecond):
			}
		}
	}()
	return func() time.Duration {
		close(done)
		mu.Lock()
		defer mu.Unlock()
		longest := worst
		if !current.IsZero() {
			longest = max(longest, time.Since(current))
		}
		return longest
	}
}
