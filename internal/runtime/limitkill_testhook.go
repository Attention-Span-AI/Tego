// SPDX-License-Identifier: Apache-2.0

//go:build tegotesthooks

package runtime

import (
	"os"
	"time"

	"github.com/attention-span-ai/tego/internal/runtime/cgroup"
	"github.com/attention-span-ai/tego/internal/runtime/limits"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// lateKiller writes the kill lag after the watcher asked for it. The watcher's own goroutine is not held, as a slow kernel
// would not hold it: the write simply lands late.
type lateKiller struct {
	inner limits.Killer
	lag   time.Duration
}

func (k lateKiller) Kill(c cgroup.Cgroup) error {
	time.AfterFunc(k.lag, func() { _ = k.inner.Kill(c) }) // the run may be gone by then: nothing is left to end
	return nil
}

func init() {
	// Never under AT_SECURE, where no environment variable may steer the capability-bearing binary.
	if secure, err := config.DetectSecureExec(); err != nil || secure {
		return
	}
	lag, err := time.ParseDuration(os.Getenv(EnvTestLimitKillLag))
	if err != nil || lag <= 0 {
		return
	}
	limitKiller = func(k limits.Killer) limits.Killer {
		if k == nil {
			return nil
		}
		return lateKiller{inner: k, lag: lag}
	}
}
