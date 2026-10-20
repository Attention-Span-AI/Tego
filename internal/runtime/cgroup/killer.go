// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"errors"
	"fmt"
)

// Killer is the production launch.Killer: one write of "1" to the run cgroup's cgroup.kill through the
// Manager, the escalation target of stop_grace (runtime-launch.md R9). Delivery is asynchronous; the caller
// observes completion through the child's wait or cgroup.events. It lives here rather than in launch so that
// launch, which starts the agent's first process, links no cgroup manager and no policy type (ADR 0031 (a)).
type Killer struct {
	Manager Manager
	Cgroup  Cgroup
}

// Kill writes cgroup.kill.
func (k Killer) Kill() error {
	if k.Manager == nil {
		return errors.New("cgroup: Killer without a Manager")
	}
	if err := k.Manager.Kill(k.Cgroup); err != nil {
		return fmt.Errorf("cgroup.kill %s: %w", k.Cgroup.Path, err)
	}
	return nil
}
