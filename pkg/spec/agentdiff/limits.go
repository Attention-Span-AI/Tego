// SPDX-License-Identifier: Apache-2.0

package agentdiff

import (
	"fmt"
	"reflect"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// bound compares a resource ceiling. Nil is the universe; explicit zero allows
// none. A mixed change still reports every newly increased resource.
func bound[T ~uint64 | ~int64 | ~int | ~float64](name string, a, b *T, added, removed *[]string) {
	if a == nil && b == nil {
		return
	}
	if b == nil {
		*added = append(*added, name+": no limit")
		return
	}
	if a == nil {
		*removed = append(*removed, name)
		return
	}
	if *b > *a {
		*added = append(*added, fmt.Sprintf("%s: %v (was %v)", name, *b, *a))
	}
	if *b < *a {
		*removed = append(*removed, name)
	}
}

func netLimits(a, b *agent.RuleTable) Result {
	var added, removed []string
	bound("Network connections", a.NetLimits.Connections, b.NetLimits.Connections, &added, &removed)
	bound("Pending connections", a.NetLimits.PendingConnects, b.NetLimits.PendingConnects, &added, &removed)
	bound("Network bytes", a.NetLimits.Bytes, b.NetLimits.Bytes, &added, &removed)
	bound("Datagrams per second", a.NetLimits.DatagramsPerSecond, b.NetLimits.DatagramsPerSecond, &added, &removed)
	return order(added, removed)
}

func limits(a, b *agent.RuleTable) Result {
	// Simple changes wall only. Every other changed resource remains visible
	// as CannotClassify until its units and order are added to the matrix.
	x, y := a.Limits, b.Limits
	x.Wall, y.Wall = 0, 0
	x.Set &^= agent.BudgetWall
	y.Set &^= agent.BudgetWall
	if !reflect.DeepEqual(x, y) {
		return unknown()
	}
	var av, bv *agent.Duration
	if a.Limits.Bounded(agent.BudgetWall) {
		v := agent.Duration(a.Limits.Wall)
		av = &v
	}
	if b.Limits.Bounded(agent.BudgetWall) {
		v := agent.Duration(b.Limits.Wall)
		bv = &v
	}
	var added, removed []string
	bound("Run duration", av, bv, &added, &removed)
	return order(added, removed)
}

func askConfig(a, b *agent.RuleTable) Result {
	x, y := a.AskConfig, b.AskConfig
	if reflect.DeepEqual(x, y) {
		return Result{Direction: Unchanged}
	}
	// No broker means no opportunity to request an approval. Valid compiled
	// tables have a broker for every held scope. Hold modes constrain
	// different operations and cannot be ordered by duration alone.
	if x == nil {
		return Result{Direction: Widened, NewlyAllowed: []string{"Request approval for held operations"}}
	}
	if y == nil {
		return Result{Direction: Narrowed}
	}
	if x.Hold != y.Hold {
		return unknown()
	}
	valid := func(v agent.AskOnTimeout) bool {
		return v == agent.AskOnTimeoutRefuse || v == agent.AskOnTimeoutRefuseAlways
	}
	if !valid(x.OnTimeout) || !valid(y.OnTimeout) {
		return unknown()
	}
	var added, removed []string
	xp, yp := int64(x.MaxPending), int64(y.MaxPending)
	if xp == 0 {
		xp = 64
	}
	if yp == 0 {
		yp = 64
	}
	bound("Pending approval requests", &xp, &yp, &added, &removed)
	// Zero is the broker's default timeout (five minutes), not unbounded.
	xt, yt := x.Timeout, y.Timeout
	if xt == 0 {
		xt = 5 * 60 * 1e9
	}
	if yt == 0 {
		yt = 5 * 60 * 1e9
	}
	bound("Approval response time", &xt, &yt, &added, &removed)
	if x.OnTimeout != y.OnTimeout {
		if y.OnTimeout == agent.AskOnTimeoutRefuse {
			added = append(added, "Retry an approval request after its timeout instead of keeping a standing refusal")
		} else {
			removed = append(removed, "approval retries after timeout")
		}
	}
	return order(added, removed)
}
