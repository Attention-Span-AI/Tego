// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"fmt"
	"net/netip"
	"slices"
	"time"

	"github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"golang.org/x/sys/unix"
)

type TimelineRow struct {
	Key bpf.NetTimelineKey
	Val bpf.NetTimeline
}

type deadlineClock struct {
	wall    time.Time
	mono    uint64
	dynamic bool
}

func newDeadlineClock(rules []agent.NetRule) (deadlineClock, error) {
	for _, r := range rules {
		if !r.ExpiresAt.IsZero() {
			var ts unix.Timespec
			wall := time.Now()
			if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
				return deadlineClock{}, fmt.Errorf("network expiry clock: %w", err)
			}
			return deadlineClock{wall: wall, mono: uint64(ts.Nano()), dynamic: true}, nil
		}
	}
	return deadlineClock{}, nil
}

func (c deadlineClock) deadline(at time.Time) uint64 {
	d := at.Sub(c.wall)
	if d <= 0 {
		return c.mono
	}
	if uint64(d) > ^uint64(0)-c.mono {
		return ^uint64(0)
	}
	return c.mono + uint64(d)
}

// timelineVerdict composes all covering declarations at every effective expiry.
// A static overlap stays usable immediately after an earlier hostname expires;
// a refusal keeps precedence until its own deadline. The final interval remains
// explicit, including refusal when all grants have expired.
func (c *netCover) timelineVerdict(proto uint8, port uint16, target netip.Prefix, exact bool, clock deadlineClock) (bpf.NetVerdict, bpf.NetTimeline, error) {
	var chain bpf.NetTimeline
	if !clock.dynamic {
		return c.verdict(proto, port, target, exact), chain, nil
	}
	var indexes []int
	if exact {
		indexes = append(indexes, c.allExact[coverKey{proto: proto, port: port, pfx: target}]...)
	}
	for _, bits := range c.bits[coverKey{proto: proto, port: port}] {
		if bits > target.Bits() {
			continue
		}
		prefix, err := target.Addr().Prefix(bits)
		if err == nil {
			indexes = append(indexes, c.allCIDR[coverKey{proto: proto, port: port, pfx: prefix}]...)
		}
	}
	slices.Sort(indexes)
	indexes = slices.Compact(indexes)
	var expiries []time.Time
	for _, index := range indexes {
		e := c.net[index].ExpiresAt
		if !e.IsZero() && e.After(clock.wall) {
			expiries = append(expiries, e)
		}
	}
	slices.SortFunc(expiries, func(a, b time.Time) int { return a.Compare(b) })
	expiries = slices.CompactFunc(expiries, func(a, b time.Time) bool { return a.Equal(b) })
	choose := func(at time.Time) bpf.NetVerdict {
		first := -1
		for _, index := range indexes {
			r := c.net[index]
			if !r.ExpiresAt.IsZero() && !at.Before(r.ExpiresAt) {
				continue
			}
			if r.Verdict != agent.VerdictAllow {
				return verdictOf(r.Verdict, uint16(index+1))
			}
			if first < 0 {
				first = index
			}
		}
		if first < 0 {
			return verdictOf(agent.VerdictRefused, 0)
		}
		return verdictOf(c.net[first].Verdict, uint16(first+1))
	}
	current := choose(clock.wall)
	first := current
	appendStep := func(value bpf.NetVerdict, deadline uint64) error {
		if chain.Count >= bpf.MaxNetIntervals {
			return fmt.Errorf("%w: network destination %s:%d has more than %d composed expiry intervals", ErrMapFull, target, port, bpf.MaxNetIntervals)
		}
		chain.Steps[chain.Count] = bpf.NetDecision{Verdict: value.Verdict, Reason: value.Reason, RuleIdx: value.RuleIdx, DeadlineNS: deadline}
		chain.Count++
		return nil
	}
	for _, expiry := range expiries {
		next := choose(expiry)
		if next == current {
			continue
		}
		if err := appendStep(current, clock.deadline(expiry)); err != nil {
			return first, chain, err
		}
		current = next
	}
	if chain.Count == 0 {
		return current, bpf.NetTimeline{}, nil
	}
	if err := appendStep(current, 0); err != nil {
		return first, chain, err
	}
	first.DeadlineNS = chain.Steps[0].DeadlineNS
	return first, chain, nil
}

func (k *bpfKernel) populateTimelines(rows []TimelineRow) error {
	if len(rows) == 0 {
		return nil
	}
	m := k.maps[bpf.MapNetTimeline]
	if m == nil {
		return fmt.Errorf("%w: network expiry timeline map missing", ErrProgramLoad)
	}
	for _, row := range rows {
		if err := m.Put(&row.Key, &row.Val); err != nil {
			return mapFull(bpf.MapNetTimeline, err)
		}
	}
	return nil
}

func rebaseTimelines(rows *RuleMaps, next *uint32) error {
	if uint64(*next)+uint64(len(rows.Timelines)) > uint64(^uint32(0)) {
		return fmt.Errorf("%w: network expiry revision ids exhausted", ErrMapFull)
	}
	offset := *next
	for i := range rows.Timelines {
		rows.Timelines[i].Key.Index += offset
	}
	for i := range rows.Exact {
		if rows.Exact[i].Val.Timeline != 0 {
			rows.Exact[i].Val.Timeline += offset
		}
	}
	for i := range rows.CIDR {
		if rows.CIDR[i].Val.Timeline != 0 {
			rows.CIDR[i].Val.Timeline += offset
		}
	}
	*next += uint32(len(rows.Timelines))
	return nil
}
