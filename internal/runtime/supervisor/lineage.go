// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"strconv"
	"strings"
	"sync"
)

const (
	// lineageDepth bounds the identities a refused line carries: the refused process and its ancestors, nearest first.
	// A harness sits a handful of processes above a tool call; the run's first processes above it add nothing.
	lineageDepth = 16
	// lineageCacheSize bounds lineageCache, which caches by process (first in, first out).
	lineageCacheSize = 1024
)

// lineageCache remembers each refused process's lineage with the start time it was read for, so a flood of refusals
// from one process walks /proc once and then revalidates with one stat read.
type lineageCache struct {
	mu    sync.Mutex
	m     map[int]lineageEntry
	order []int
}

type lineageEntry struct {
	start uint64
	s     string
}

// lineageOf is the owners string of the refused process pid (record.Event.Lineage): "pid:start,pid:start" for it
// and each ancestor up to a process 1, an unreadable one or lineageDepth entries, the start time in clock ticks as
// /proc/<pid>/stat gives it (a pid alone could be reused). It is empty when pid itself cannot be read (the process
// is gone): the line is then unowned, and the reason channel tells it to any session's hook, as before ownership
// existed. Only refused lines ask for it, and the reason file (ADR 0063) is the one place it is written.
func (l *Loop) lineageOf(pid int) string {
	if pid <= 1 {
		return ""
	}
	_, start, err := l.k.ProcStat(pid)
	if err != nil {
		return ""
	}
	c := &l.lineages
	c.mu.Lock()
	e, ok := c.m[pid]
	c.mu.Unlock()
	if ok && e.start == start {
		return e.s
	}
	var b strings.Builder
	for cur, st, n := pid, start, 0; n < lineageDepth; n++ {
		if n > 0 {
			b.WriteByte(',')
		}
		b.WriteString(strconv.Itoa(cur))
		b.WriteByte(':')
		b.WriteString(strconv.FormatUint(st, 10))
		ppid, _, err := l.k.ProcStat(cur)
		if err != nil || ppid <= 1 {
			break
		}
		_, pst, err := l.k.ProcStat(ppid)
		if err != nil {
			break
		}
		cur, st = ppid, pst
	}
	s := b.String()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m == nil {
		c.m = make(map[int]lineageEntry, lineageCacheSize)
	}
	if _, ok := c.m[pid]; !ok {
		if len(c.order) >= lineageCacheSize {
			delete(c.m, c.order[0])
			c.order = c.order[1:]
		}
		c.order = append(c.order, pid)
	}
	c.m[pid] = lineageEntry{start, s}
	return s
}
