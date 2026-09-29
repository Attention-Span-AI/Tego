// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"sync"
	"time"
)

// execLineSize bounds the listener-refused execs kept for the fanotify listener to ask about (ExecLine): an exec
// the listener refuses reaches it within the exec's own open, microseconds after this loop answers.
const execLineSize = 64

// execLineTTL is how long such an exec is kept: far longer than the exec's open takes to reach the listener,
// and short enough that an entry the listener never asked about (its refusal not written) cannot stand for a
// later open.
const execLineTTL = 10 * time.Second

// execLine is one exec this loop continued at tier 2 and recorded as the fanotify listener's refusal of its
// image's open (listenerExec): the thread and the image's identity.
type execLine struct {
	tid  int
	id   fileID
	at   time.Time
	used bool
}

// execLines is a ring of them.
type execLines struct {
	mu   sync.Mutex
	ring [execLineSize]execLine
	next int
}

func (e *execLines) put(tid int, id fileID) {
	e.mu.Lock()
	e.ring[e.next] = execLine{tid: tid, id: id, at: time.Now()}
	e.next = (e.next + 1) % len(e.ring)
	e.mu.Unlock()
}

// take consumes the oldest unconsumed, unexpired entry of tid for the image id.
func (e *execLines) take(tid int, id fileID) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	now := time.Now()
	var hit *execLine
	for i := range e.ring {
		x := &e.ring[i]
		if x.used || x.tid != tid || x.id != id || now.Sub(x.at) > execLineTTL {
			continue
		}
		if hit == nil || x.at.Before(hit.at) {
			hit = x
		}
	}
	if hit == nil {
		return false
	}
	hit.used = true
	return true
}

// ExecLine reports whether a refused fanotify open by thread tid of file dev/ino is an exec's open whose line
// this loop has written: an exec it continued at tier 2 and recorded refused, read-denied, under the deny_read
// the listener refuses the image's open by (listenerExec). The exec then has this loop's exec line, which names
// its argv and identity, and the listener writes none, so the action has one line (R7a). Each exec answers one
// open. The listener asks it through enforce.SupervisorExecLines.
//
// The fanotify group requests FAN_REPORT_TID, so a sibling opening the same inode cannot consume this
// thread's entry. The exec's open occurs before execve changes the thread-group identity.
func (l *Loop) ExecLine(tid int, dev, ino uint64) bool {
	return l.execLines.take(tid, fileID{dev: dev, ino: ino})
}
