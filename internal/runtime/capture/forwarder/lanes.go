// SPDX-License-Identifier: Apache-2.0

package forwarder

import "sync"

// maxLaneMemory bounds how many exchanges' lanes are remembered for a retry to find its original's by.
const maxLaneMemory = 256

// laneKey is one lane of one peer process.
type laneKey struct {
	pid  int
	lane uint64
}

// lanes numbers the model turns each peer process has in flight at once, and is what the forwarder keys a
// turn's thread by (record.Event.Lane, derive.Thread; R34).
//
// The forwarder knows the process behind a connection (R19a's admission resolves it) and no thread: a loopback
// socket belongs to a process's descriptor table, not to the thread that wrote on it. Its lines carried the
// launcher's own pid and tid, stamped by the pipeline, so every turn of the run was one thread to derive, two
// concurrent turns — two subagents, two worker threads — had one open step between them, and an action while
// both were in flight was attributed "likely" where capture-derive R34 says more than one candidate is
// unattributed. Keyed by the peer process alone, two turns of two processes are apart and two of one process
// are still one.
//
// A lane is a concurrency slot of one process: a turn takes the lowest lane of its process with no turn in
// flight and gives it back when its response has been recorded. Two turns in flight at once are two lanes, so
// two threads to derive, which is what keying by connection is for: HTTP/1.1 carries one exchange at a time on
// a connection. Sequential turns take the same lane whichever connection they come on, and so continue one
// thread: an SDK's pool opens a new connection whenever a keep-alive one has expired (httpx's after 5 s idle),
// and a thread per connection would have made every such turn a new thread, and every action between turns of
// a single-threaded agent unattributed. A retry takes the lane of the turn it repeats when that lane is free,
// so it extends that turn's step (R23, R33) rather than another's.
//
// One lanes is shared by a run's listeners (NewManager), so a process's turns to two providers at once are
// two lanes too.
type lanes struct {
	mu   sync.Mutex
	busy map[laneKey]bool
	// held remembers the lane each recent exchange took, by exchange id, for a retry to find; order bounds it
	// at maxLaneMemory, oldest first.
	held  map[string]laneKey
	order []string
}

func newLanes() *lanes {
	return &lanes{busy: map[laneKey]bool{}, held: map[string]laneKey{}}
}

// acquire gives exchange id of process pid a lane: the lane of the exchange retryOf names when it is that
// process's and free, else the process's lowest free lane, from 1.
func (l *lanes) acquire(pid int, id, retryOf string) uint64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	lane := uint64(0)
	if k, ok := l.held[retryOf]; ok && retryOf != "" && k.pid == pid && !l.busy[k] {
		lane = k.lane
	}
	if lane == 0 {
		lane = 1
		for l.busy[laneKey{pid, lane}] {
			lane++
		}
	}
	k := laneKey{pid, lane}
	l.busy[k] = true
	l.held[id] = k
	l.order = append(l.order, id)
	for len(l.order) > maxLaneMemory {
		delete(l.held, l.order[0])
		l.order = l.order[1:]
	}
	return lane
}

// release gives a lane back once its exchange has been recorded.
func (l *lanes) release(pid int, lane uint64) {
	if lane == 0 {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.busy, laneKey{pid, lane})
}
