// SPDX-License-Identifier: Apache-2.0

package forwarder

import (
	"io"
	"runtime"
	"sync/atomic"
	"time"
)

// DefaultMaxCaptureBytes is how much every array capture holds may add up to between them: room for
// eight MaxBody-sized arrays at the default MaxBody, and a full-size request with its event's copy is two
// of them. Past it capture keeps less of a body rather than the process keeping more.
const DefaultMaxCaptureBytes = 64 << 20

// exchangeBuffers is the budget's floor, in MaxBody-sized arrays. At its largest one exchange holds four:
// its request and the request event's copy of it, and then either its response as it came off the wire
// with the decoded form being read out of it, or that decoded form with the response event's copy. The
// fifth is headroom for the two things that push an exchange past four bodies' worth: a buffer that grows
// holds its old array and its new one while it copies from one to the other, and an event's copy is its
// body's JSON encoding, which escaping makes a little larger than text itself.
const exchangeBuffers = 5

// collectSpacing is the least time between two collections a take short of its need asks for
// (collectSoon).
const collectSpacing = 100 * time.Millisecond

// budgetEpoch anchors collectSoon's clock; time.Since reads the monotonic clock, which never steps.
var budgetEpoch = time.Now()

// budget bounds the bytes capture holds in the launcher's heap: every request body, response body,
// decoded form and event copy of a body, counted by the capacity of the array that holds it (§3).
//
// One body is bounded by MaxBody, but how many are in flight at once is not: net/http serves every
// accepted connection in its own goroutine, and R38 makes this listener the agent's only route to the
// model, so the agent chooses both multiplicands of that product. Only the child is cloned into the run's
// cgroup (docs/p0/runtime-launch.md §6 step 6), so limits.memory bounds the agent and never the launcher
// holding these buffers: without a bound here an agent stays comfortably inside its own memory ceiling
// while the process that owns the supervisor's notify loop and the ledger writer is OOM-killed, which
// takes enforcement and the record down with it.
//
// Exhaustion degrades the record, never the agent's call: capture is best-effort against that call (§7),
// and a body kept short is reported as gap why=size-cap, which I4 requires and R14/R29 already give a
// meaning to. It counts the capacity capture asks make for, not what Go's allocator rounds that up to.
type budget struct {
	limit int64
	used  atomic.Int64
	// awaiting is the part of used that event copies hold (holdWhileReachable): bytes that go back when
	// the collector finds the copy unreachable, not at any point this package can name.
	awaiting atomic.Int64
	// lastCollect is when collectSoon last started a collection, as time since budgetEpoch.
	lastCollect atomic.Int64
}

// newBudget sizes one run's budget. The floor is one exchange at its largest (exchangeBuffers), so
// whatever MaxBody is raised to, a lone exchange of text keeps its bodies and its events' copies of them,
// and no configuration can turn capture into nothing by arithmetic. Lone means nothing else is counted:
// no other exchange in flight, and no earlier event's copy still waiting for the collector to find it
// unreachable (collectSoon asks for that collection when a take comes up short of what it needs).
func newBudget(limit, maxBody int) *budget {
	if limit <= 0 {
		limit = DefaultMaxCaptureBytes
	}
	if limit < exchangeBuffers*maxBody {
		limit = exchangeBuffers * maxBody
	}
	return &budget{limit: int64(limit)}
}

// take reserves up to want bytes and reports how many it granted. It grants what is left rather than
// refusing, so a small body still lands whole under pressure.
//
// need is how much of the grant the caller cannot do without, and only a grant short of it asks for a
// collection (collectSoon). Short of need, the caller stops keeping bytes: a write keeps less than the
// bytes in hand and its body is recorded truncated, an event's copy is cut, and a read of unknown length
// is left with no room, so the rest of its body is lost unless the body happens to end right there. A
// grant short of want alone stops nothing: held.grow asks for twice its capacity to spare later copies, a
// read asks for a chunk of room whose size is a guess, a declared length is reserved ahead of the bytes
// that fill it, and held.fit asks for a trimmed copy and keeps its headroom when it gets less. Starting a
// collection for those would spend the launcher's CPU for no byte of the record.
func (b *budget) take(want, need int) int {
	if want <= 0 {
		return 0
	}
	for {
		used := b.used.Load()
		room := min(b.limit-used, int64(want))
		if room <= 0 {
			if need > 0 {
				b.collectSoon()
			}
			return 0
		}
		if b.used.CompareAndSwap(used, used+room) {
			if room < int64(need) {
				b.collectSoon()
			}
			return int(room)
		}
	}
}

// give returns bytes to the budget.
//
// Listener.derive is where a recorded exchange's buffers go back: claim() and Close's taking of the
// in-flight set let exactly one of finish and Close derive each tracked exchange, and derive returns
// what its request and its response held. Every other caller returns an array derive will never see:
//   - held.growFor, which grow and fill go through, and held.fit: the array a buffer was copied out of,
//     and a grant too small to copy into;
//   - held.drop, which gives back a buffer's whole array: from readRequest, for the request of a body
//     that could not be read or an exchange id that could not be drawn, since no exchange is returned to
//     carry it; from Listener.relay, for the compressed bytes a decode replaced; from decodeWith, for a
//     decode that kept nothing; and from held.fit itself, for a buffer that ended empty;
//   - forward: the request body of an exchange whose outbound leg could not be built, which is never
//     tracked and so never derived;
//   - finish: the response buffer a handler built after Close had already claimed its exchange and
//     derived it without one;
//   - encodePayload: the part of a grant an event's copy did not use, and release, for the copy itself
//     once the collector has found it unreachable;
//   - holdWhileReachable: a reservation for an array with no backing store, which gives the collector
//     nothing to watch. encodePayload, its one caller, never makes one: its copy always holds at least
//     the payload object's braces.
//
// A reservation with no give on its path is not a slow leak — it is capture switched off for the rest
// of the run (§3).
func (b *budget) give(n int) {
	if n > 0 {
		b.used.Add(-int64(n))
	}
}

// holdWhileReachable keeps n bytes of the budget, already taken, reserved for as long as the array under
// buf is reachable, and gives them back once the collector has found that it is not.
//
// It is for an event's copy of a body. The copy leaves this package inside the event and sits in the run
// queue (runtime.QueueCapacity deep) until the single ledger writer reaches it, and nothing tells the
// producer when that has happened: source.Sink has Emit and nothing else. Giving the bytes back when the
// exchange is derived would count them for the moment they are made and not for the time the queue holds
// them, and a writer that falls behind would then hold as many body copies as the queue has slots, which
// no budget bounds. Reachability is the one signal that is both available here and true.
func (b *budget) holdWhileReachable(buf []byte, n int) {
	if n <= 0 {
		return
	}
	if cap(buf) == 0 {
		b.give(n)
		return
	}
	b.awaiting.Add(int64(n))
	runtime.AddCleanup(&buf[:1][0], b.release, n)
}

// release is the cleanup holdWhileReachable attaches: the copy it counted is unreachable, so its bytes
// go back.
func (b *budget) release(n int) {
	b.awaiting.Add(-int64(n))
	b.give(n)
}

// collectSoon starts a collection when some of what the budget counts is waiting on one: a take that
// comes up short of its need while event copies are counted may be short only because the collector has
// not yet looked at copies the writer is done with. Left to the collector's own pacing, that look can be a
// long time coming, since a capture the budget refuses stops allocating the very buffers that pacing
// counts. At most one collection per collectSpacing is asked for, so an agent that keeps the budget full
// of copies the writer has not reached yet cannot keep the launcher collecting back to back. The caller's
// own take is not held up: it keeps what it was granted, and the collection frees room for later ones.
func (b *budget) collectSoon() {
	if b.awaiting.Load() <= 0 {
		return
	}
	now := int64(time.Since(budgetEpoch))
	last := b.lastCollect.Load()
	if last != 0 && now-last < int64(collectSpacing) {
		return
	}
	if b.lastCollect.CompareAndSwap(last, now) {
		go runtime.GC()
	}
}

// hold starts a buffer that may keep up to limit bytes, every array of it reserved from b.
func (b *budget) hold(limit int) *held {
	return &held{b: b, limit: max(limit, 0)}
}

// held is a byte buffer whose whole backing array is reserved from the budget: its capacity, not its
// length, since the array is what the heap holds however much of it is filled (§3). The reservation is
// cap(buf) at every point outside growFor and fit, and inside them it also covers the array being copied
// out of, because that one is live until the copy ends.
type held struct {
	b     *budget
	buf   []byte
	limit int
}

// bytes is what the buffer has kept.
func (h *held) bytes() []byte { return h.buf }

// reserved is what the buffer holds of the budget, which is its array's capacity.
func (h *held) reserved() int { return cap(h.buf) }

// grow makes room for n more bytes as far as the limit and the budget allow, and reports how much room
// there now is, which may be less than n or none at all. All n are bytes the caller has in hand.
func (h *held) grow(n int) int { return h.growFor(n, n) }

// growFor is grow for a caller that may do with less room than it asks for: least is the room below which
// it stops keeping bytes, 1 for a read that takes whatever room there is, 0 for room reserved ahead of
// bytes that have not arrived.
func (h *held) growFor(n, least int) int {
	want := min(len(h.buf)+n, h.limit)
	if want > cap(h.buf) {
		// Doubling keeps a body that arrives in small pieces from being copied once per piece.
		size := min(max(want, 2*cap(h.buf)), h.limit)
		// The array the caller cannot do without. When the one it has already covers that, a short
		// grant costs it nothing: the old array is kept.
		need := min(len(h.buf)+least, h.limit)
		if need <= cap(h.buf) {
			need = 0
		}
		// The new array is reserved in full before it exists and the old one goes back only once
		// the copy is done, so the moment both are live is counted too.
		got := h.b.take(size, need)
		if got > cap(h.buf) {
			next := make([]byte, len(h.buf), got)
			copy(next, h.buf)
			h.b.give(cap(h.buf))
			h.buf = next
		} else {
			h.b.give(got)
		}
	}
	return min(cap(h.buf), h.limit) - len(h.buf)
}

// write keeps as much of p as the buffer can make room for and reports how much that was.
func (h *held) write(p []byte) int {
	n := min(len(p), h.grow(len(p)))
	h.buf = append(h.buf, p[:n]...)
	return n
}

// fill reads r into the buffer until r ends, the limit is reached or the budget stops the buffer growing,
// asking for chunk bytes of room at a time. extra is nil when r ended inside what was kept; otherwise it
// is the one byte read past it to find out, which a caller forwarding the rest puts back in front of r.
// That probe never enters the buffer: a body ending exactly at the limit is not cut short, and a body
// past it costs one byte more than the limit, not a larger array.
//
// chunk is a guess, since how much r holds is not known, so fill does with any room at all: only a grant
// that leaves none stops it, and only that one asks the budget for a collection.
func (h *held) fill(r io.Reader, chunk int) (extra []byte, err error) {
	for {
		// The array in hand is filled before a larger one is asked for: a body that has sent one byte of
		// a chunk's room holds that room and not twice it (R27).
		room := min(cap(h.buf), h.limit) - len(h.buf)
		if room <= 0 {
			room = h.growFor(chunk, 1)
		}
		if room == 0 {
			probe := make([]byte, 1)
			n, err := io.ReadFull(r, probe)
			switch {
			case n == 1:
				return probe, nil
			case err == io.EOF:
				return nil, nil
			default:
				return nil, err
			}
		}
		n, err := r.Read(h.buf[len(h.buf) : len(h.buf)+room])
		h.buf = h.buf[:len(h.buf)+n]
		if err == io.EOF {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
	}
}

// fit trims the array to the length the buffer ended at, so what an exchange holds until it is derived
// is its bytes and not the headroom doubling left. The copy is reserved like any other array; when the
// budget has no room for it the buffer keeps its headroom, which stays counted.
func (h *held) fit() {
	switch {
	case cap(h.buf) == len(h.buf):
		return
	case len(h.buf) == 0:
		h.drop()
		return
	}
	// Nothing is lost when the trim cannot be paid for, so it never asks for a collection.
	got := h.b.take(len(h.buf), 0)
	if got < len(h.buf) {
		h.b.give(got)
		return
	}
	next := make([]byte, len(h.buf))
	copy(next, h.buf)
	h.b.give(cap(h.buf))
	h.buf = next
}

// drop gives the buffer's array back and forgets it.
func (h *held) drop() {
	h.b.give(cap(h.buf))
	h.buf = nil
}
