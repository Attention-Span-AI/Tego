// SPDX-License-Identifier: Apache-2.0

package derive_test

import (
	"strconv"
	"testing"

	"github.com/attention-span-ai/tego/internal/runtime/derive"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// turn is a model request on thread tid reporting results (nil: not read), from the forwarder or, with ssl set,
// from the uprobe source, which names the thread by its tid.
func turn(tid int, ssl bool, results ...string) *record.Event {
	p := record.SSLRequestPayload{Endpoint: "anthropic", Method: "POST", Path: "/v1/messages", Host: "api.anthropic.com"}
	if results != nil {
		ids := append([]string{}, results...)
		p.ToolResults = &ids
	}
	e := ev(record.KindSSLRequest, tid, p)
	if ssl {
		e.Source = record.SourceSSL
	}
	return e
}

// read is the reading of a request that reports no result: an empty, non-nil list.
var read = []string{}

func answer(tid int, ssl bool) *record.Event {
	e := sslResponse(tid)
	if ssl {
		e.Source = record.SourceSSL
	}
	return e
}

func toolUse(tid int, ssl bool, id string) *record.Event {
	e := ev(record.KindDecision, tid, record.DecisionPayload{ToolUseID: id, Tool: "db_query", InputHash: "h"})
	if ssl {
		e.Source = record.SourceSSL
	}
	return e
}

// attributed folds e and returns its attribution.
func attributed(s *derive.Steps, e *record.Event) record.Attribution {
	s.Apply(e)
	return *e.Attr
}

func wantAttr(t *testing.T, what string, got, want record.Attribution) {
	t.Helper()
	if got != want {
		t.Errorf("%s: attribution %+v, want %+v", what, got, want)
	}
}

// TestToolWindowAttributesActionsToTheReply is E29 on one thread (capture-derive R42): a reply's tool_use opens a
// window, an action while it is the one open window and no model request is in flight is that reply's, method
// tool_id; the request reporting its result closes it, and time decides again.
func TestToolWindowAttributesActionsToTheReply(t *testing.T) {
	s := derive.NewSteps("api.anthropic.com")
	const tid = 48212
	thread := "t" + strconv.Itoa(tid)
	s.Apply(turn(tid, false, read...))
	wantAttr(t, "while step 1 is in flight", attributed(s, action(tid)), *record.AttributedByTime(thread, 1))
	s.Apply(answer(tid, false))
	s.Apply(toolUse(tid, false, "toolu_8812"))
	wantAttr(t, "the db_query tool", attributed(s, action(tid)), *record.AttributedByToolUse(thread, 1, "toolu_8812"))
	wantAttr(t, "a child of the tool", attributed(s, action(tid+1)), *record.AttributedByToolUse(thread, 1, "toolu_8812"))

	s.Apply(turn(tid, false, "toolu_8812"))
	wantAttr(t, "while step 2 is in flight", attributed(s, action(tid)), *record.AttributedByTime(thread, 2))
	s.Apply(answer(tid, false))
	s.Apply(toolUse(tid, false, "toolu_8813"))
	wantAttr(t, "the second reply's tool", attributed(s, action(tid)), *record.AttributedByToolUse(thread, 2, "toolu_8813"))

	s.Apply(turn(tid, false, "toolu_8813"))
	s.Apply(answer(tid, false)) // end_turn: text only
	wantAttr(t, "after a reply with no tool_use", attributed(s, action(tid)), *record.AttributedByTime(thread, 3))
}

// TestToolWindowsNeverGuess: two windows open at once (a reply with two tool_use blocks) are two candidates, so the
// action is attributed by time to the step that holds both, never to one of them.
func TestToolWindowsNeverGuess(t *testing.T) {
	s := derive.NewSteps()
	s.Apply(turn(7, false, read...))
	s.Apply(answer(7, false))
	s.Apply(toolUse(7, false, "toolu_a"))
	s.Apply(toolUse(7, false, "toolu_b"))
	wantAttr(t, "two tools", attributed(s, action(7)), *record.AttributedByTime("t7", 1))
	s.Apply(turn(7, false, "toolu_a", "toolu_b"))
	s.Apply(answer(7, false))
	wantAttr(t, "both reported", attributed(s, action(7)), *record.AttributedByTime("t7", 2))
}

// TestToolWindowOutlivesAnotherConversation: a request on the same thread that does not report the window's result
// (a harness's side call, a subagent's turn) leaves the tool running: while it is in flight time decides, and once
// it is answered the window is again the one candidate.
func TestToolWindowOutlivesAnotherConversation(t *testing.T) {
	s := derive.NewSteps()
	s.Apply(turn(7, false, read...))
	s.Apply(answer(7, false))
	s.Apply(toolUse(7, false, "toolu_bash"))
	s.Apply(turn(7, false, read...))
	wantAttr(t, "the side call in flight", attributed(s, action(7)), *record.AttributedByTime("t7", 2))
	s.Apply(answer(7, false))
	wantAttr(t, "the tool still running", attributed(s, action(7)), *record.AttributedByToolUse("t7", 1, "toolu_bash"))
}

// TestUnreadRequestLeavesEveryWindowUnknown: a model request derive could not read may have reported any result the run
// was waiting on, not only its own thread's: the next turn's request can come on another forwarder lane (the lane of the
// previous reply is freed only once its exchange is recorded) or from another thread of the agent, and a conversation
// can go on in another process. So no window of the run stays open on a guess, where no later request would report it
// again and it would claim every later action; and a reply's decision folded after it from a step opened before it
// opens none, since the request may have reported it. Neither is closed on a guess either: its tool may still run, so
// while one is of unknown state no other window is the run's only one. Its own reply's window opens.
func TestUnreadRequestLeavesEveryWindowUnknown(t *testing.T) {
	none := record.Attribution{Confidence: record.ConfidenceUnattributed, Method: record.MethodTime}
	t.Run("its own thread", func(t *testing.T) {
		s := derive.NewSteps()
		s.Apply(turn(7, false, read...))
		s.Apply(answer(7, false))
		s.Apply(toolUse(7, false, "toolu_1"))
		s.Apply(turn(7, false)) // not read
		s.Apply(answer(7, false))
		wantAttr(t, "after an unread turn", attributed(s, action(7)), *record.AttributedByTime("t7", 2))
	})
	t.Run("another forwarder lane", func(t *testing.T) {
		s := derive.NewSteps()
		s.Apply(at(turn(0, false, read...), 100))
		s.Apply(at(answer(0, false), 200))
		s.Apply(at(toolUse(0, false, "toolu_1"), 200))
		next := at(turn(0, false), 300) // not read, on lane 2
		next.Lane = 2
		s.Apply(next)
		end := at(answer(0, false), 400)
		end.Lane = 2
		s.Apply(end)
		wantAttr(t, "after the unread turn", attributed(s, at(action(8), 500)), none)
		s.Apply(at(turn(0, false, read...), 600)) // lane 1 again, reporting nothing
		s.Apply(at(answer(0, false), 700))
		wantAttr(t, "after a third turn", attributed(s, at(action(8), 800)), none)
	})
	t.Run("another thread of the agent", func(t *testing.T) {
		s := derive.NewSteps()
		s.Apply(at(turn(10, true, read...), 100))
		s.Apply(at(answer(10, true), 200))
		s.Apply(at(toolUse(10, true, "toolu_A"), 200))
		s.Apply(at(turn(11, true), 300)) // not read
		s.Apply(at(answer(11, true), 400))
		wantAttr(t, "a child process", attributed(s, at(action(8), 500)), none)
		wantAttr(t, "thread 10's own action", attributed(s, at(action(10), 500)), *record.AttributedByTID("t10", 1))
		wantAttr(t, "a child process, late", attributed(s, at(action(8), 250)), *record.AttributedByToolUse("t10", 1, "toolu_A"))
	})
	t.Run("a decision folded after it", func(t *testing.T) {
		s := derive.NewSteps()
		s.Apply(at(turn(0, false, read...), 100))
		s.Apply(at(answer(0, false), 200))
		next := at(turn(0, false), 300) // not read, on lane 2: it may report toolu_1
		next.Lane = 2
		s.Apply(next)
		s.Apply(at(toolUse(0, false, "toolu_1"), 200)) // step 1's reply, written after the next turn's request
		end := at(answer(0, false), 400)
		end.Lane = 2
		s.Apply(end)
		wantAttr(t, "after both turns", attributed(s, at(action(8), 500)), none)
		own := at(toolUse(0, false, "toolu_2"), 400) // the unread request's own reply
		own.Lane = 2
		s.Apply(own)
		wantAttr(t, "its own reply's tool beside one unknown", attributed(s, at(action(8), 500)), none)
		s.Apply(at(turn(0, false, "toolu_1"), 600)) // lane 1 again: toolu_1 is done
		s.Apply(at(answer(0, false), 700))
		wantAttr(t, "its own reply's tool", attributed(s, at(action(8), 800)), *record.AttributedByToolUse("t48212.2", 2, "toolu_2"))
	})
}

// TestWindowOfUnknownStateBlocksTheOnlyOne: a window an unread request may have reported, closed or held back, may still
// have its tool running (the request can be another conversation's: a subagent on another lane or thread). While one is,
// another window is not the run's only one, nor the only one of the thread the unknown one belongs to, or the running
// tool's actions would be named after the other's reply; a read request that reports its result ends it.
func TestWindowOfUnknownStateBlocksTheOnlyOne(t *testing.T) {
	none := record.Attribution{Confidence: record.ConfidenceUnattributed, Method: record.MethodTime}
	lane2 := func(e *record.Event) *record.Event {
		e.Lane = 2
		return e
	}
	t.Run("a decision the unread request held back", func(t *testing.T) {
		s := derive.NewSteps()
		s.Apply(at(turn(0, false, read...), 100))      // lane 1, step 1, in flight
		s.Apply(lane2(at(turn(0, false), 150)))        // not read, another conversation: step 2
		s.Apply(at(answer(0, false), 200))             // lane 1's reply...
		s.Apply(at(toolUse(0, false, "toolu_B"), 200)) // ...asks for toolu_B, which the unread request may have reported
		s.Apply(lane2(at(answer(0, false), 250)))
		s.Apply(lane2(at(toolUse(0, false, "toolu_C"), 250)))
		wantAttr(t, "while both tools may run", attributed(s, at(action(8), 300)), none)
		s.Apply(at(turn(0, false, "toolu_B"), 400)) // lane 1 reports toolu_B
		s.Apply(at(answer(0, false), 500))
		wantAttr(t, "once toolu_B is reported", attributed(s, at(action(8), 600)), *record.AttributedByToolUse("t48212.2", 2, "toolu_C"))
	})
	t.Run("a window the unread request closed", func(t *testing.T) {
		s := derive.NewSteps()
		s.Apply(at(turn(0, false, read...), 100))
		s.Apply(at(answer(0, false), 200))
		s.Apply(at(toolUse(0, false, "toolu_B"), 200)) // lane 1's tool runs
		s.Apply(lane2(at(turn(0, false), 300)))        // not read: another conversation's turn, or lane 1's next
		s.Apply(lane2(at(answer(0, false), 400)))
		s.Apply(lane2(at(toolUse(0, false, "toolu_C"), 400)))
		wantAttr(t, "while both tools may run", attributed(s, at(action(8), 500)), none)
		s.Apply(at(turn(0, false, "toolu_B"), 600))
		s.Apply(at(answer(0, false), 700))
		wantAttr(t, "once toolu_B is reported", attributed(s, at(action(8), 800)), *record.AttributedByToolUse("t48212.2", 2, "toolu_C"))
	})
	t.Run("rule (1) of its thread", func(t *testing.T) {
		s := derive.NewSteps()
		s.Apply(at(turn(10, true, read...), 100))
		s.Apply(at(answer(10, true), 200))
		s.Apply(at(toolUse(10, true, "toolu_A"), 200)) // thread 10's in-process tool runs
		s.Apply(at(turn(11, true), 300))               // not read
		s.Apply(at(answer(11, true), 350))
		s.Apply(at(turn(10, true, read...), 400)) // a side call of thread 10, reporting nothing
		s.Apply(at(answer(10, true), 500))
		s.Apply(at(toolUse(10, true, "toolu_A2"), 500))
		wantAttr(t, "thread 10 with an unknown window", attributed(s, at(action(10), 600)), *record.AttributedByTID("t10", 3))
		s.Apply(at(turn(12, true, "toolu_A"), 700)) // toolu_A is done, as another thread's request says
		wantAttr(t, "thread 10 once it is reported", attributed(s, at(action(10), 800)), *record.AttributedByToolUse("t10", 3, "toolu_A2"))
		wantAttr(t, "thread 10 before, late", attributed(s, at(action(10), 650)), *record.AttributedByTID("t10", 3))
	})
}

// TestDecisionAfterItsThreadsNextRequest: a source writes a reply's decisions right after its ssl_response, on the
// reply's thread, but the forwarder writes each declared host's lines through a queue of its own while a process's turns
// to two hosts share its lanes (R34), so another host's request on the same lane can reach the stage between the two;
// and a queue can drop the response line. A decision folded after a later model request of its own thread is then one
// whose reply, and so whether a request reported it, is not known. Numbered into the thread's new step, it passed the
// watermark of an unread request and opened a window no request would report again. It opens none, and its tool may
// run, so it keeps every other window from being the only one until a request reports its result.
func TestDecisionAfterItsThreadsNextRequest(t *testing.T) {
	for _, source := range []struct {
		name   string
		ssl    bool
		tid    int
		thread string
	}{{"uprobe", true, 7, "t7"}, {"forwarder", false, 0, "t48212"}} {
		for _, c := range []struct {
			name string
			next []string // what the thread's next request reported (nil: not read)
		}{{"not read", nil}, {"read, not reporting it", read}, {"read, reporting it", []string{"toolu_1"}}} {
			t.Run(source.name+"/"+c.name, func(t *testing.T) {
				ssl, tid, thread := source.ssl, source.tid, source.thread
				s := derive.NewSteps()
				s.Apply(at(turn(tid, ssl, read...), 100))
				s.Apply(at(answer(tid, ssl), 200))
				s.Apply(at(turn(tid, ssl, c.next...), 300))
				s.Apply(at(toolUse(tid, ssl, "toolu_1"), 200)) // step 1's reply's, folded after the thread's next request
				s.Apply(at(answer(tid, ssl), 400))
				if ssl {
					wantAttr(t, "the thread's own action", attributed(s, at(action(tid), 500)), *record.AttributedByTID(thread, 2))
				}
				wantAttr(t, "another process's action", attributed(s, at(action(8), 500)), *record.AttributedByTime(thread, 2))
				s.Apply(at(turn(tid, ssl, "toolu_1"), 600))
				s.Apply(at(answer(tid, ssl), 700))
				s.Apply(at(toolUse(tid, ssl, "toolu_3"), 700))
				if ssl {
					wantAttr(t, "the third reply's tool", attributed(s, at(action(tid), 800)), *record.AttributedByToolUse(thread, 3, "toolu_3"))
				}
				wantAttr(t, "its child", attributed(s, at(action(8), 800)), *record.AttributedByToolUse(thread, 3, "toolu_3"))
			})
		}
	}
}

// TestSideTrafficOpensNoStep: a model host's side traffic (R40) is no model turn: it opens no step, its answer ends
// no wait, and an action beside it keeps the attribution the turns give.
func TestSideTrafficOpensNoStep(t *testing.T) {
	s := derive.NewSteps("api.anthropic.com")
	s.Apply(turn(7, false, read...))
	s.Apply(answer(7, false))
	s.Apply(toolUse(7, false, "toolu_1"))
	logging := ev(record.KindSSLRequest, 7, record.SSLRequestPayload{Endpoint: "anthropic", Method: "POST",
		Path: "/api/event_logging/batch", Host: "api.anthropic.com", Side: true})
	logging.Pair = 99
	s.Apply(logging)
	if s.Count() != 1 {
		t.Fatalf("side traffic opened a step: %d steps", s.Count())
	}
	wantAttr(t, "beside the side call", attributed(s, action(7)), *record.AttributedByToolUse("t7", 1, "toolu_1"))
	s.Apply(turn(7, false, "toolu_1"))
	done := answer(7, false)
	done.Pair = 99
	s.Apply(done) // the side call's answer must not end step 2's wait
	if st := s.States()["t7"]; !st.InFlight || st.Step != 2 {
		t.Fatalf("the side call's answer ended the model step's wait: %+v", st)
	}
}

// TestTIDAttributesAThreadsOwnActions is E30's in-process rule: the uprobe source names a thread by its tid, so an
// action that thread made is its own turn's, method tid, however many threads have steps; with one open window of
// its own and no request in flight, it is that reply's.
func TestTIDAttributesAThreadsOwnActions(t *testing.T) {
	s := derive.NewSteps()
	s.Apply(turn(7, true, read...))
	s.Apply(turn(9, true, read...))
	s.Apply(answer(7, true))
	s.Apply(answer(9, true))
	wantAttr(t, "thread 9's own action", attributed(s, action(9)), *record.AttributedByTID("t9", 2))
	wantAttr(t, "another process's action", attributed(s, action(11)),
		record.Attribution{Confidence: record.ConfidenceUnattributed, Method: record.MethodTime})
	s.Apply(toolUse(7, true, "toolu_7"))
	wantAttr(t, "thread 7 runs its tool", attributed(s, action(7)), *record.AttributedByToolUse("t7", 1, "toolu_7"))
	wantAttr(t, "the run's one window", attributed(s, action(11)), *record.AttributedByToolUse("t7", 1, "toolu_7"))
	s.Apply(turn(7, true, "toolu_7"))
	wantAttr(t, "thread 7 in flight", attributed(s, action(7)), *record.AttributedByTID("t7", 3))
}

// TestForwarderLanesAreNoTIDs: the forwarder names a turn's thread after its process (R34), so a kernel action whose
// tid happens to equal that pid is no evidence of the thread, and time decides.
func TestForwarderLanesAreNoTIDs(t *testing.T) {
	s := derive.NewSteps()
	req := turn(0, false, read...)
	other := turn(0, false, read...)
	other.Lane = 2
	s.Apply(req)
	s.Apply(other)
	s.Apply(answer(0, false))
	end := answer(0, false)
	end.Lane = 2
	s.Apply(end)
	got := attributed(s, action(48212))
	if got.Method != record.MethodTime {
		t.Fatalf("a forwarder thread was matched by tid: %+v", got)
	}
}

// TestToolWindowsBound: past MaxToolWindows windows open or of unknown state the stage stops reading windows for the
// run, since a window it did not keep could make another look like the only one; tid and time decide from then on.
func TestToolWindowsBound(t *testing.T) {
	s := derive.NewSteps()
	s.Apply(turn(7, false, read...))
	s.Apply(answer(7, false))
	for i := range derive.MaxToolWindows + 1 {
		s.Apply(toolUse(7, false, "toolu_"+strconv.Itoa(i)))
	}
	s.Apply(turn(7, false, read...))
	s.Apply(answer(7, false))
	s.Apply(toolUse(7, false, "toolu_last"))
	wantAttr(t, "after the bound", attributed(s, action(7)), *record.AttributedByTime("t7", 2))

	// Windows of unknown state count: they are as many to remember.
	s = derive.NewSteps()
	s.Apply(turn(7, true, read...))
	s.Apply(answer(7, true))
	for i := range derive.MaxToolWindows {
		s.Apply(toolUse(7, true, "toolu_"+strconv.Itoa(i)))
	}
	s.Apply(turn(9, true)) // not read: every window is of unknown state
	s.Apply(answer(9, true))
	s.Apply(turn(11, true, read...))
	s.Apply(answer(11, true))
	s.Apply(toolUse(11, true, "toolu_last"))
	wantAttr(t, "a thread's one window past the bound", attributed(s, action(11)), *record.AttributedByTID("t11", 3))
}

// at stamps e with a monotonic time and returns it.
func at(e *record.Event, mono uint64) *record.Event {
	e.MonoNS = mono
	return e
}

// TestLateActionIsPlacedWhenItHappened: the kernel's recorder can deliver an action after the model traffic of a
// later turn (seen at tiers cgroup and bpflsm: a tool's write reached the stage after the next turn's reply). An action
// whose monotonic time is before the latest transition is attributed by the state at its time, never by the current
// one: here to the first reply, though the second's window is the one open when it arrives.
func TestLateActionIsPlacedWhenItHappened(t *testing.T) {
	s := derive.NewSteps()
	s.Apply(at(turn(7, false, read...), 100))
	s.Apply(at(answer(7, false), 200))
	s.Apply(at(toolUse(7, false, "toolu_8812"), 200))
	s.Apply(at(turn(7, false, "toolu_8812"), 400))
	s.Apply(at(answer(7, false), 500))
	s.Apply(at(toolUse(7, false, "toolu_8813"), 500))
	wantAttr(t, "a write of the first tool", attributed(s, at(action(8), 300)), *record.AttributedByToolUse("t7", 1, "toolu_8812"))
	wantAttr(t, "while step 2 was in flight", attributed(s, at(action(8), 450)), *record.AttributedByTime("t7", 2))
	wantAttr(t, "before any turn", attributed(s, at(action(8), 50)),
		record.Attribution{Confidence: record.ConfidenceUnattributed, Method: record.MethodTime})
	wantAttr(t, "an action in order", attributed(s, at(action(8), 600)), *record.AttributedByToolUse("t7", 2, "toolu_8813"))
	wantAttr(t, "no time of its own", attributed(s, action(8)), *record.AttributedByToolUse("t7", 2, "toolu_8813"))
}

// TestLateActionOfAThreadIsItsOwn: a late action of a thread the uprobe source names is answered by rule (1) as that
// thread was at the action's time, never by the run's one window, which belongs to another thread's reply, and never
// by the step the thread has moved on to since.
func TestLateActionOfAThreadIsItsOwn(t *testing.T) {
	s := derive.NewSteps()
	s.Apply(at(turn(10, true, read...), 100))
	s.Apply(at(answer(10, true), 200))
	s.Apply(at(toolUse(10, true, "toolu_A"), 200))
	s.Apply(at(turn(20, true, read...), 300))
	s.Apply(at(answer(20, true), 400)) // a text reply: thread 20 opens no window
	s.Apply(at(turn(10, true, "toolu_A"), 600))
	wantAttr(t, "thread 20's own write", attributed(s, at(action(20), 500)), *record.AttributedByTID("t20", 2))
	wantAttr(t, "thread 10's tool", attributed(s, at(action(10), 500)), *record.AttributedByToolUse("t10", 1, "toolu_A"))
	wantAttr(t, "a child of thread 10's tool", attributed(s, at(action(8), 500)), *record.AttributedByToolUse("t10", 1, "toolu_A"))
	s.Apply(at(turn(20, true, read...), 700))
	wantAttr(t, "thread 20's write before its next turn", attributed(s, at(action(20), 500)), *record.AttributedByTID("t20", 2))
	wantAttr(t, "thread 20 between the turns", attributed(s, at(action(20), 650)), *record.AttributedByTID("t20", 2))
	wantAttr(t, "thread 10 in flight", attributed(s, at(action(10), 650)), *record.AttributedByTID("t10", 3))
	wantAttr(t, "thread 20 in order", attributed(s, at(action(20), 800)), *record.AttributedByTID("t20", 4))
}

// TestTurnFoldedLateLeavesItsIntervalUnattributed: request lines are queued when their body has been read, so one turn's
// line can reach the stage after a later turn's. The state between the late turn's own time and the time it was folded
// at is not known (the late turn changed it, the epochs there do not say so), so an action in that interval is
// unattributed, never given a window whose result was already reported.
func TestTurnFoldedLateLeavesItsIntervalUnattributed(t *testing.T) {
	s := derive.NewSteps()
	s.Apply(at(turn(10, false, read...), 100))
	s.Apply(at(answer(10, false), 150))
	s.Apply(at(toolUse(10, false, "toolu_W"), 150))
	s.Apply(at(turn(20, false, read...), 500))
	s.Apply(at(turn(10, false, "toolu_W"), 450)) // queued behind thread 20's turn
	none := record.Attribution{Confidence: record.ConfidenceUnattributed, Method: record.MethodTime}
	wantAttr(t, "before the late turn", attributed(s, at(action(8), 400)), *record.AttributedByToolUse("t10", 1, "toolu_W"))
	wantAttr(t, "at the late turn", attributed(s, at(action(8), 450)), none)
	wantAttr(t, "after the late turn", attributed(s, at(action(8), 470)), none)
	wantAttr(t, "both in flight", attributed(s, at(action(8), 520)), none)
	s.Apply(at(answer(20, false), 600))
	s.Apply(at(answer(10, false), 700))
	wantAttr(t, "still unknown", attributed(s, at(action(8), 470)), none)
	wantAttr(t, "thread 10 alone in flight", attributed(s, at(action(8), 650)), *record.AttributedByTime("t10", 3))
}

// TestResultReportedBeforeItsWindowOpens: a source writes a reply's decisions once it has read the reply's last byte,
// which the agent may have read first, so the next turn's request line (on another lane) can reach the stage before the
// decision that asks for the tool it reports. The window then never opens: opened, it would stay open for good, its
// result already reported, and claim every later action of the run.
func TestResultReportedBeforeItsWindowOpens(t *testing.T) {
	s := derive.NewSteps()
	s.Apply(at(turn(0, false, read...), 100))
	s.Apply(at(answer(0, false), 200))
	next := at(turn(0, false, "toolu_9"), 300)
	next.Lane = 2
	s.Apply(next)
	s.Apply(at(toolUse(0, false, "toolu_9"), 200)) // the first reply's decision, written after the next turn's request
	end := at(answer(0, false), 400)
	end.Lane = 2
	s.Apply(end)
	wantAttr(t, "after both turns", attributed(s, at(action(8), 500)),
		record.Attribution{Confidence: record.ConfidenceUnattributed, Method: record.MethodTime})
	s.Apply(at(toolUse(0, false, "toolu_10"), 400))
	wantAttr(t, "a window that opens in order", attributed(s, at(action(8), 500)), *record.AttributedByToolUse("t48212", 1, "toolu_10"))
}

// TestUnopenedResultsBound: the ids reported before their window opened are bounded. Past the bound the oldest is
// forgotten and its decision opens its window again; an id a window took and a later request reported again is
// forgotten only with its later report.
func TestUnopenedResultsBound(t *testing.T) {
	ids := func(first, n int, more ...string) []string {
		for i := range n {
			more = append(more, "toolu_"+strconv.Itoa(first+i))
		}
		return more
	}
	s := derive.NewSteps()
	s.Apply(turn(7, false, ids(0, derive.MaxUnopenedResults+1)...))
	s.Apply(answer(7, false))
	s.Apply(toolUse(7, false, "toolu_1"))
	s.Apply(toolUse(7, false, "toolu_0")) // the oldest report, forgotten
	wantAttr(t, "the forgotten report's window", attributed(s, action(8)), *record.AttributedByToolUse("t7", 1, "toolu_0"))

	s = derive.NewSteps()
	s.Apply(turn(7, false, "toolu_again"))
	s.Apply(answer(7, false))
	s.Apply(toolUse(7, false, "toolu_again")) // takes the report: no window
	s.Apply(turn(7, false, ids(0, derive.MaxUnopenedResults-2, "toolu_again")...))
	s.Apply(answer(7, false))
	s.Apply(turn(7, false, "toolu_x")) // past the bound: the first report of toolu_again goes, not its second
	s.Apply(answer(7, false))
	s.Apply(toolUse(7, false, "toolu_again"))
	s.Apply(toolUse(7, false, "toolu_x"))
	s.Apply(toolUse(7, false, "toolu_y"))
	wantAttr(t, "the one window", attributed(s, action(8)), *record.AttributedByToolUse("t7", 3, "toolu_y"))
}

// TestLateActionSeesWhatEndedAWait: an abandoned request, an exit and a model line with no time of its own change the
// state at the latest transition, as the stage folds them in arrival order, so a late action from then on is answered
// as an action folded in order is.
func TestLateActionSeesWhatEndedAWait(t *testing.T) {
	for _, end := range []string{"abandon", "exit", "untimed answer"} {
		t.Run(end, func(t *testing.T) {
			s := derive.NewSteps()
			s.Apply(at(turn(7, false, read...), 100))
			s.Apply(at(answer(7, false), 200))
			s.Apply(at(toolUse(7, false, "toolu_7"), 200))
			req := at(turn(9, false, read...), 300)
			req.Pair, req.PID = 41, 2000
			s.Apply(req)
			switch end {
			case "abandon":
				s.Abandon(41)
			case "exit":
				s.Exit(2000)
			default:
				resp := answer(9, false)
				resp.Pair, resp.PID = 41, 2000
				s.Apply(resp)
			}
			want := *record.AttributedByToolUse("t7", 1, "toolu_7")
			wantAttr(t, "in order", attributed(s, at(action(8), 400)), want)
			s.Apply(at(turn(7, false, "toolu_7"), 600))
			wantAttr(t, "late", attributed(s, at(action(8), 400)), want)
			wantAttr(t, "before the wait", attributed(s, at(action(8), 250)), want)
		})
	}
}

// TestLateActionPastAnExitOfManyThreads: an exit of a process with more model threads than an epoch keeps answers for
// leaves rule (1)'s earlier answer unknown for the threads past them. That matters only where rule (1) could have
// applied: in a run no model request of which named its thread by tid (the forwarder's), a late action carrying a tid
// is answered by rules (2) and (3) as they stood at its time, as one with no tid is. Where the uprobe source named the
// exiting threads, a late action of one past the kept answers is unattributed, never the run's one window, another
// thread's reply.
func TestLateActionPastAnExitOfManyThreads(t *testing.T) {
	setup := func(ssl bool) *derive.Steps {
		s := derive.NewSteps()
		for i := range derive.MaxTouched + 1 {
			req := at(turn(1001+i, ssl, read...), 100)
			end := at(answer(1001+i, ssl), 100)
			if !ssl {
				req.TID, req.Lane, end.TID, end.Lane = 0, uint64(i+1), 0, uint64(i+1) // the forwarder's lanes
			}
			req.PID, end.PID = 2000, 2000
			s.Apply(req)
			s.Apply(end)
		}
		s.Apply(at(turn(7, false, read...), 150))
		s.Apply(at(answer(7, false), 200))
		s.Apply(at(toolUse(7, false, "toolu_7"), 200))
		s.Apply(at(turn(9, false, read...), 300))
		s.Exit(2000)
		return s
	}
	window := *record.AttributedByToolUse("t7", derive.MaxTouched+2, "toolu_7")
	t.Run("forwarder", func(t *testing.T) {
		s := setup(false)
		wantAttr(t, "a late action with a tid", attributed(s, at(action(8), 250)), window)
		wantAttr(t, "a late action with none", attributed(s, at(action(0), 250)), window)
	})
	t.Run("uprobe", func(t *testing.T) {
		s := setup(true)
		last := 1001 + derive.MaxTouched
		wantAttr(t, "a kept thread", attributed(s, at(action(1001), 250)), *record.AttributedByTID("t1001", 1))
		wantAttr(t, "a thread past the kept ones", attributed(s, at(action(last), 250)),
			record.Attribution{Confidence: record.ConfidenceUnattributed, Method: record.MethodTime})
		wantAttr(t, "a late action with none", attributed(s, at(action(0), 250)), window)
	})
}
