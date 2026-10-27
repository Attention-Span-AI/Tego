// SPDX-License-Identifier: Apache-2.0

package observe

import (
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
	"unsafe"

	"github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/internal/runtime/supervisor"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// The fold of a pinned run's execs (ADR 0048 (8), P2's K4): the recorder's exec record and the plane's held or kill
// sample of the same exec make one line. These tests feed the two halves in either order, lose one of them, mismatch
// the pin's seq and fail the kill's send, and hold the fold to its two rules: no line says allow for an exec the plane
// killed, and none says kernel_pinned without the plane's held sample of the decision's own pin.

const pinTestSeq = 7

// pinnedExecSample is execSample's record of an exec the plane held to the pin of seq (tego_ev_exec.pin_seq).
func pinnedExecSample(h sample, seq uint32, argv []string) []byte {
	h.Kind = KindExec
	blob := []byte(strings.Join(argv, "\x00") + "\x00")
	e := bpf.ExecEvent{Hdr: h.header(ExecSize), ExecStartNS: h.Start, ArgvLen: uint32(len(blob)), PinSeq: seq}
	e.Hdr.TID = h.PID // after de_thread the exec's task is the leader
	copy(e.Comm[:], fixed("tool", CommLen))
	copy(e.Path[:], fixed("/kernel/tool", PathMax))
	copy(e.Argv[:], fixed(string(blob), ArgvMax))
	e.OldTID = h.TID
	return wire(&e)
}

// heldSample is the plane's held sample (struct tego_ev_exec_held) of the pin of seq.
func heldSample(h sample, seq uint32) []byte {
	h.Kind = KindPlaneExecHeld
	h.Verdict = KernelAllow
	e := bpf.ExecHeldEvent{Hdr: h.header(int(unsafe.Sizeof(bpf.ExecHeldEvent{}))), ExecStartNS: h.Start, OldTID: h.TID, Seq: seq}
	return wire(&e)
}

// killSample is the plane's kill sample (struct tego_ev_exec_kill) of the pin of seq, with the area the new image
// maps and bpf_send_signal's error.
func killSample(h sample, seq uint32, reason bpf.ReasonCode, killErr int32, argv []string) []byte {
	h.Kind = KindPlaneExecKill
	h.Verdict, h.Reason = KernelRefused, uint8(reason)
	blob := []byte(strings.Join(argv, "\x00") + "\x00")
	e := bpf.ExecKillEvent{Hdr: h.header(int(unsafe.Sizeof(bpf.ExecKillEvent{}))), ExecStartNS: h.Start, OldTID: h.TID, Seq: seq,
		KillErr: killErr, ArgvLen: uint32(len(blob)), Form: 1}
	copy(e.Argv[:], blob)
	return wire(&e)
}

// pinRun runs a pinned recorder over samples, every exec joined to a naming whose decision wrote the pin of
// namingSeq, and returns the recorder, its lines and the backstop's kills.
func pinRun(t *testing.T, namingSeq uint32, samples ...[]byte) (*Recorder, *fakeSink, [][2]uint64) {
	t.Helper()
	f := newFixture(t)
	n := outcomeNaming(10)
	n.PinSeq = namingSeq
	n.ArgvFacts = record.ArgvFactsCopied
	var (
		mu    sync.Mutex
		kills [][2]uint64
	)
	r, sink := runRecorder(t, f, Options{FlushInterval: time.Hour, ExecResults: true, ExecPins: true,
		ContinuedExec: func(int, int, uint64, uint64) (supervisor.ExecNaming, bool) { return n, true },
		ExecPinKill: func(pid int, start uint64) error {
			mu.Lock()
			defer mu.Unlock()
			kills = append(kills, [2]uint64{uint64(pid), start})
			return nil
		}}, samples...)
	return r, sink, kills
}

func TestExecPinFoldHeldIsKernelPinned(t *testing.T) {
	h := execOutcomeHeader(30)
	exec, held := pinnedExecSample(h, pinTestSeq, []string{"tool", "argument"}), heldSample(h, pinTestSeq)
	for name, order := range map[string][][]byte{"exec first": {exec, held}, "held first": {held, exec}} {
		t.Run(name, func(t *testing.T) {
			r, sink, _ := pinRun(t, pinTestSeq, order...)
			ev, p := oneExecOutcome(t, sink)
			if ev.Verdict == record.VerdictRefused || ev.Rule == RuleExecPin || p.ArgvFacts != record.ArgvFactsKernelPinned {
				t.Fatalf("a held exec: %+v %+v", ev, p)
			}
			if n := gapCount(r.Gaps())[GapExecPinUnproven]; n != 0 {
				t.Fatalf("a held exec counted %d unproven", n)
			}
		})
	}
}

// TestExecPinFoldKillIsRefused: a kill makes the exec's one line refused, rule exec.pin, with the kernel's mapped argv
// and the decision's, whichever half came first and whether or not the exec record arrived at all.
func TestExecPinFoldKillIsRefused(t *testing.T) {
	h := execOutcomeHeader(30)
	exec := pinnedExecSample(h, pinTestSeq, []string{"tool", "argument"})
	kill := killSample(h, pinTestSeq, bpf.ReasonArgvChanged, 0, []string{"tool", "push"})
	// An earlier exec of the process whose record was lost left its held sample waiting: this exec's record is not
	// its pair, so the kill still makes this exec's one line.
	earlier := heldSample(h, pinTestSeq-1)
	for name, order := range map[string][][]byte{"exec first": {exec, kill}, "kill first": {kill, exec}, "no exec record": {kill},
		"an earlier exec's held sample waits": {earlier, exec, kill}} {
		t.Run(name, func(t *testing.T) {
			r, sink, kills := pinRun(t, pinTestSeq, order...)
			ev, p := oneExecOutcome(t, sink)
			if ev.Verdict != record.VerdictRefused || ev.Rule != RuleExecPin || ev.Reason != record.ReasonExecNotAllowed ||
				p.PlaneReason != "argv-changed" || p.Signal != record.SignalKill || p.ArgvFrom != "kernel" ||
				!slices.Equal(p.Argv, []string{"tool", "push"}) || !slices.Equal(p.ArgvDecided, []string{"tool", "argument"}) ||
				p.ArgvFacts == record.ArgvFactsKernelPinned || p.DetectedBypass || p.KillFailed != 0 {
				t.Fatalf("a killed exec: %+v %+v", ev, p)
			}
			if killed, failed, _ := r.ExecPinCounts(); killed != 1 || failed != 0 || len(kills) != 0 {
				t.Fatalf("killed %d, kill_failed %d, pidfd kills %v", killed, failed, kills)
			}
		})
	}
}

// TestExecPinFoldKillFailed: a kill the kernel could not send is refused with kill_failed and detected_bypass, the gap,
// and the launcher's pidfd kill of the process the sample named.
func TestExecPinFoldKillFailed(t *testing.T) {
	h := execOutcomeHeader(30)
	r, sink, kills := pinRun(t, pinTestSeq, pinnedExecSample(h, pinTestSeq, []string{"tool", "argument"}),
		killSample(h, pinTestSeq, bpf.ReasonArgvChanged, -3, []string{"tool", "push"}))
	ev, p := oneExecOutcome(t, sink)
	if ev.Verdict != record.VerdictRefused || p.KillFailed != -3 || !p.DetectedBypass || p.Signal != record.SignalKill {
		t.Fatalf("a failed kill: %+v %+v", ev, p)
	}
	if gapCount(r.Gaps())[GapExecPinKillFailed] != 1 || len(kills) != 1 || kills[0] != [2]uint64{50, h.Start} {
		t.Fatalf("gaps %v, pidfd kills %v", r.Gaps(), kills)
	}
	if killed, failed, _ := r.ExecPinCounts(); killed != 1 || failed != 1 {
		t.Fatalf("killed %d, kill_failed %d", killed, failed)
	}
}

// TestExecPinFoldUnproven: an exec whose held sample was lost, or whose held sample, record or naming name different
// pins, says unproven with the gap, never kernel_pinned, and keeps the verdict the mechanisms answered.
func TestExecPinFoldUnproven(t *testing.T) {
	h := execOutcomeHeader(30)
	exit := sample{PID: 50, TID: 50, MonoNS: 40, Start: h.Start}
	for _, c := range []struct {
		name      string
		namingSeq uint32
		samples   [][]byte
	}{
		{"held lost, drained at stop", pinTestSeq, [][]byte{pinnedExecSample(h, pinTestSeq, []string{"tool"})}},
		{"held lost, the process exits", pinTestSeq, [][]byte{pinnedExecSample(h, pinTestSeq, []string{"tool"}),
			exitSample(exit, 0, 0)}},
		{"held of another pin", pinTestSeq, [][]byte{pinnedExecSample(h, pinTestSeq, []string{"tool"}), heldSample(h, pinTestSeq+1)}},
		{"the decision wrote another pin", pinTestSeq - 1, [][]byte{pinnedExecSample(h, pinTestSeq, []string{"tool"}),
			heldSample(h, pinTestSeq)}},
		{"a record with no pin", pinTestSeq, [][]byte{pinnedExecSample(h, 0, []string{"tool"}), heldSample(h, 0)}},
	} {
		t.Run(c.name, func(t *testing.T) {
			r, sink, _ := pinRun(t, c.namingSeq, c.samples...)
			ev, p := oneExecOutcome(t, sink)
			if ev.Verdict == record.VerdictRefused || ev.Rule == RuleExecPin || p.ArgvFacts != record.ArgvFactsUnproven {
				t.Fatalf("an unproven exec: %+v %+v", ev, p)
			}
			if n := gapCount(r.Gaps())[GapExecPinUnproven]; n != 1 {
				t.Fatalf("unproven gap %d, gaps %v", n, r.Gaps())
			}
		})
	}
}

// TestExecPinFoldPairsOneExec: the fold pairs an exec record only with the sample of the same exec, the one whose seq
// is the record's pin_seq (a kill names the task's cur_seq, which the record reads). Under a ring loss of one half of one
// exec and the other half of the next, each exec keeps its own line: the earlier exec's record says unproven with the
// verdict the mechanisms answered, and the later exec's kill is its own refused line, never the earlier exec's.
func TestExecPinFoldPairsOneExec(t *testing.T) {
	h := execOutcomeHeader(30)
	t.Run("an earlier exec's record, a later exec's kill", func(t *testing.T) {
		r, sink, _ := pinRun(t, pinTestSeq, pinnedExecSample(h, pinTestSeq, []string{"tool", "argument"}),
			killSample(h, pinTestSeq+1, bpf.ReasonArgvChanged, 0, []string{"tool", "push"}))
		evs := sink.byKind(record.KindExec)
		if len(evs) != 2 {
			t.Fatalf("%d exec lines, want the earlier exec's and the kill's: %+v", len(evs), evs)
		}
		first, kill := payload[execOutcomePayload](t, evs[0]), payload[execOutcomePayload](t, evs[1])
		if evs[0].Verdict == record.VerdictRefused || evs[0].Rule == RuleExecPin || first.ArgvFacts != record.ArgvFactsUnproven ||
			first.Signal != "" {
			t.Errorf("the earlier exec's line: %+v %+v", evs[0], first)
		}
		if evs[1].Verdict != record.VerdictRefused || evs[1].Rule != RuleExecPin || kill.PlaneReason != "argv-changed" ||
			kill.Signal != record.SignalKill || !slices.Equal(kill.Argv, []string{"tool", "push"}) {
			t.Errorf("the kill's line: %+v %+v", evs[1], kill)
		}
		if n := gapCount(r.Gaps())[GapExecPinUnproven]; n != 1 {
			t.Errorf("unproven gap %d, gaps %v", n, r.Gaps())
		}
	})
	// A kill of an exec no pin was armed for, or whose slot was cleared since bprm_check, names the task's cur_seq, the
	// seq the exec's record reads as its pin_seq: 0 when the task holds no state of the run, else the seq bprm_check's
	// first stage left. Its own record pairs with it in either order.
	for _, seq := range []uint32{0, pinTestSeq} {
		for name, order := range map[string][][]byte{
			"exec first": {pinnedExecSample(h, seq, []string{"tool"}), killSample(h, seq, bpf.ReasonPinMissing, 0, []string{"tool"})},
			"kill first": {killSample(h, seq, bpf.ReasonPinMissing, 0, []string{"tool"}), pinnedExecSample(h, seq, []string{"tool"})},
		} {
			t.Run(fmt.Sprintf("a kill of no armed pin, seq %d, %s", seq, name), func(t *testing.T) {
				_, sink, _ := pinRun(t, pinTestSeq, order...)
				ev, p := oneExecOutcome(t, sink)
				if ev.Verdict != record.VerdictRefused || ev.Rule != RuleExecPin || p.PlaneReason != "pin-missing" {
					t.Fatalf("a kill of no armed pin: %+v %+v", ev, p)
				}
			})
		}
	}
	// Exec 7's record waits, its held sample lost, and exec 8's kill is read before exec 8's record. A
	// kill pairs only with the record of its own seq, 0 included: exec 7's line keeps the verdict the mechanisms
	// answered and says unproven, and exec 8's kill and record make exec 8's refused line. A kill of seq 0 that took any
	// waiting record would log exec 7, which ran, as refused.
	h8 := execOutcomeHeader(31) // exec 8 comes later than exec 7
	for _, later := range []uint32{0, pinTestSeq + 1} {
		t.Run(fmt.Sprintf("an earlier exec's record waits, a later kill of seq %d comes before its record", later), func(t *testing.T) {
			r, sink, _ := pinRun(t, pinTestSeq, pinnedExecSample(h, pinTestSeq, []string{"tool", "argument"}),
				killSample(h8, later, bpf.ReasonPinUnverifiable, 0, []string{"tool", "push"}),
				pinnedExecSample(h8, later, []string{"tool", "push"}))
			evs := sink.byKind(record.KindExec)
			if len(evs) != 2 {
				t.Fatalf("%d exec lines, want exec 7's and exec 8's: %+v", len(evs), evs)
			}
			first, second := payload[execOutcomePayload](t, evs[0]), payload[execOutcomePayload](t, evs[1])
			if evs[0].Verdict == record.VerdictRefused || evs[0].Rule == RuleExecPin || first.ArgvFacts != record.ArgvFactsUnproven ||
				first.Signal != "" || first.PlaneReason != "" {
				t.Errorf("exec 7's line, which ran: %+v %+v", evs[0], first)
			}
			if evs[1].Verdict != record.VerdictRefused || evs[1].Rule != RuleExecPin || second.PlaneReason != "pin-unverifiable" ||
				second.Signal != record.SignalKill || !slices.Equal(second.Argv, []string{"tool", "push"}) {
				t.Errorf("exec 8's line, which the plane killed: %+v %+v", evs[1], second)
			}
			if n := gapCount(r.Gaps())[GapExecPinUnproven]; n != 1 {
				t.Errorf("unproven gap %d, gaps %v", n, r.Gaps())
			}
		})
	}
}

// TestExecPinFoldKillOutsideAPinnedRun: a kill sample in a run the recorder was not told is pinned is still a refused
// line, never nothing and never an allow.
func TestExecPinFoldKillOutsideAPinnedRun(t *testing.T) {
	f := newFixture(t)
	h := execOutcomeHeader(30)
	_, sink := runRecorder(t, f, Options{FlushInterval: time.Hour},
		killSample(h, 0, bpf.ReasonPinMissing, 0, []string{"tool"}))
	ev, p := oneExecOutcome(t, sink)
	if ev.Verdict != record.VerdictRefused || ev.Rule != RuleExecPin || p.PlaneReason != "pin-missing" || p.Signal != record.SignalKill {
		t.Fatalf("a kill outside a pinned run: %+v %+v", ev, p)
	}
}
