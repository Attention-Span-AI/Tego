// SPDX-License-Identifier: Apache-2.0

package livestatus

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestStatusTable decides every kind against every combination of facts and of confirmation.
func TestStatusTable(t *testing.T) {
	type conf struct {
		name              string
		serial, confirmed uint64
	}
	confs := []conf{{"unconfirmed", 3, 2}, {"confirmed", 3, 3}, {"confirmed-later", 3, 7}, {"never", 1, 0}}
	for _, kind := range []string{KindExec, KindNet, KindPath, "other"} {
		for _, observe := range []bool{false, true} {
			for _, reads := range []bool{false, true} {
				for _, ended := range []bool{false, true} {
					for _, c := range confs {
						f := Facts{Observe: observe, ReadsSeen: reads, Ended: ended}
						var want State
						switch {
						case ended:
							want = Ended
						case observe:
							want = RecordedOnly
						case c.confirmed < c.serial:
							want = Waiting
						case kind == KindPath && !reads:
							want = Partial
						default:
							want = InForce
						}
						name := fmt.Sprintf("%s/observe=%v/reads=%v/ended=%v/%s", kind, observe, reads, ended, c.name)
						t.Run(name, func(t *testing.T) {
							got := Status(kind, f, c.serial, c.confirmed)
							if got.State != want {
								t.Fatalf("State = %s, want %s", got.State, want)
							}
							if got.Sentence != sentenceOf[want] {
								t.Fatalf("Sentence = %q, want %q", got.Sentence, sentenceOf[want])
							}
						})
					}
				}
			}
		}
	}
}

var sentenceOf = map[State]string{
	Ended: SentenceEnded, RecordedOnly: SentenceRecordedOnly, Waiting: SentenceWaiting,
	Partial: SentencePartial, InForce: SentenceInForce,
}

// TestWatchedNeverClaimsARefusal: on a watched run no kind, confirmed or not, reads seen or not, says it refuses.
func TestWatchedNeverClaimsARefusal(t *testing.T) {
	for _, kind := range []string{KindExec, KindNet, KindPath} {
		for _, reads := range []bool{false, true} {
			r := Status(kind, Facts{Observe: true, ReadsSeen: reads}, 1, 9)
			if r.State.Refuses() {
				t.Errorf("%s reads=%v on a watched run: %s claims a refusal", kind, reads, r.State)
			}
		}
	}
	if !InForce.Refuses() || !Partial.Refuses() || Waiting.Refuses() || Ended.Refuses() {
		t.Error("Refuses: only in_force and partial refuse")
	}
}

func TestFromStart(t *testing.T) {
	sha := strings.Repeat("0a", 32)
	cases := []struct {
		name string
		raw  string
		want Facts
	}{
		{"watch", `{"tier":"observe","fs_reads":{"reads":"direct","why":"records-only"},"reads_notified":{"notified":false,"why":"records-only"}}`, Facts{Started: true, Observe: true}},
		{"held", `{"tier":"landlock","fs_reads":{"reads":"held","why":"contract"}}`, Facts{Started: true, ReadsSeen: true}},
		{"record-full", `{"tier":"landlock","fs_reads":{"reads":"direct","why":"none-nested"},"reads_notified":{"notified":true,"why":"record-full"}}`, Facts{Started: true, ReadsSeen: true}},
		{"direct", `{"tier":"landlock","fs_reads":{"reads":"direct","why":"none-nested"},"reads_notified":{"notified":false,"why":"reason-off"}}`, Facts{Started: true}},
		{"old ledger", `{"tier":"cgroup"}`, Facts{Started: true}},
		{"r6 launcher", `{"tier":"landlock","record_minor":23}`, Facts{Started: true, RecordMinor: 23}},
		{"r7 launcher", `{"tier":"landlock","record_minor":24}`, Facts{Started: true, RecordMinor: 24}},
		{"lsm plane", `{"tier":"bpf-lsm","record_minor":24,"decision_plane":"lsm"}`, Facts{Started: true, RecordMinor: 24, KernelDecidesChanges: true}},
		{"fmod_ret plane", `{"tier":"bpf-lsm","decision_plane":"fmod_ret"}`, Facts{Started: true, KernelDecidesChanges: true}},
		{"fanotify listener", `{"tier":"cgroup","decision_plane":"fanotify"}`, Facts{Started: true}},
		{"not json", `{`, Facts{StartUnreadable: true}},
		{"lp1 launcher, Locked", `{"tier":"cgroup","record_minor":26}`, Facts{Started: true, RecordMinor: 26, Timed: true}},
		{"Adjustable", `{"tier":"cgroup","record_minor":26,"live_mode":"adjustable","live_fence":{"sha256":"` + sha + `","entries":[{"kind":"read","value":"/srv/x","source":"new","rule":"live.fence[read:/srv/x]"}]}}`,
			Facts{Started: true, RecordMinor: 26, Timed: true, Adjustable: true, Fence: []record.LiveFenceEntry{{Kind: "read", Value: "/srv/x", Source: "new", Rule: "live.fence[read:/srv/x]"}}}},
		{"mode below 26", `{"tier":"cgroup","record_minor":25,"live_mode":"adjustable","live_fence":{"sha256":"` + sha + `","entries":[]}}`, Facts{Started: true, RecordMinor: 25}},
		{"mode without fence", `{"tier":"cgroup","record_minor":26,"live_mode":"adjustable"}`, Facts{Started: true, RecordMinor: 26, Timed: true}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := FromStartJSON([]byte(c.raw)); !reflect.DeepEqual(got, c.want) {
				t.Fatalf("FromStartJSON = %+v, want %+v", got, c.want)
			}
		})
	}
	if FromStart(nil).Started {
		t.Fatal("FromStart(nil) says a run_start was read")
	}
	p := &record.RunStartPayload{Tier: "landlock", FSReads: &record.FSReads{Reads: record.FSReadsHeld}}
	if got := FromStart(p); !reflect.DeepEqual(got, Facts{Started: true, ReadsSeen: true}) {
		t.Fatalf("FromStart = %+v", got)
	}
	p = &record.RunStartPayload{Tier: "bpf-lsm", RecordMinor: record.MinorLiveControl, DecisionPlane: record.DecisionPlaneLSM}
	if got := FromStart(p); !reflect.DeepEqual(got, Facts{Started: true, RecordMinor: record.MinorLiveControl, KernelDecidesChanges: true}) || !got.NarrowKinds() {
		t.Fatalf("FromStart(plane) = %+v", got)
	}
	if (Facts{RecordMinor: record.MinorLiveControl - 1}).NarrowKinds() || (Facts{}).NarrowKinds() {
		t.Fatal("NarrowKinds: a launcher below MinorLiveControl, or one not known, has no read or write blocks")
	}
	fence := &record.LiveFence{SHA256: sha, Entries: []record.LiveFenceEntry{{Kind: "net", Value: "api.stripe.com:443",
		Source: "new", Rule: "live.fence[net:api.stripe.com:443]"}}}
	p = &record.RunStartPayload{Tier: "cgroup", RecordMinor: record.MinorLiveModes, LiveMode: record.LiveModeAdjustable, LiveFence: fence}
	got := FromStart(p)
	if !got.Timed || !got.Adjustable || len(got.Fence) != 1 {
		t.Fatalf("FromStart(adjustable) = %+v", got)
	}
	if e, ok := got.InFence("net", "api.stripe.com:443"); !ok || e.Source != "new" {
		t.Fatalf("InFence = %+v, %v", e, ok)
	}
	if _, ok := got.InFence("net", "api.stripe.com:80"); ok {
		t.Fatal("InFence found an entry the fence does not list")
	}
	if got := FromStart(nil); !reflect.DeepEqual(got, Facts{}) {
		t.Fatalf("FromStart(nil) = %+v", got)
	}
}

// TestStatusOnAPlaneRun: on a run whose kernel plane decides file changes (Facts.KernelDecidesChanges) a write block
// and a path block, once the launcher confirmed them, are only partly in force: the supervisor refuses what still
// reaches it and the plane's own answers are not covered. They say so, and never "In force". The other kinds, which
// the plane does not decide, are in force as before; a block still waiting, and a run that ended or is only watched,
// say what they said.
func TestStatusOnAPlaneRun(t *testing.T) {
	plane := Facts{KernelDecidesChanges: true, ReadsSeen: true}
	for _, kind := range []string{KindWrite, KindPath} {
		got := Status(kind, plane, 1, 1)
		if got.State != PartlyKernel || got.Sentence != SentencePartlyKernel || !got.State.Refuses() {
			t.Errorf("%s on a plane run = %+v, want partly in force", kind, got)
		}
		if strings.Contains(got.Sentence, "In force") {
			t.Errorf("%s on a plane run says %q", kind, got.Sentence)
		}
		// A path block on a plane run that also does not see its reads says both gaps.
		noReads := Facts{KernelDecidesChanges: true}
		if got := Status(kind, noReads, 1, 1); got.State != PartlyKernel || (kind == KindPath) != (got.Sentence == SentencePartlyKernelNoReads) {
			t.Errorf("%s on a plane run without reads = %+v", kind, got)
		}
		if got := Status(kind, plane, 2, 1); got.State != Waiting {
			t.Errorf("%s on a plane run, unconfirmed = %+v, want waiting", kind, got)
		}
		ended := plane
		ended.Ended = true
		if got := Status(kind, ended, 1, 1); got.State != Ended {
			t.Errorf("%s on an ended plane run = %+v", kind, got)
		}
		watched := plane
		watched.Observe = true
		if got := Status(kind, watched, 1, 1); got.State != RecordedOnly {
			t.Errorf("%s on a watched plane run = %+v", kind, got)
		}
	}
	for _, kind := range []string{KindExec, KindNet, KindRead} {
		if got := Status(kind, plane, 1, 1); got.State != InForce {
			t.Errorf("%s on a plane run = %+v, want in force", kind, got)
		}
	}
	// A time limit keeps the partial wording: the sentence never turns into "In force ... until its time limit ends".
	if got := StatusAt(KindWrite, plane, 1, 1, time.Unix(100, 0), time.Time{}, time.Unix(200, 0)); got.State != PartlyKernel {
		t.Errorf("timed write block on a plane run = %+v", got)
	}
}

// TestStatusOnAPlaneRunWhoseLauncherBlocksInThePlane (ADR 0124, amendment 2026-11-21): on a run whose kernel plane
// decides file changes and whose launcher puts file blocks in force there too (the run directory's plane mark,
// Facts.PlaneBlocks), a write, path or read block the launcher confirmed is in force, reads included where the
// supervisor does not see them, since the plane decides every open; a time limit says so. Without the mark it stays
// partly in force (TestStatusOnAPlaneRun). ReadsDecided says a read block refuses reads there.
func TestStatusOnAPlaneRunWhoseLauncherBlocksInThePlane(t *testing.T) {
	marked := Facts{KernelDecidesChanges: true, PlaneBlocks: true}
	for _, kind := range []string{KindWrite, KindPath, KindRead} {
		if got := Status(kind, marked, 1, 1); got.State != InForce || got.Sentence != SentenceInForce {
			t.Errorf("%s on a plane run with the mark = %+v, want in force", kind, got)
		}
		if got := Status(kind, marked, 2, 1); got.State != Waiting {
			t.Errorf("%s unconfirmed = %+v, want waiting", kind, got)
		}
	}
	if got := StatusAt(KindWrite, marked, 1, 1, time.Unix(100, 0), time.Time{}, time.Unix(200, 0)); got.State != InForce ||
		got.Sentence != SentenceInForceUntil {
		t.Errorf("a timed write block with the mark = %+v, want in force until its limit", got)
	}
	if !marked.ReadsDecided() || (Facts{KernelDecidesChanges: true}).ReadsDecided() || (Facts{PlaneBlocks: true}).ReadsDecided() {
		t.Error("ReadsDecided: the plane decides reads only on a plane run whose launcher blocks there")
	}
}
