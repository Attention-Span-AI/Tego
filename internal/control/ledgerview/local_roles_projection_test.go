// SPDX-License-Identifier: Apache-2.0

package ledgerview

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

func TestLocalRolesViewAuthorityRequiresCompleteRunStart(t *testing.T) {
	authority := `{"mode":"owner_only","sha256":"` + strings.Repeat("ab", 32) + `","agent_uid":1001}`
	for _, tc := range []struct {
		name, key, value string
		want             bool
	}{
		{"valid", "local_approval_authority", authority, true},
		{"folded-key", "Local_approval_authority", authority, false},
		{"extra-member", "local_approval_authority", strings.TrimSuffix(authority, "}") + `,"extra":true}`, false},
		{"folded-member", "local_approval_authority", strings.Replace(authority, `"mode"`, `"Mode"`, 1), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			payload := `{"record_minor":37,"` + tc.key + `":` + tc.value + `}`
			st := newRunState("r-test", "")
			st.take(Event{Kind: "run_start", Raw: payload})
			if got := st.b.LocalApprovalAuthority != nil; got != tc.want {
				t.Fatalf("authority projected=%v, want %v from %s", got, tc.want, payload)
			}
		})
	}
}

func TestLocalRolesAnswerRevisionComesFromExactRunStart(t *testing.T) {
	for _, tc := range []struct {
		start string
		want  int
	}{{`{"record_minor":37}`, 37}, {`{"record_minor":31}`, 31}, {`{"Record_minor":37}`, 0}, {`{"record_minor":37,"Record_minor":31}`, 0}} {
		st := newRunState("r-test", "")
		authority := `,"local_approval_authority":{"mode":"owner_only","sha256":"` + strings.Repeat("ab", 32) + `","agent_uid":1001}}`
		st.take(Event{Kind: "run_start", Raw: strings.TrimSuffix(tc.start, "}") + authority})
		st.take(Event{Kind: "answer", Raw: `{"approved":true}`})
		if got := st.b.Events[1].RecordMinor; got != tc.want {
			t.Fatalf("start %s: minor %d want %d", tc.start, got, tc.want)
		}
		if got := st.b.LocalApprovalAuthority != nil; got != (tc.want >= 37) {
			t.Fatalf("start %s: authenticated policy=%v", tc.start, got)
		}
	}
}

func TestLocalRolesAnswerRevisionSurvivesWindowsAndExports(t *testing.T) {
	old := MaxLines
	MaxLines = 3
	t.Cleanup(func() { MaxLines = old })
	// The floor travels with the revision: an answer is shown as root's only when its run's run_start carries the
	// root-only floor, also from a window that dropped run_start and from an export.
	for _, c := range []struct {
		minor int
		floor bool
	}{{31, false}, {37, true}, {37, false}, {record.MinorEveryLaunch, true}, {record.MinorEveryLaunch, false}} {
		minor, floor := c.minor, c.floor
		t.Run(fmt.Sprint(minor, "/floor=", floor), func(t *testing.T) {
			root, id := t.TempDir(), "r-aaaa-0908-rolesx"
			at := time.Date(2026, 11, 12, 0, 0, 0, 0, time.UTC)
			answer := `"ask_id":"q-local","approved":true,"by":"uid:0 pid:42","actor":{"uid":0,"pid":42,"start_boot_ns":10,"user_namespace":4026531837,"source":"kernel-local-uid","role":"owner"}`
			writeRun(t, root, id,
				line(id, "roles", 0, at, "run_start", fmt.Sprintf(`"record_minor":%d`, minor)+map[bool]string{true: `,"local_approval_authority":{"mode":"owner_only","sha256":"` + strings.Repeat("ab", 32) + `","agent_uid":1001}`}[floor]),
				line(id, "roles", 1, at, "ask", `"ask_id":"q-local"`),
				line(id, "roles", 2, at, "answer", answer),
				line(id, "roles", 3, at, "fs", `"op":"open","path":"/held","verdict":"refused"`),
				line(id, "roles", 4, at, "run_end", `"reason":"exit","exit_code":1`))
			store := Open(root)
			r, err := store.Run(id)
			if err != nil {
				t.Fatal(err)
			}
			if !r.Cut || len(r.Events) == 0 || r.Events[0].Seq == 0 {
				t.Fatal("fixture must evict run_start from its resident event window")
			}
			check := func(e *Event) {
				t.Helper()
				if e.RecordMinor != minor {
					t.Fatalf("line %d lost exact run revision: %d, want %d", e.Seq, e.RecordMinor, minor)
				}
				if e.LocalFloor != floor {
					t.Fatalf("line %d lost the run's floor: %v, want %v", e.Seq, e.LocalFloor, floor)
				}
				if e.Kind == "answer" {
					got := record.AnswerAuthorityOf(json.RawMessage(e.Raw), e.RecordMinor, e.LocalFloor).Actor != nil
					if got != (floor && minor >= record.MinorLocalRoles) {
						t.Fatalf("answer attribution=%v at minor %d, floor %v", got, minor, floor)
					}
				}
			}
			for i := range r.Events {
				check(&r.Events[i])
			}
			// Rehydration begins at the retained answer, after run_start's bytes.
			st := store.runs[id]
			st.b.Events, st.bytes, st.resident = nil, 0, false
			if err := st.loadWindow(); err != nil {
				t.Fatal(err)
			}
			if len(st.b.Events) != 3 || st.b.Events[0].Kind != "answer" {
				t.Fatalf("rehydrated wrong retained window: %s, %+v", filepath.Base(st.path), st.b.Events)
			}
			for i := range st.b.Events {
				check(&st.b.Events[i])
			}
			older, err := WindowBefore(root, r, 4)
			if err != nil {
				t.Fatal(err)
			}
			for i := range older.Events {
				check(&older.Events[i])
			}
			snap := &Snapshot{Root: root, Runs: []*Run{r}}
			for _, order := range []Order{OldestFirst, NewestFirst} {
				n := 0
				snap.Each(Filter{Run: id, Ledger: true}, order, func(e *Event, _ func() ([]byte, error)) bool {
					check(e)
					n++
					return true
				})
				if n != 5 {
					t.Fatalf("export order %v checked %d lines, want 5", order, n)
				}
			}
		})
	}
}
