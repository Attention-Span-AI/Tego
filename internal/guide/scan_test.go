// SPDX-License-Identifier: Apache-2.0

package guide_test

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/guide"
	"github.com/attention-span-ai/tego/internal/guide/guidetest"
	"github.com/attention-span-ai/tego/internal/scan/result"
)

func TestGuideScanStates(t *testing.T) {
	for _, state := range guidetest.ScanCases {
		t.Run(state, func(t *testing.T) {
			f := guidetest.Make(t, guidetest.Fresh)
			in := f.Inputs(t)
			in.Now = guidetest.CheckTime.Add(time.Minute)
			before := guide.Compute(t.Context(), in)
			want := f.PutScan(t, state)
			got := guide.Compute(t.Context(), in)
			if got.Unreadable() != before.Unreadable() {
				t.Fatal("scan changed unreadable/exit status")
			}
			for i, st := range got.Steps {
				if st.ID != guide.StepFind && !reflect.DeepEqual(st, before.Steps[i]) {
					t.Fatalf("changed %s", st.ID)
				}
			}
			st := got.Steps[2]
			if st.State == guide.NotKnown {
				t.Fatal("scan set find not known")
			}
			if (st.State == guide.Done) != want {
				t.Fatalf("find %+v", st)
			}
			if want {
				wantFact := "found by scan at " + guidetest.CheckTime.Format(time.RFC3339) + " (any program running as you can change it)"
				if st.Fact == nil {
					t.Fatal("missing scan fact")
				}
				if *st.Fact != wantFact {
					t.Fatalf("fact %q; want %q", *st.Fact, wantFact)
				}
			}
			if !want && !strings.Contains(strings.Join(got.NotKnown, " "), "scan") {
				t.Fatal("no reason")
			}
			if got.Next.Command != before.Next.Command {
				t.Fatal("scan chose a command")
			}
		})
	}
}

func TestGuideScanPartialDisclosesUnreadSources(t *testing.T) {
	for _, state := range []string{"systemd-login", "partial", "partial-b", "partial-zero", "partial-limit"} {
		t.Run(state, func(t *testing.T) {
			f := guidetest.Make(t, guidetest.Fresh)
			f.PutScan(t, state)
			got := guide.Compute(t.Context(), f.Inputs(t))
			nk := strings.Join(got.NotKnown, "\n")
			switch state {
			case "systemd-login":
				for _, want := range []string{"1 of your processes", "3130", "program file", "any program can make itself unreadable"} {
					if !strings.Contains(nk, want) {
						t.Errorf("missing %q in %s", want, nk)
					}
				}
			case "partial-limit":
				for _, want := range []string{"kind B source", "reason limit", "source-limit", "remaining scope is unknown"} {
					if !strings.Contains(nk, want) {
						t.Errorf("missing %q in %s", want, nk)
					}
				}
			default:
				for _, want := range []string{"/project/requirements.txt", "syntax"} {
					if !strings.Contains(nk, want) {
						t.Errorf("missing %q in %s", want, nk)
					}
				}
			}
		})
	}
}

func TestGuideScanFreshnessBoundary(t *testing.T) {
	f := guidetest.Make(t, guidetest.Fresh)
	f.PutScan(t, "systemd-login")
	for _, tc := range []struct {
		age  time.Duration
		done bool
	}{{5 * time.Minute, true}, {5*time.Minute + time.Nanosecond, false}} {
		in := f.Inputs(t)
		in.Now = guidetest.CheckTime.Add(tc.age)
		if got := guide.Compute(t.Context(), in); (got.Steps[2].State == guide.Done) != tc.done {
			t.Fatalf("age %s: %+v", tc.age, got.Steps[2])
		}
	}
}

func TestGuideMissingScanDoesNotImplySavedResult(t *testing.T) {
	f := guidetest.Make(t, guidetest.Fresh)
	got := guide.Compute(t.Context(), f.Inputs(t))
	if nk := strings.Join(got.NotKnown, "\n"); strings.Contains(nk, "the saved scan's rules") || !strings.Contains(nk, "agents outside a scan's rules and sources") {
		t.Fatal(nk)
	}
}
func TestGuideRecordedFindPrecedesScan(t *testing.T) {
	f := guidetest.Make(t, guidetest.HalfDone)
	in := f.Inputs(t)
	before := guide.Compute(t.Context(), in)
	f.PutScan(t, "b")
	got := guide.Compute(t.Context(), in)
	if !reflect.DeepEqual(got.Steps[2], before.Steps[2]) {
		t.Fatal("scan replaced recorded evidence")
	}
}

// Advanced B still describes the recipient's installed candidates. The root
// collector identity must not hide that independent positive observation.
func TestGuideAdvancedInstalledCandidateBelongsToRecipient(t *testing.T) {
	for _, status := range []string{"ok", "partial"} {
		t.Run(status, func(t *testing.T) {
			f := guidetest.Make(t, guidetest.Fresh)
			in := f.Inputs(t)
			in.Now = guidetest.CheckTime.Add(time.Minute)
			before := guide.Compute(t.Context(), in)
			f.PutScan(t, "b")
			path := filepath.Join(f.Home, ".tego/scan/last.json")
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			s, err := result.Decode(data)
			if err != nil {
				t.Fatal(err)
			}
			advanced := result.NewAdvanced(s.Started, 0, uint32(in.UID), s.Tego)
			s.Mode, s.Catalog, s.As, s.Exclusions = advanced.Mode, advanced.Catalog, advanced.As, advanced.Exclusions
			s.Status = status
			if status == "partial" {
				s.Sources = append(s.Sources, result.Source{ID: "unread-cron", Kind: "cron", Locator: result.Path("/etc/cron.d/unknown"), State: "not-read", NotRead: 1, Reason: "permission"})
			}
			if err := result.Save(f.Home, uint32(in.UID), s); err != nil {
				t.Fatal(err)
			}
			got := guide.Compute(t.Context(), in)
			if got.Steps[2].State != guide.Done || got.Steps[2].Fact == nil || !strings.Contains(*got.Steps[2].Fact, "found by scan at") {
				t.Fatalf("root collector hid recipient's installed candidate: %+v; %v", got.Steps[2], got.NotKnown)
			}
			for i, step := range got.Steps {
				if step.ID != guide.StepFind && !reflect.DeepEqual(step, before.Steps[i]) {
					t.Fatalf("advanced installed candidate changed %s", step.ID)
				}
			}
			if got.Unreadable() != before.Unreadable() || got.Next.Command != before.Next.Command {
				t.Fatal("advanced scan changed guide exit status or command")
			}
			if status == "partial" && !strings.Contains(strings.Join(got.NotKnown, "\n"), "/etc/cron.d/unknown") {
				t.Fatal("independent installed evidence hid unreadable source")
			}
		})
	}
}
