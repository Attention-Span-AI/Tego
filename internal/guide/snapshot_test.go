// SPDX-License-Identifier: Apache-2.0

package guide_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/agentid"
	"github.com/attention-span-ai/tego/internal/guide"
	"github.com/attention-span-ai/tego/internal/guide/guidetest"
	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

func TestAgentSnapshotRejectsReplacement(t *testing.T) {
	for _, inPlace := range []bool{false, true} {
		name := "renamed-inode"
		if inPlace {
			name = "same-inode"
		}
		t.Run(name, func(t *testing.T) { assertAgentSnapshotRejectsReplacement(t, inPlace) })
	}
}

func assertAgentSnapshotRejectsReplacement(t *testing.T, inPlace bool) {
	t.Helper()
	f := guidetest.Make(t, guidetest.Finished)
	id := f.Runs[len(f.Runs)-1]
	path := filepath.Join(f.Ledger, id, ledger.EventsFile)
	authentic, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	forged := bytes.Replace(authentic, []byte(`"sh"`), []byte(`"/forged/agent"`), 1)
	if bytes.Equal(authentic, forged) {
		t.Fatal("fixture did not change")
	}
	if err := os.WriteFile(path, forged, 0600); err != nil {
		t.Fatal(err)
	}
	rows := guide.AgentsAfterDiscovery(t.Context(), f.Inputs(t), func() {
		if inPlace {
			if err := os.WriteFile(path, authentic, 0600); err != nil {
				t.Fatal(err)
			}
			return
		}
		tmp := path + ".replacement"
		if err := os.WriteFile(tmp, authentic, 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(tmp, path); err != nil {
			t.Fatal(err)
		}
	})
	found := false
	for _, a := range rows {
		for _, r := range a.Runs {
			if r.ID == id {
				found = true
				for _, s := range a.Stages {
					if s.ID != agentid.RecordedStage && s.Fact.Established {
						t.Fatalf("replaced metadata gained tick: %+v", a)
					}
				}
				if r.Verification != agentid.CannotVerify || !strings.Contains(r.VerificationReason, "changed") {
					t.Fatalf("replacement not explained: %+v", r)
				}
			}
		}
	}
	if !found {
		t.Fatal("replaced run disappeared")
	}
}

func TestAgentSnapshotTimeoutAndMissingAnchor(t *testing.T) {
	for _, which := range []string{"timeout", "missing-anchor", "absent-anchor-file", "missing-anchor-line"} {
		t.Run(which, func(t *testing.T) {
			f := guidetest.Make(t, guidetest.Finished)
			in := f.Inputs(t)
			ctx := t.Context()
			switch which {
			case "timeout":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "missing-anchor-line":
				if err := os.WriteFile(f.Anchor, nil, 0600); err != nil {
					t.Fatal(err)
				}
			case "absent-anchor-file":
				in.Anchor = filepath.Join(f.Home, "absent-chain.log")
			default:
				in.Anchor = ""
			}
			s := guide.Compute(ctx, in)
			if len(s.Agents) == 0 {
				t.Fatal("records disappeared")
			}
			for _, a := range s.Agents {
				if a.VerificationReason == "" || a.NextStep == "" {
					t.Fatalf("missing reason or action: %+v", a)
				}
				for _, st := range a.Stages {
					if st.ID != agentid.RecordedStage && st.Fact.Established {
						t.Fatalf("%s established %s: %+v", which, st.ID, a)
					}
				}
			}
		})
	}
}

func TestAgentChecksOlderCorruptionBesideNewerRun(t *testing.T) {
	f := guidetest.Make(t, guidetest.Finished)
	older := f.Runs[0]
	p := filepath.Join(f.Ledger, older, ledger.EventsFile)
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	b = bytes.Replace(b, []byte(`"observe"`), []byte(`"landlock"`), 1)
	if err := os.WriteFile(p, b, 0600); err != nil {
		t.Fatal(err)
	}
	s := guide.Compute(t.Context(), f.Inputs(t))
	found := false
	for _, a := range s.Agents {
		for _, r := range a.Runs {
			if r.ID != older {
				continue
			}
			found = true
			if r.Verification != agentid.Broken {
				t.Fatalf("older corrupted run was not checked: %+v", r)
			}
			for _, st := range a.Stages {
				if st.ID != agentid.RecordedStage && st.Fact.Established {
					t.Fatalf("older corrupt run gained tick: %+v", a)
				}
			}
		}
	}

	if !found {
		t.Fatal("older corrupted record disappeared")
	}
}

func TestAgentSnapshotAnchorBudgetAndCacheHead(t *testing.T) {
	for _, which := range []string{"oversized-anchor", "changed-head"} {
		t.Run(which, func(t *testing.T) {
			f := guidetest.Make(t, guidetest.Finished)
			first := guide.Compute(t.Context(), f.Inputs(t))
			checked := false
			for _, a := range first.Agents {
				for _, st := range a.Stages {
					checked = checked || st.ID == agentid.VerifiedStage && st.Fact.Established
				}
			}
			if !checked {
				t.Fatal("fixture lacked a checked ended run")
			}
			if which == "oversized-anchor" {
				file, err := os.OpenFile(f.Anchor, os.O_RDWR, 0600)
				if err != nil {
					t.Fatal(err)
				}
				err = file.Truncate(4<<20 + 1)
				closeErr := file.Close()
				if err != nil || closeErr != nil {
					t.Fatal(err, closeErr)
				}
			} else {
				b, err := os.ReadFile(f.Anchor)
				if err != nil {
					t.Fatal(err)
				}
				// A valid but different final anchored head must invalidate a cached result.
				pos := len(b) - 2
				if b[pos] == '0' {
					b[pos] = '1'
				} else {
					b[pos] = '0'
				}
				if err := os.WriteFile(f.Anchor, b, 0600); err != nil {
					t.Fatal(err)
				}
			}
			s := guide.Compute(t.Context(), f.Inputs(t))
			for _, a := range s.Agents {
				for _, r := range a.Runs {
					if r.ID != f.Runs[len(f.Runs)-1] {
						continue
					}
					if r.Verification == agentid.Verified || a.VerificationReason == "" {
						t.Fatalf("%s reused checked cache: %+v", which, a)
					}
					if which == "oversized-anchor" && !strings.Contains(r.VerificationReason, "4 MiB") {
						t.Fatalf("anchor budget not explained: %+v", r)
					}
				}
			}
		})
	}
}

func TestAgentSnapshotRunBudgetKeepsUncheckedRows(t *testing.T) {
	f := guidetest.Make(t, guidetest.Finished)
	// Copy a valid run start into new independently anchored records. Each id is
	// unique; selection and the expected unverified rows belong to this fixture.
	rd, err := ledger.OpenReader(filepath.Join(f.Ledger, f.Runs[1]))
	if err != nil {
		t.Fatal(err)
	}
	var start record.RunStartPayload
	for e, err := range rd.Iter() {
		if err != nil {
			t.Fatal(err)
		}
		if err := e.DecodePayload(&start); err != nil {
			t.Fatal(err)
		}
		break
	}
	if err := rd.Close(); err != nil {
		t.Fatal(err)
	}
	for n := range 35 {
		rid, err := identity.NewRunID(identity.HostID([]byte("budget")), guidetest.CheckTime.Add(time.Duration(n)*time.Minute), bytes.NewReader([]byte{1, 2, 3, byte(n)}))
		if err != nil {
			t.Fatal(err)
		}
		id := string(rid)
		w, err := ledger.Open(filepath.Join(f.Ledger, id), record.RunRef{ID: id, Agent: "budget"}, ledger.WithAnchor(ledger.NewFileChainAnchor(f.Anchor)))
		if err != nil {
			t.Fatal(err)
		}
		if err := w.WriteRunStart(start); err != nil {
			t.Fatal(err)
		}
		if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
			t.Fatal(err)
		}
	}
	s := guide.Compute(t.Context(), f.Inputs(t))
	checked, unchecked := 0, 0
	for _, a := range s.Agents {
		for _, r := range a.Runs {
			switch r.Verification {
			case agentid.Verified:
				checked++
			case agentid.Unchecked:
				unchecked++
				if !strings.Contains(r.VerificationReason, "budget") {
					t.Fatalf("skipped run unexplained: %+v", r)
				}
				for _, st := range a.Stages {
					if st.ID != agentid.RecordedStage && st.Fact.Established {
						t.Fatalf("budget gave tick: %+v", a)
					}
				}
			case agentid.Broken, agentid.CannotVerify:
				t.Fatalf("unexpected run verification: %+v", r)
			}
		}
	}
	if checked != 32 || unchecked != 5 {
		t.Fatalf("checked=%d unchecked=%d; want32+5 visible rows", checked, unchecked)
	}
}

func TestAgentSnapshotRefusesLinkedAnchor(t *testing.T) {
	f := guidetest.Make(t, guidetest.Finished)
	if err := os.Link(f.Anchor, f.Anchor+".link"); err != nil {
		t.Fatal(err)
	}
	s := guide.Compute(t.Context(), f.Inputs(t))
	if len(s.Agents) != 2 {
		t.Fatal("linked anchor made run rows disappear")
	}
	for _, a := range s.Agents {
		for _, st := range a.Stages {
			if st.ID != agentid.RecordedStage && st.Fact.Established {
				t.Fatalf("linked anchor established tick: %+v", a)
			}
		}
	}
}

func TestAgentSnapshotWarmCacheRejectsReplacementAndExtension(t *testing.T) {
	f := guidetest.Make(t, guidetest.Finished)
	id := f.Runs[len(f.Runs)-1]
	path := filepath.Join(f.Ledger, id, ledger.EventsFile)
	authentic, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	check := func(want agentid.Verification) {
		t.Helper()
		for _, a := range guide.Compute(t.Context(), f.Inputs(t)).Agents {
			for _, r := range a.Runs {
				if r.ID == id {
					if r.Verification != want {
						t.Errorf("verification=%v want %v: %+v", r.Verification, want, a)
					}
					if want != agentid.Verified {
						for _, st := range a.Stages {
							if st.ID != agentid.RecordedStage && st.Fact.Established {
								t.Errorf("mutated record gained tick: %+v", a)
							}
						}
					}
					return
				}
			}
		}
		t.Fatal("mutated run disappeared")
	}
	check(agentid.Verified)
	check(agentid.Verified) // Exercise the warmed affirmative entry before mutation.
	forged := bytes.Replace(authentic, []byte(`"exit"`), []byte(`"signal"`), 1)
	if bytes.Equal(authentic, forged) {
		t.Fatal("fixture did not change")
	}
	replacement := path + ".replacement"
	if err := os.WriteFile(replacement, forged, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacement, path); err != nil {
		t.Fatal(err)
	}
	check(agentid.Broken)
	// Restore a valid replacement and warm its new entry before appending bytes.
	if err := os.WriteFile(path, authentic, 0600); err != nil {
		t.Fatal(err)
	}
	check(agentid.Verified)
	check(agentid.Verified)
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		t.Fatal(err)
	}
	last := bytes.LastIndexByte(bytes.TrimSuffix(authentic, []byte("\n")), '\n') + 1
	_, err = file.Write(authentic[last:])
	closeErr := file.Close()
	if err != nil || closeErr != nil {
		t.Fatal(err, closeErr)
	}
	check(agentid.Broken)
}
