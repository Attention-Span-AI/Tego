// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/attention-span-ai/tego/internal/check/receipt"
	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// resealed is the kept receipt given, edited by edit and sealed again: binding.receipt_sha256 is the sha256 of the
// receipt without it, which anyone who writes the file can recompute (the binding says so), so an edit that is sealed
// again is what a forger writes.
func resealed(t *testing.T, good []byte, edit func(m map[string]any)) []byte {
	t.Helper()
	var m map[string]any
	dec := json.NewDecoder(bytes.NewReader(good))
	dec.UseNumber()
	if err := dec.Decode(&m); err != nil {
		t.Fatal(err)
	}
	edit(m)
	b, ok := m["binding"].(map[string]any)
	if !ok {
		t.Fatal("the kept receipt has no binding")
	}
	delete(b, "receipt_sha256")
	data, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	b["receipt_sha256"] = hex.EncodeToString(sum[:])
	out, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// figures edits a receipt's exit code and refusal count, two figures a forger would change.
func figures(m map[string]any) {
	m["exit_code"] = json.Number("3")
	m["refusals"].(map[string]any)["total"] = json.Number("7")
}

// namedMaker makes the receipt say a tego of this version and commit made it.
func namedMaker(by receipt.MadeBy) func(map[string]any) {
	return func(m map[string]any) {
		rb := m["binding"].(map[string]any)["receipt_by"].(map[string]any)
		rb["tego_version"], rb["commit"] = by.TegoVersion, by.Commit
	}
}

// keepAndRead is a kept run and the bytes tego run kept for it.
func keepAndRead(t *testing.T) (id, dir, path string, good []byte) {
	t.Helper()
	id, dir, anchor, res := keptRun(t)
	if _, warn := finishKeeping(t.Context(), anchor, res); warn != "" {
		t.Fatal(warn)
	}
	path = filepath.Join(dir, ledger.ReceiptFile)
	good, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return id, dir, path, good
}

// forgedMakers are the builds a forger can name as the maker of a copy: a release that does not exist, a later one, a
// build with uncommitted changes, one with no stamp, and an empty one.
var forgedMakers = map[string]receipt.MadeBy{
	"a release that does not exist": {TegoVersion: "v9.9.9", Commit: "0123456789abcdef0123456789abcdef01234567"},
	"a later release":               otherBuilds["a later release"],
	"a dirty build":                 otherBuilds["a dirty build"],
	"a build with no stamp":         otherBuilds["a build with no stamp"],
	"no maker at all":               {},
}

// TestVerifyRefusesAKeptReceiptThatNamesAnotherMaker is the forge the second review found: change a figure in the kept
// receipt, change binding.receipt_by, seal again. Under the build that kept the copy, the changed figure alone is
// exit 1 (facts); a changed receipt_by must not turn that into "not compared" and exit 0, under that build or under
// another. The record's run_start names the build that ran the run, and a copy kept by tego run is made by it.
func TestVerifyRefusesAKeptReceiptThatNamesAnotherMaker(t *testing.T) {
	id, _, path, good := keepAndRead(t)
	put := func(b []byte) {
		t.Helper()
		if err := os.WriteFile(path, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	verify := func(checking receipt.MadeBy) (int, string, string) {
		useStamp(t, checking)
		return run(t, "receipt", id, "--verify")
	}

	// controls: the same edit with the maker left alone is a difference under the build that kept the copy, and the
	// untouched copy is no difference under another build
	put(resealed(t, good, figures))
	if code, out, errs := verify(releasedStamp); code != identity.ExitFinding || !strings.Contains(errs, "differs from it: facts") || strings.Contains(out, "Kept receipt: ") {
		t.Fatalf("control, a figure edited and sealed again: exit %d\n%s\n%s", code, out, errs)
	}
	put(good)
	if code, out, errs := verify(otherBuilds["a later release"]); code != identity.ExitOK || !strings.Contains(out, "not compared") {
		t.Fatalf("control, the intact copy under a later release: exit %d\n%s\n%s", code, out, errs)
	}

	for name, forged := range forgedMakers {
		for _, changed := range []string{"figures", "nothing else"} {
			for _, checking := range []receipt.MadeBy{releasedStamp, otherBuilds["a later release"], otherBuilds["a dirty build"]} {
				t.Run(name+"/"+changed+"/checked by "+checking.TegoVersion, func(t *testing.T) {
					put(resealed(t, good, func(m map[string]any) {
						if changed == "figures" {
							figures(m)
						}
						namedMaker(forged)(m)
					}))
					code, out, errs := verify(checking)
					if checking == forged && receipt.Exact(checking) {
						// the checking build's own name: this build compares the figures, so an edited one differs there, and an
						// intact copy that merely names this tego as its maker says nothing false
						if changed == "figures" && (code != identity.ExitFinding || !strings.Contains(errs, "differs from it: facts")) ||
							changed != "figures" && (code != identity.ExitOK || !strings.Contains(out, "matches the record")) {
							t.Fatalf("exit %d\nstdout %s\nstderr %s", code, out, errs)
						}
						return
					}
					if code != identity.ExitFinding || !strings.Contains(out, "Chain: ") || strings.Contains(out, "Kept receipt: ") ||
						!strings.Contains(errs, "the record verified; only the kept receipt") || !strings.Contains(errs, "as its maker") ||
						!strings.Contains(errs, "["+codeKeptReceipt+"]") {
						t.Fatalf("exit %d\nstdout %s\nstderr %s", code, out, errs)
					}
				})
			}
		}
	}
	// a forger who names the checking build itself is compared, figure for figure
	put(resealed(t, good, func(m map[string]any) { figures(m); namedMaker(otherBuilds["a later release"])(m) }))
	if code, _, errs := verify(otherBuilds["a later release"]); code != identity.ExitFinding || !strings.Contains(errs, "differs from it: facts") {
		t.Errorf("a figure edited under the checking build's own name: exit %d (stderr %q)", code, errs)
	}
	put(good)
	if code, out, errs := verify(releasedStamp); code != identity.ExitOK || !strings.Contains(out, "matches the record") {
		t.Errorf("restored: exit %d\n%s\n%s", code, out, errs)
	}
}

// TestVerifyRefusesAKeptReceiptOfABuildThatKeepsNone: a run that a dirty build, or one with no stamp, ran has a
// run_start that names it, and no such build keeps a copy, so a receipt.json that names that same build was written by
// someone else: exit 1, whatever tego checks it.
func TestVerifyRefusesAKeptReceiptOfABuildThatKeepsNone(t *testing.T) {
	for _, by := range []string{"a dirty build", "a build with no stamp"} {
		t.Run(by, func(t *testing.T) {
			maker := otherBuilds[by]
			useStamp(t, maker)
			id, dir := stampedRun(t, maker)
			root := filepath.Dir(dir)
			prev := ledgerRootOf
			t.Cleanup(func() { ledgerRootOf = prev })
			ledgerRootOf = func(*config.Machine) (string, error) { return root, nil }
			code, out, errs := run(t, "receipt", id, "--json")
			if code != identity.ExitOK {
				t.Fatalf("receipt --json: exit %d (stderr %q)", code, errs)
			}
			// the receipt a forger can build for it with this very tego, planted where tego run would have kept one
			planted := filepath.Join(dir, ledger.ReceiptFile)
			if err := os.WriteFile(planted, []byte(out), 0o600); err != nil {
				t.Fatal(err)
			}
			for _, checking := range []receipt.MadeBy{maker, releasedStamp} {
				useStamp(t, checking)
				code, out, errs := run(t, "receipt", id, "--verify")
				if code != identity.ExitFinding || !strings.Contains(out, "Chain: ") || !strings.Contains(errs, "a build that keeps no receipt") {
					t.Errorf("checked by %s: exit %d\nstdout %s\nstderr %s", checking.TegoVersion, code, out, errs)
				}
			}
		})
	}
}

// TestVerifyRefusesAKeptReceiptInARunOfAnOlderRevision is the upgrade path the third review found: a run made by a
// release that never kept a copy (record revision 30 and before) names that release exactly in run_start, so a
// receipt.json an agent of that run wrote, naming the same release as its maker and sealed again, passed the maker rule and
// got "figures were not compared" and exit 0 after the upgrade. No build that wrote such a record kept a copy, so
// whatever stands at the name is not tego's: exit 1, with or without edited figures, under any checking build.
func TestVerifyRefusesAKeptReceiptInARunOfAnOlderRevision(t *testing.T) {
	// the build that ran it compares the figures itself, so it needs no maker rule: an edited figure is a difference in
	// facts, and an intact copy is what the record computes (checked below)
	checkers := map[string]receipt.MadeBy{"a later release": otherBuilds["a later release"], "a dirty build": otherBuilds["a dirty build"]}
	plant := func(t *testing.T, minor int, edit func(map[string]any)) (id, path string) {
		t.Helper()
		useStamp(t, releasedStamp)
		id, dir := stampedRunAt(t, releasedStamp, minor)
		root := filepath.Dir(dir)
		prev := ledgerRootOf
		t.Cleanup(func() { ledgerRootOf = prev })
		ledgerRootOf = func(*config.Machine) (string, error) { return root, nil }
		code, out, errs := run(t, "receipt", id, "--json")
		if code != identity.ExitOK {
			t.Fatalf("receipt --json: exit %d (stderr %q)", code, errs)
		}
		path = filepath.Join(dir, ledger.ReceiptFile)
		if err := os.WriteFile(path, resealed(t, []byte(out), edit), 0o600); err != nil {
			t.Fatal(err)
		}
		return id, path
	}
	for _, minor := range []int{30, record.MinorEveryLaunch - 1, 0} {
		for _, changed := range []string{"figures", "nothing"} {
			for cname, checking := range checkers {
				t.Run(fmt.Sprintf("revision %d/%s/checked by %s", minor, changed, cname), func(t *testing.T) {
					// the forger names the run's own, exact build as the maker, so the maker rule has nothing to object to
					id, _ := plant(t, minor, func(m map[string]any) {
						if changed == "figures" {
							figures(m)
						}
						namedMaker(releasedStamp)(m)
					})
					useStamp(t, checking)
					code, out, errs := run(t, "receipt", id, "--verify")
					if code != identity.ExitFinding || !strings.Contains(out, "Chain: ") || strings.Contains(out, "Kept receipt: ") ||
						!strings.Contains(errs, "the record verified; only the kept receipt") ||
						!strings.Contains(errs, fmt.Sprintf("at record revision %d, a build that keeps no receipt", minor)) ||
						!strings.Contains(errs, "["+codeKeptReceipt+"]") {
						t.Fatalf("exit %d\nstdout %s\nstderr %s", code, out, errs)
					}
				})
			}
		}
	}
	for _, minor := range []int{30, 0} {
		t.Run(fmt.Sprintf("revision %d/checked by the build that ran it", minor), func(t *testing.T) {
			id, _ := plant(t, minor, func(m map[string]any) { figures(m); namedMaker(releasedStamp)(m) })
			useStamp(t, releasedStamp)
			if code, _, errs := run(t, "receipt", id, "--verify"); code != identity.ExitFinding || !strings.Contains(errs, "differs from it: facts") {
				t.Fatalf("figures edited: exit %d\nstderr %s", code, errs)
			}
		})
	}
	// controls: the same copy, edited the same way, in a run of the revision this build writes is what the maker rule
	// already decided (the intact copy under another exact build is the note and exit 0, the figures edited under the
	// build that ran it are a difference in facts), so the revision is the only thing that turned those into exit 1
	t.Run("control, the revision this build writes", func(t *testing.T) {
		id, _ := plant(t, record.MinorEveryLaunch, namedMaker(releasedStamp))
		useStamp(t, otherBuilds["a later release"])
		if code, out, errs := run(t, "receipt", id, "--verify"); code != identity.ExitOK || !strings.Contains(out, "not compared") {
			t.Fatalf("the intact copy under a later release: exit %d\nstdout %s\nstderr %s", code, out, errs)
		}
		useStamp(t, releasedStamp)
		id, _ = plant(t, record.MinorEveryLaunch, func(m map[string]any) { figures(m); namedMaker(releasedStamp)(m) })
		if code, _, errs := run(t, "receipt", id, "--verify"); code != identity.ExitFinding || !strings.Contains(errs, "differs from it: facts") {
			t.Fatalf("figures edited under the build that ran it: exit %d\nstderr %s", code, errs)
		}
	})
}

// TestVerifyKeptReceiptOfALaterFormat: a copy kept by a release that raised the receipt or the binding version is a
// receipt this tego cannot read. The record verified, so the message says that only the copy is unchecked and how to
// check it; the exit stays "could not check" (125), never 0: any file can claim a later version, so a pass here would
// let a planted file through.
func TestVerifyKeptReceiptOfALaterFormat(t *testing.T) {
	id, _, path, good := keepAndRead(t)
	for name, edit := range map[string]func(map[string]any){
		"a later receipt version": func(m map[string]any) { m["receipt_v"] = json.Number("2") },
		"a later binding version": func(m map[string]any) { m["binding"].(map[string]any)["v"] = json.Number("9") },
	} {
		t.Run(name, func(t *testing.T) {
			if err := os.WriteFile(path, resealed(t, good, edit), 0o600); err != nil {
				t.Fatal(err)
			}
			code, out, errs := run(t, "receipt", id, "--verify")
			if code != identity.ExitError || !strings.Contains(out, "Chain: ") || strings.Contains(out, "Kept receipt: ") ||
				!strings.Contains(errs, "in a form this tego does not read") || !strings.Contains(errs, "the record itself verified") ||
				!strings.Contains(errs, "check it with the tego that ran the run") {
				t.Fatalf("exit %d\nstdout %s\nstderr %s", code, out, errs)
			}
		})
	}
}

// TestVerifyAPlantedFileIsOnlyTheCopyThatDiffers: whatever stands at receipt.json when the run ends (an agent that can
// write its run folder may put anything there) is left as it is, and --verify, after the chain line, says that the record
// verified and only the kept copy differs: exit 1, never a hang on a pipe, a followed link or a pass.
func TestVerifyAPlantedFileIsOnlyTheCopyThatDiffers(t *testing.T) {
	for name, plant := range map[string]func(t *testing.T, path, other string){
		"text": func(t *testing.T, path, _ string) {
			if err := os.WriteFile(path, []byte("planted\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"an empty file": func(t *testing.T, path, _ string) {
			if err := os.WriteFile(path, nil, 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"a JSON object that is no receipt": func(t *testing.T, path, _ string) {
			if err := os.WriteFile(path, []byte(`{"receipt_v":1,"run":"x"}`), 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"another run's receipt": func(t *testing.T, path, other string) {
			b, err := os.ReadFile(other)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, b, 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"a link": func(t *testing.T, path, other string) {
			if err := os.Symlink(other, path); err != nil {
				t.Fatal(err)
			}
		},
		"a pipe": func(t *testing.T, path, _ string) {
			if err := syscall.Mkfifo(path, 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"a directory": func(t *testing.T, path, _ string) {
			if err := os.Mkdir(path, 0o700); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			// the receipt of a second run, kept as tego run keeps it, for the plants that copy or point to one
			_, _, otherPath, _ := keepAndRead(t)
			id, dir, anchor, res := keptRun(t)
			path := filepath.Join(dir, ledger.ReceiptFile)
			plant(t, path, otherPath)
			if _, warn := finishKeeping(t.Context(), anchor, res); !strings.Contains(warn, "already in the run directory") || strings.Count(warn, "\n") != 1 {
				t.Fatalf("the run end must say once that the name was taken: %q", warn)
			}
			code, out, errs := run(t, "receipt", id, "--verify")
			if code != identity.ExitFinding || !strings.Contains(out, "Chain: ") || strings.Contains(out, "Kept receipt: ") ||
				!strings.Contains(errs, "the record verified; only the kept receipt") || !strings.Contains(errs, "["+codeKeptReceipt+"]") {
				t.Fatalf("exit %d\nstdout %s\nstderr %s", code, out, errs)
			}
		})
	}
}

// TestSummaryKeepsItsReceiptWhenTheExecutableCannotBeHashed: binding the receipt needs the hash of tego's own executable,
// and a tego that is executable but not readable (mode 0711) has none. The end summary is then what it is with no copy
// kept, built in the same one pass; only the copy is not kept, with one warning that says why.
func TestSummaryKeepsItsReceiptWhenTheExecutableCannotBeHashed(t *testing.T) {
	_, dir, anchor, res := keptRun(t)
	plain := summarizeRun(t.Context(), &config.Machine{}, anchor, res, agent.RecordSummary)
	prev := executableSHA256
	t.Cleanup(func() { executableSHA256 = prev })
	executableSHA256 = func() (string, error) { return "", os.ErrPermission }
	s, warn := finishKeeping(t.Context(), anchor, res)
	if s == nil || s.rc == nil || s.err != nil || s.kept != nil {
		t.Fatalf("summary made %v, receipt %v, copy %v", s != nil, s != nil && s.rc != nil, s != nil && s.kept != nil)
	}
	if got, want := s.text(), plain.text(); got != want {
		t.Errorf("the summary changed when the hash failed:\n%s\nwant\n%s", got, want)
	}
	if !strings.Contains(warn, "could not be bound") || strings.Count(warn, "\n") != 1 {
		t.Errorf("warning %q", warn)
	}
	if _, err := os.Lstat(filepath.Join(dir, ledger.ReceiptFile)); !os.IsNotExist(err) {
		t.Errorf("a copy was kept: %v", err)
	}
}
