// SPDX-License-Identifier: Apache-2.0

package scan

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/grouptrust"
	"github.com/attention-span-ai/tego/internal/runscope"
	"github.com/attention-span-ai/tego/internal/scan/catalog"
	"github.com/attention-span-ai/tego/internal/scan/result"
	"github.com/attention-span-ai/tego/internal/testutil/answertest"
	"github.com/attention-span-ai/tego/internal/testutil/jsonschema"
	"golang.org/x/sys/unix"
)

func commandOptions(t *testing.T) Options {
	t.Helper()
	root, home := unitFixtureRoot(t), unitFixtureRoot(t)
	uid := uint32(os.Getuid())
	processFixture(t, root, 10, 1, 100, "/bin/self", []byte("self\x00"+markerSecret+"\x00"), 0)
	processFixture(t, root, 20, 1, 200, "/bin/claude", []byte("claude\x00--key="+markerSecret+"\x00"), 0)
	processFixture(t, root, 30, 1, 300, "/bin/python3", []byte("python3\x00bot.py\x00"+markerSecret+"\x00"), 1)
	writeProcFile(t, home, "passwd", []byte(fmt.Sprintf("me:x:%d:42::%s:/bin/sh\n", uid, home)))
	writeProcFile(t, home, "boot", []byte(testBoot+"\n"))
	metadataFixture(t, home, ".local/bin/claude", 0700)
	metadataFixture(t, home, ".claude", 0600)
	return Options{ReadCallerPasswd: fixtureCallerReader, ProcRoot: root, Passwd: filepath.Join(home, "passwd"), Boot: filepath.Join(home, "boot"), Directory: home, Path: "", Version: "dev", Caller: Caller{UID: uid, EUID: uid, PID: 10, CgroupNamespace: runscope.InitCgroupNS, PIDNamespace: InitPIDNS, Membership: answertest.Outside()}, Rows: catalog.Rows()}
}

func TestCollectOutputAndSchema(t *testing.T) {
	o := commandOptions(t)
	o.AllMine = true
	o.Check = true
	got := Collect(t.Context(), o)
	s := got.Snapshot
	if s.Counts.Running != 1 || s.Counts.Outside != 1 || s.Counts.Installed != 1 || s.Counts.Settings != 1 || s.Counts.Other != 1 || s.ExitCode() != 1 {
		t.Fatalf("counts/check: %+v %s", s.Counts, s.Check)
	}
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	var wire any
	if err = json.Unmarshal(b, &wire); err != nil {
		t.Fatal(err)
	}
	if err = jsonschema.Check("../../spec/scan/v1/schema.json", wire); err != nil {
		t.Fatal(err)
	}
	for _, verbose := range []bool{false, true} {
		var out, errs bytes.Buffer
		if err := result.Render(&out, &errs, s, false, verbose, nil); err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{"exe-name", "contents not read", "Not looked at:", "agents under a name no rule knows", "Tego cannot tell whether these are agents"} {
			if !strings.Contains(out.String(), want) {
				t.Fatalf("missing %s", want)
			}
		}
		if strings.Contains(out.String()+errs.String(), markerSecret) {
			t.Fatal("marker retained")
		}
	}
}

func TestCollectCheckPriority(t *testing.T) {
	for _, tc := range []struct {
		name    string
		outside bool
		want    int
	}{{"clean", false, 0}, {"unknown", false, 125}, {"outside priority", true, 1}} {
		t.Run(tc.name, func(t *testing.T) {
			o := commandOptions(t)
			o.Check = true
			if !tc.outside {
				if err := os.RemoveAll(filepath.Join(o.ProcRoot, "20")); err != nil {
					t.Fatal(err)
				}
			}
			if tc.name != "clean" {
				writeProcFile(t, o.ProcRoot, "99/status", []byte("bad"))
			}
			s := Collect(t.Context(), o).Snapshot
			if s.ExitCode() != tc.want {
				t.Fatalf("code %d check %s", s.ExitCode(), s.Check)
			}
		})
	}
}

func TestCollectRefusal(t *testing.T) {
	o := commandOptions(t)
	o.Caller.Sudo = true
	o.Check = true
	s := Collect(t.Context(), o).Snapshot
	if s.ExitCode() != 125 || len(s.Items) != 0 || !strings.Contains(strings.Join(s.Exclusions, ","), "scan-not-performed") {
		t.Fatal("refusal lost")
	}
}

type discardedRead struct {
	processFiles
	calls int
}

func (p *discardedRead) read(string, int) ([]byte, error) { p.calls++; return nil, errSize }
func TestBudgetChargesDiscardedReads(t *testing.T) {
	input := &discardedRead{}
	b := &budgetProc{remaining: 9}
	remaining := maxProcessInputBytes
	p := &budgetProcess{processFiles: input, budget: b, remaining: &remaining}
	_, _ = p.read("cmdline", 4)
	if b.remaining >= 9 {
		t.Fatal("discarded input cost nothing")
	}
	for range 8 {
		_, _ = p.read("cmdline", 4)
	}
	if input.calls > 2 || b.remaining != 0 {
		t.Fatalf("discarded read bypass: calls %d remaining %d", input.calls, b.remaining)
	}
}

func TestMetadataLinkInputBound(t *testing.T) {
	home := t.TempDir()
	target := metadataFixture(t, home, "program", 0700)
	link := filepath.Join(home, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	ctx := context.WithValue(t.Context(), metadataBudgetKey{}, &metadataBudget{remaining: 1})
	fd, _, err := metadataPath(ctx, link, true)
	if fd != nil {
		_ = fd.Close()
	}
	if err != errLimit {
		t.Fatalf("link input limit bypassed: %v", err)
	}
}

func TestCollectUnreadableProgramCheckModes(t *testing.T) {
	for _, tc := range []struct {
		name                string
		allow, outside, gap bool
		want                int
	}{
		{"strict", false, false, false, 3},
		{"explicit accept", true, false, false, 0},
		{"outside priority", false, true, false, 1},
		{"gap priority", true, false, true, 125},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := commandOptions(t)
			o.Check, o.AllowUnreadablePrograms = true, tc.allow
			if tc.outside {
				processFixture(t, o.ProcRoot, 40, 1, 400, "/bin/codex", []byte("codex\x00"), 0)
			}
			if tc.gap {
				writeProcFile(t, o.ProcRoot, "99/status", []byte("bad"))
			}
			out := collect(t.Context(), o, func(ctx context.Context, fs procAccess, root string, uid uint32, rows []catalog.Row) processSnapshot {
				spy := &spyProc{procAccess: fs, t: t, opened: map[int]bool{}, ownerHook: func(pid int, owner uint32, err error) (uint32, error) {
					if pid == 20 {
						return 0, nil
					}
					return owner, err
				}, linkHook: func(pid int, name, value string, err error) (string, error) {
					if pid == 20 && name == "exe" {
						return "", unix.EACCES
					}
					return value, err
				}}
				return readProcesses(ctx, spy, root, uid, rows)
			})
			s := out.Snapshot
			if got := s.ExitCode(); got != tc.want {
				t.Fatalf("exit %d want %d: %+v", got, tc.want, s)
			}
			if s.Counts.UnreadablePrograms != 1 || len(s.UnreadableProgramPIDs) != 1 || s.UnreadableProgramPIDs[0] != 20 || s.Status != "partial" {
				t.Fatalf("unreadable accounting %+v", s)
			}
			if _, err := result.Encode(s); err != nil {
				t.Fatal(err)
			}
			var text, errs bytes.Buffer
			if err := result.Render(&text, &errs, s, false, false, nil); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(text.String(), "1 of your processes do not let their program file be read; pids: 20") {
				t.Fatal(text.String())
			}
		})
	}
}

func TestCollectProcessInputBudget(t *testing.T) {
	for _, exhausted := range []bool{false, true} {
		o := commandOptions(t)
		o.Check = true
		got := collect(t.Context(), o, func(ctx context.Context, fs procAccess, root string, uid uint32, rows []catalog.Row) processSnapshot {
			// Keep the command's caller-read allocation, replacing only the input.
			fs.(*budgetProc).procAccess = &generatedProc{count: 1000, realistic: !exhausted, largeArgv: exhausted}
			return readProcesses(ctx, fs, root, uid, rows)
		}).Snapshot
		read := 0
		for _, source := range got.Sources {
			if source.Kind == "A" {
				read += source.Read
			}
		}
		byteLimited := strings.Contains(strings.Join(got.Limits, ","), "byte-limit")
		if !exhausted && (got.ExitCode() != 0 || read != 1000 || byteLimited) {
			t.Fatalf("ordinary process input: check=%s read=%d limits=%v", got.Check, read, got.Limits)
		}
		if exhausted && (got.Status != "partial" || got.ExitCode() != 125 || !byteLimited) {
			t.Fatalf("input cap not a stated gap: status=%s check=%s limits=%v", got.Status, got.Check, got.Limits)
		}
		if _, err := result.Encode(got); err != nil {
			t.Fatal(err)
		}
	}
}

func TestCollectOmitsReplacementPathBeforeEncoding(t *testing.T) {
	o := commandOptions(t)
	o.Directory += "\ufffd"
	s := Collect(t.Context(), o).Snapshot
	if s.Project != nil {
		t.Fatal("retained a path the saved-result reader refuses")
	}
	omitted := false
	for _, source := range s.Sources {
		omitted = omitted || source.Kind == "meta" && source.State == "not-read" && source.Reason == "unsupported" && source.Locator == nil
	}
	if !omitted {
		t.Fatal("omitted path was not disclosed")
	}
	if _, err := result.Encode(s); err != nil {
		t.Fatalf("omitted metadata broke whole result: %v", err)
	}
}

func TestCallerAccountRepairSurvivesRefusal(t *testing.T) {
	o := commandOptions(t)
	o.ReadCallerPasswd = fixtureAccountReader(o.Directory)
	if err := os.Chmod(o.Directory, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(o.Passwd, 0664); err != nil {
		t.Fatal(err)
	}
	s := Collect(t.Context(), o).Snapshot
	if s.ExitCode() != 125 || !slices.Contains(s.Exclusions, "scan-not-performed") {
		t.Fatalf("not a pre-discovery refusal: %+v", s)
	}
	found := false
	for _, src := range s.Sources {
		if src.Kind == "meta" && src.Reason == "owner" && strings.Contains(src.AccountRepair, "account file") && strings.Contains(src.AccountRepair, "run the scan again") {
			found = true
		}
	}
	if !found {
		t.Fatal("caller refused without the collector's named account-file repair")
	}
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := result.Decode(b); err != nil {
		t.Fatalf("caller repair is not a valid saved-result shape: %v", err)
	}
	for name, mutate := range map[string]func(*result.Snapshot){
		"not a failed scan":                func(bad *result.Snapshot) { bad.Status = "partial" },
		"discovery without group evidence": func(bad *result.Snapshot) { bad.Sources[0].Kind = "D" },
		"discovery already ran": func(bad *result.Snapshot) {
			bad.Exclusions = slices.DeleteFunc(bad.Exclusions, func(x string) bool { return x == "scan-not-performed" })
		},
	} {
		bad := s
		bad.Sources = append([]result.Source(nil), s.Sources...)
		bad.Exclusions = append([]string(nil), s.Exclusions...)
		mutate(&bad)
		encoded, e := json.Marshal(bad)
		if e != nil {
			t.Fatal(e)
		}
		if _, e := result.Decode(encoded); e == nil {
			t.Errorf("caller repair accepted for %s", name)
		}
	}

}

func fixtureAccountReader(root string) func(string) ([]byte, error) {
	return func(path string) ([]byte, error) {
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return nil, err
		}
		return grouptrust.ReadAccountFileAt(root, "/"+rel, os.Getuid())
	}
}

// Ordinary collection fixtures isolate caller identity from account placement.
func fixtureCallerReader(path string) ([]byte, error) {
	return readLocalMetadata(context.Background(), path, maxProcText, uint32(os.Getuid()))
}
