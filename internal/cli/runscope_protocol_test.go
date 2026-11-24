// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"encoding/gob"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/guide/guidetest"
	"github.com/attention-span-ai/tego/internal/platform/proc"
	"github.com/attention-span-ai/tego/internal/runscope"
	rtcgroup "github.com/attention-span-ai/tego/internal/runtime/cgroup"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// A separate wire shape lets this test exercise rejection by older decoders too.
type scopeWireRequest struct {
	Argv, Env []string
	Rehearse  bool
}

func TestScopeProtocolHelper(t *testing.T) {
	mode := os.Getenv("TEGO_SCOPE_PROTOCOL_HELPER")
	if mode == "" {
		return
	}
	marker := os.Getenv("SCOPE_DISPATCH_MARKER")
	selfAnswer = func() runscope.Answer {
		if mode == "environment" && (os.Getenv("DUP") != "first" || os.Getenv("SYSTEMD_ADDED") != "") {
			return answerGoverned()
		}
		switch mode {
		case "nested":
			return answerGoverned()
		case "unknown":
			return answerUnknown()
		case "zero":
			return runscope.Answer{}
		}
		return answerOutside()
	}
	if mode == "undumpable-refused" {
		makeUndumpable = func() error { return errors.New("refused by the test") }
	}
	scopePlacement = func() error {
		if mode == "outside" {
			return rtcgroup.ErrBesideSubtree
		}
		return nil
	}
	commandTable = map[string]func() Command{}
	for _, name := range []string{"run", "doctor", "setup", "start", "machine"} {
		register(func() Command {
			return Command{Name: name, Raw: func(context.Context, []string, io.Writer, io.Writer) int {
				if err := os.WriteFile(marker, []byte("dispatched"), 0600); err != nil {
					return 99
				}
				return 37
			}}
		})
	}
	os.Exit(scopedMain(context.Background(), io.Discard, io.Discard))
}

func TestScopeProtocolBeforeCommit(t *testing.T) {
	for _, tc := range []struct {
		name, mode         string
		argv, env          []string
		rehearse, dispatch bool
		reason             byte
	}{
		{name: "environment before membership", mode: "environment", argv: []string{"tego", "run"}, env: []string{"DUP=first", "DUP=second"}, dispatch: true, reason: 1},
		{name: "malformed environment", argv: []string{"tego", "run"}, env: []string{"BROKEN"}, reason: 5},
		{name: "empty environment name", argv: []string{"tego", "run"}, env: []string{"=value"}, reason: 5},
		{name: "nul environment", argv: []string{"tego", "run"}, env: []string{"KEY=a\x00b"}, reason: 5},
		{name: "not a scope command", argv: []string{"tego", "rules", "allow"}, reason: 2},
		{name: "nested", mode: "nested", argv: []string{"tego", "run"}, reason: 3},
		{name: "unknown membership", mode: "unknown", argv: []string{"tego", "run"}, reason: 3},
		{name: "the zero answer", mode: "zero", argv: []string{"tego", "run"}, reason: 3},
		{name: "unknown membership, rehearsal", mode: "unknown", argv: []string{"tego", "doctor"}, rehearse: true, reason: 3},
		// The hold comes before the request is read: the request that would be reason 5 (a malformed environment) is 6.
		{name: "the process cannot be made undumpable, before the request is read", mode: "undumpable-refused", argv: []string{"tego", "run"}, env: []string{"BROKEN"}, reason: 6},
		{name: "placement", mode: "outside", argv: []string{"tego", "run"}, reason: 4},
		{name: "machine test", argv: []string{"tego", "machine", "test"}, dispatch: true, reason: 1},
		{name: "machine check rehearsal", argv: []string{"tego", "machine", "check"}, rehearse: true, reason: 1},
		{name: "doctor rehearsal", argv: []string{"tego", "doctor"}, rehearse: true, reason: 1},
		{name: "setup rehearsal", argv: []string{"tego", "setup"}, rehearse: true, reason: 1},
		{name: "start rehearsal", argv: []string{"tego", "start"}, rehearse: true, reason: 1},
		{name: "doctor cannot relocate", argv: []string{"tego", "doctor"}, reason: 2},
		{name: "machine other verb", argv: []string{"tego", "machine", "other"}, rehearse: true, reason: 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mode := tc.mode
			if mode == "" {
				mode = "normal"
			}
			marker := filepath.Join(t.TempDir(), "dispatch")
			rd, send, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer rd.Close()
			defer send.Close()
			receive, wr, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer receive.Close()
			defer wr.Close()
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestScopeProtocolHelper$")
			cmd.Env = append(os.Environ(), "TEGO_SCOPE_PROTOCOL_HELPER="+mode, "SCOPE_DISPATCH_MARKER="+marker, "SYSTEMD_ADDED=must-disappear")
			cmd.ExtraFiles = []*os.File{rd, wr}
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			defer func() { _ = cmd.Process.Kill() }()
			_ = rd.Close()
			_ = wr.Close()
			if err := gob.NewEncoder(send).Encode(scopeWireRequest{Argv: tc.argv, Env: tc.env, Rehearse: tc.rehearse}); err != nil {
				t.Fatal(err)
			}
			_ = receive.SetReadDeadline(time.Now().Add(5 * time.Second))
			var reason [1]byte
			if _, err := io.ReadFull(receive, reason[:]); err != nil || reason[0] != tc.reason {
				t.Errorf("reason=%v error=%v, want %d", reason, err, tc.reason)
			}
			// A rehearsing child must not dispatch even when a hostile sender grants permission.
			_, _ = send.Write([]byte{1})
			_ = send.Close()
			err = cmd.Wait()
			want := 125
			if tc.dispatch {
				want = 37
			} else if tc.reason == 1 {
				want = 0
			}
			got := 0
			if ee, ok := err.(*exec.ExitError); ok {
				got = ee.ExitCode()
			} else if err != nil {
				t.Fatal(err)
			}
			if got != want {
				t.Errorf("exit=%d, want %d", got, want)
			}
			_, statErr := os.Stat(marker)
			if tc.dispatch != (statErr == nil) {
				t.Errorf("dispatch=%v, want %v", statErr == nil, tc.dispatch)
			}
		})
	}
}

func TestSetupRehearsesInPlace(t *testing.T) {
	for _, noScope := range []bool{false, true} {
		t.Run(map[bool]string{false: "scope", true: "no-scope"}[noScope], func(t *testing.T) {
			onFixture(t, guidetest.Finished)
			scopeStands(t)
			calls := 0
			scopeExec = func(_ context.Context, p scopePlan, out io.Writer) (int, error) {
				calls++
				if !p.Request.Rehearse {
					t.Error("setup relocated")
				}
				return 0, nil
			}
			args := []string{"setup", "--json"}
			if noScope {
				args = append(args, "--no-scope")
			}
			code, out, errs := run(t, args...)
			want := 1
			if noScope {
				want = 0
			}
			if code != 0 || calls != want {
				t.Fatalf("exit=%d calls=%d want=%d stdout=%s stderr=%s", code, calls, want, out, errs)
			}
			if strings.Contains(errs, "opened a user scope for this run") {
				t.Fatal("rehearsal announced relocation")
			}
		})
	}
}

func TestScopeRehearsalParentNeverCommits(t *testing.T) {
	old := scopeCommandFor
	defer func() { scopeCommandFor = old }()
	scopeCommandFor = func(string, ...string) *proc.Cmd {
		return proc.Command(os.Args[0], "-test.run=^TestScopeProtocolHelper$")
	}
	for _, failure := range []bool{false, true} {
		var out bytes.Buffer
		mode := "normal"
		if failure {
			mode = "outside"
		}
		code, err := executeUserScope(t.Context(), scopePlan{Runner: "/usr/bin/systemd-run", Binary: "/proc/self/exe", Env: append(os.Environ(), "TEGO_SCOPE_PROTOCOL_HELPER="+mode), Request: scopeRequest{Argv: []string{"tego", "doctor"}, Rehearse: true}}, &out)
		if failure {
			if err == nil || !strings.Contains(err.Error(), "still cannot place") {
				t.Fatalf("lost reason: %v", err)
			}
		} else if err != nil || code != 0 {
			t.Fatalf("rehearsal code=%d error=%v", code, err)
		}
		if out.Len() != 0 {
			t.Fatalf("rehearsal output %q", out.String())
		}
	}
}

func TestDoctorRehearsesBeforeReadingState(t *testing.T) {
	for _, args := range [][]string{{"doctor"}, {"doctor", "--no-scope"}, {"machine", "check"}, {"machine", "check", "--no-scope"}, {"doctor", "--require", "unknown"}} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			scopeStands(t)
			calls := 0
			scopeExec = func(context.Context, scopePlan, io.Writer) (int, error) { calls++; return 0, nil }
			old := machineGuard
			machineGuard = func(*config.Machine) error { return errors.New("stop after rehearsal") }
			t.Cleanup(func() { machineGuard = old })
			run(t, args...)
			want := 1
			if len(args) > 1 && (args[len(args)-1] == "--no-scope" || args[len(args)-1] == "unknown") {
				want = 0
			}
			if calls != want {
				t.Fatalf("rehearsals=%d, want %d", calls, want)
			}
		})
	}
}

func TestFailedRehearsalKeepsTheInPlaceFinding(t *testing.T) {
	onFixture(t, guidetest.NotReady)
	scopeStands(t)
	scopeExec = func(context.Context, scopePlan, io.Writer) (int, error) {
		return 0, errors.New("re-entered placement refused")
	}
	code, _, errs := run(t, "setup", "--json")
	if code != identity.ExitFinding || !strings.Contains(errs, "re-entered placement refused") || strings.Contains(errs, "opened a user scope for this run") {
		t.Fatalf("exit=%d stderr=%s", code, errs)
	}
}

// TestRehearsalThatCannotTellStaysInPlace: doctor, machine check and start from a shell that cannot be shown to be
// outside every run (the rule's unknown) try no scope, say why once under [governed], with the line a person can
// act on first where there is one, and go on to their in-place report.
func TestRehearsalThatCannotTellStaysInPlace(t *testing.T) {
	for _, tc := range []struct {
		args []string
		a    runscope.Answer
		want string
	}{
		{[]string{"doctor"}, runscope.Unproven(runscope.CauseWSLLauncherUnproven, nil),
			"tego doctor: no user scope was tried: this process cannot be shown to be outside every tego run: on WSL"},
		{[]string{"machine", "check"}, runscope.Unproven(runscope.CauseUserNamespace, nil),
			"tego machine check: no user scope was tried: this process cannot be shown to be outside every tego run: "},
		{[]string{"doctor"}, runscope.Unproven(runscope.CauseNoUserManager, nil),
			"tego doctor: your user session is not up"},
	} {
		scopeStands(t)
		selfAnswer = func() runscope.Answer { return tc.a }
		scopeExec = func(context.Context, scopePlan, io.Writer) (int, error) {
			t.Fatalf("%v: a scope was tried for a process that cannot be shown to be outside every run", tc.args)
			return 0, nil
		}
		old := machineGuard
		machineGuard = func(*config.Machine) error { return errors.New("stop after rehearsal") }
		_, _, errs := run(t, tc.args...)
		machineGuard = old
		if !strings.Contains(errs, tc.want) || !strings.Contains(errs, "what follows describes this shell as it is") ||
			!strings.Contains(errs, "["+codeGoverned+"]") || strings.Contains(errs, "a governed agent") || strings.Contains(errs, "could not open a user scope") {
			t.Errorf("%v with %s: stderr:\n%s", tc.args, runscope.Describe(tc.a).Cause, errs)
		}
	}
}

func TestScopeRequiresTheSystemManagerAtTheTop(t *testing.T) {
	scopeStands(t)
	scopeInitCgroup = func() bool { return false }
	scopeExec = func(context.Context, scopePlan, io.Writer) (int, error) {
		t.Fatal("entry attempted below an unproved system manager")
		return 0, nil
	}
	code, _, errs := run(t, "run", scopeContract(t))
	if code != identity.ExitLauncher || !strings.Contains(errs, "service manager is not at the top of this cgroup tree") {
		t.Fatalf("exit=%d stderr=%s", code, errs)
	}
}
