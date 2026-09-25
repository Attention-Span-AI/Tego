// SPDX-License-Identifier: Apache-2.0

//go:build integration

package runtime

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/runtime/enforce"
	"github.com/attention-span-ai/tego/internal/runtime/enforce/api"
	"github.com/attention-span-ai/tego/internal/runtime/enforce/landlock"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// abiBackend is the production tier-1 backend built as it is on a kernel of Landlock ABI abi: its rulesets
// carry that ABI's profile and its filter the arms that ABI needs, which is what a 5.14, 6.1 or 6.8 row of
// the support matrix gets.
type abiBackend struct{ b *landlock.Backend }

func (a abiBackend) Tier() backend.Tier        { return a.b.Tier() }
func (a abiBackend) Capabilities() backend.Set { return a.b.Capabilities() }
func (a abiBackend) Prepare(ctx context.Context, rt *agent.RuleTable, run enforce.RunRef) (api.Handle, error) {
	return a.b.Prepare(ctx, rt, landlock.Run{Dir: run.RunDir})
}

// TestTheAgentCannotSignalOutsideTheRun: on the real kernel, at tier 1 the agent shares
// its launcher's uid, and below Landlock ABI 6 nothing but the filter's signal arm stands between them: on the
// 5.14, 6.1 and 6.8 rows the agent could SIGKILL the launcher (no run_end), SIGSTOP it (every notified syscall
// then waits) or SIGTERM it (run_end reads as an operator's stop). Built at ABI 5 the backend installs the arm,
// and at this host's own ABI the ruleset's scope decides; either way the launcher is out of reach and a child
// of the agent is not. kill(pid, 0) runs the same permission check and changes nothing, so it is the probe.
func TestTheAgentCannotSignalOutsideTheRun(t *testing.T) {
	host, err := landlock.ProbeABI()
	if err != nil {
		t.Skipf("no Landlock: %v", err)
	}
	for _, abi := range []int{5, host} {
		t.Run("abi"+string(rune('0'+abi)), func(t *testing.T) {
			if host < 6 && abi >= 6 {
				t.Skip("this kernel has no signal scope")
			}
			f := newFixture(t, contractFor("isignal", []string{"/bin/sh"},
				[]string{"/bin/sh", "/usr/bin/sh", "/bin/sleep", "/usr/bin/sleep"}))
			deps := f.deps(t, nil)
			deps.Enforce = abiBackend{b: landlock.New(landlock.Options{ABI: abi})}
			res := filepath.Join(f.out, "result")
			// $PPID of the agent's shell is the launcher: the child stage is its clone, and exec keeps the pid.
			script := `/bin/sleep 30 & child=$!
if kill -0 "$PPID" 2>"$1.launcher"; then l="signalled"; else l="refused"; fi
if kill "$child" 2>"$1.child"; then c="killed"; else c="refused"; fi
echo "$l $c" > "$1"`
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			if _, err := Run(ctx, f.rt, []string{"/bin/sh", "-c", script, "sh", res}, deps); err != nil {
				t.Fatalf("Run: %v", err)
			}
			if got := strings.TrimSpace(readFileString(res)); got != "refused killed" {
				t.Errorf("ABI %d: launcher and child %q, want \"refused killed\"", abi, got)
			}
			if abi >= 6 {
				return // the kernel's scope refused it, and the kernel records nothing
			}
			var lines int
			for _, e := range events(t, runDirs(t, f.root)[0]) {
				if e.Kind == record.KindRefused && e.Rule == "signal-scope" {
					lines++
				}
			}
			if lines != 1 {
				t.Errorf("ABI %d: %d signal-scope refusals recorded, want 1", abi, lines)
			}
		})
	}
}

// TestAGoAgentSignalsItsChildBelowABI6: with the signal arm the Go runtime's pidfd_send_signal is ENOSYS, so
// os.Process falls back to kill(2), which the supervisor admits for a child in the run, and the runtime's
// preemption signals to its own threads are admitted without a /proc read.
func TestAGoAgentSignalsItsChildBelowABI6(t *testing.T) {
	// Built from its package path, the form test/vm/go-shim.sh serves prebuilt in the root guest.
	bin := filepath.Join(t.TempDir(), "signaller")
	cmd := exec.Command("go", "build", "-o", bin, "github.com/attention-span-ai/tego/test/workloads/signaller")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOFLAGS=")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v: %s", err, out)
	}
	agentReaches(t, bin)
	f := newFixture(t, contractFor("igosignal", []string{bin}, []string{bin, "/bin/sleep", "/usr/bin/sleep"}))
	deps := f.deps(t, nil)
	deps.Enforce = abiBackend{b: landlock.New(landlock.Options{ABI: 5})}
	out := filepath.Join(f.out, "result")
	deps.Stdio.Out, _ = os.Create(out)
	agentOwns(t, out)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if _, err := Run(ctx, f.rt, []string{bin, "/bin/sleep"}, deps); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := strings.TrimSpace(readFileString(out)); got != "ok" {
		t.Errorf("the Go agent reported %q, want ok", got)
	}
}

// TestASocketOwnerCannotBeSetOutsideTheRunBelowABI6: below ABI 6 the signal arm
// decided fcntl's F_SETOWN, but ioctl(FIOSETOWN) sets the same owner record, and with F_SETSIG and O_ASYNC a
// byte written to the socket's peer sent SIGTERM to any process of the uid. Both routes are refused now, and
// the process outside the run lives.
func TestASocketOwnerCannotBeSetOutsideTheRunBelowABI6(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "sigio")
	cmd := exec.Command("go", "build", "-o", bin, "github.com/attention-span-ai/tego/test/workloads/sigio")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOFLAGS=")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v: %s", err, out)
	}
	agentReaches(t, bin)
	for _, via := range []string{"fcntl", "ioctl"} {
		t.Run(via, func(t *testing.T) {
			victim := exec.Command("/bin/sleep", "30")
			if err := victim.Start(); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { done <- victim.Wait() }()
			t.Cleanup(func() { _ = victim.Process.Kill(); <-done })
			f := newFixture(t, contractFor("isigio", []string{bin}, []string{bin}))
			deps := f.deps(t, nil)
			deps.Enforce = abiBackend{b: landlock.New(landlock.Options{ABI: 5})}
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			if _, err := Run(ctx, f.rt, []string{bin, via, strconv.Itoa(victim.Process.Pid)}, deps); err != nil {
				t.Fatalf("Run: %v", err)
			}
			select {
			case err := <-done:
				done <- err
				t.Fatalf("%s: the process outside the run ended (%v): the agent signalled it through a SIGIO owner", via, err)
			case <-time.After(500 * time.Millisecond):
			}
			var lines int
			for _, e := range events(t, runDirs(t, f.root)[0]) {
				if e.Kind == record.KindRefused && e.Rule == "signal-scope" {
					lines++
				}
			}
			if lines != 1 {
				t.Errorf("%s: %d signal-scope refusals recorded, want 1", via, lines)
			}
		})
	}
}

// TestTheAgentCannotChangeAProcessOutsideTheRun is supervisor R35 on the real kernel: no Landlock ABI governs
// prlimit64 or setpriority, and the agent shares its target's uid, so before the process-scope arm it could set
// the resource limits and nice value of any process of that uid — prlimit64(launcher, RLIMIT_CPU, {1, 1}) had the
// kernel SIGKILL the launcher, at every ABI. The workload writes a process's own values back to it, harmless if
// let through, to a process outside the run (refused, one line each) and to its child in the run (allowed).
func TestTheAgentCannotChangeAProcessOutsideTheRun(t *testing.T) {
	host, err := landlock.ProbeABI()
	if err != nil {
		t.Skipf("no Landlock: %v", err)
	}
	bin := filepath.Join(t.TempDir(), "procscope")
	cmd := exec.Command("go", "build", "-o", bin, "github.com/attention-span-ai/tego/test/workloads/procscope")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOFLAGS=")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v: %s", err, out)
	}
	agentReaches(t, bin)
	for _, abi := range []int{5, host} {
		t.Run("abi"+strconv.Itoa(abi), func(t *testing.T) {
			// The process outside the run has the agent's uid, as the launcher has at tier 1: the kernel's own uid
			// check then allows the calls, and only the arm stands between them.
			victim := exec.Command("/bin/sleep", "30")
			if uid, gid, ok := agentUID(t); ok {
				victim.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)}}
			}
			if err := victim.Start(); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = victim.Process.Kill(); _ = victim.Wait() })
			f := newFixture(t, contractFor("iprocscope", []string{bin},
				[]string{bin, "/bin/sleep", "/usr/bin/sleep"}))
			deps := f.deps(t, nil)
			deps.Enforce = abiBackend{b: landlock.New(landlock.Options{ABI: abi})}
			out := filepath.Join(f.out, "result")
			deps.Stdio.Out, _ = os.Create(out)
			agentOwns(t, out)
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			if _, err := Run(ctx, f.rt, []string{bin, "/bin/sleep", strconv.Itoa(victim.Process.Pid)}, deps); err != nil {
				t.Fatalf("Run: %v", err)
			}
			if got, want := strings.TrimSpace(readFileString(out)), "outside=EPERM,EPERM inside=ok,ok"; got != want {
				t.Errorf("ABI %d: the workload reported %q, want %q", abi, got, want)
			}
			var lines int
			for _, e := range events(t, runDirs(t, f.root)[0]) {
				if e.Kind == record.KindRefused && e.Rule == "process-scope" {
					lines++
				}
			}
			if lines != 2 {
				t.Errorf("ABI %d: %d process-scope refusals recorded, want 2 (prlimit64, setpriority)", abi, lines)
			}
		})
	}
}
