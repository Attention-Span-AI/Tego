// SPDX-License-Identifier: Apache-2.0

//go:build integration && linux && tegobpf

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/doctor"
	tegoruntime "github.com/attention-span-ai/tego/internal/runtime"
	"github.com/attention-span-ai/tego/internal/watch/watcher"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// This guest regression changes the real kernel admission condition after
// a guard's startup preflight. It uses only the existing CLI and fixture helpers.
func TestIntegrationGuardBoundaryRechecksLiveFmodRetAdmission(t *testing.T) {
	requireAdoption(t)
	if os.Getenv("TEGO_DISPOSABLE_HOST") != "kvm" {
		t.Skip("needs a disposable KVM kernel to change live preemption")
	}
	const modeFile = "/sys/kernel/debug/sched/preempt"
	raw, err := os.ReadFile(modeFile)
	if err != nil {
		t.Skipf("needs live PREEMPT_DYNAMIC controls: %v", err)
	}
	if !strings.Contains(string(raw), "voluntary") || !strings.Contains(string(raw), "full") {
		t.Skipf("needs voluntary and full PREEMPT_DYNAMIC modes: %s", strings.TrimSpace(string(raw)))
	}
	writable, err := os.OpenFile(modeFile, os.O_WRONLY, 0)
	if err != nil {
		t.Skipf("needs writable PREEMPT_DYNAMIC controls: %v", err)
	}
	if err := writable.Close(); err != nil {
		t.Fatal(err)
	}
	old := ""
	for _, word := range strings.Fields(string(raw)) {
		if strings.HasPrefix(word, "(") && strings.HasSuffix(word, ")") {
			old = strings.Trim(word, "()")
		}
	}
	if old == "" {
		t.Fatalf("no active mode: %q", raw)
	}
	setMode := func(mode string) {
		t.Helper()
		if err := os.WriteFile(modeFile, []byte(mode), 0); err != nil {
			t.Fatalf("set live preemption %s: %v", mode, err)
		}
		got, err := os.ReadFile(modeFile)
		if err != nil || !strings.Contains(string(got), "("+mode+")") {
			t.Fatalf("live preemption: %q %v", got, err)
		}
		t.Logf("live preemption %s: %s", mode, strings.TrimSpace(string(got)))
	}
	t.Cleanup(func() {
		if err := os.WriteFile(modeFile, []byte(old), 0); err != nil {
			t.Errorf("restore live preemption %s: %v", old, err)
			return
		}
		restored, err := os.ReadFile(modeFile)
		if err != nil || !strings.Contains(string(restored), "("+old+")") {
			t.Errorf("restored live preemption %s: %q %v", old, restored, err)
		}
	})
	setMode("voluntary")
	e := newAdoptEnv(t)
	e.tegoEnv = append(e.tegoEnv, "TEGO_TEST_PLANE=fmod_ret", "TEGO_TEST_PLANE_PREEMPT=")
	// Prove the live admission change is causal, rather than accepting a guard
	// that never had a supported plane. Doctor findings may exit nonzero while
	// still returning a complete JSON report.
	checkDoctor := func(mode string) {
		t.Helper()
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Minute)
		defer cancel()
		template := e.tegoCmd("machine", "check", "--json")
		cmd := exec.CommandContext(ctx, template.Path, template.Args[1:]...)
		cmd.Env, cmd.Dir, cmd.WaitDelay = template.Env, template.Dir, 5*time.Second
		var stdout, stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		err := cmd.Run()
		if ctx.Err() != nil {
			t.Fatalf("doctor under preemption %s timed out: %v: %s", mode, err, stderr.String())
		}
		var report struct {
			Plane *doctor.PlaneState `json:"plane"`
		}
		if decode := json.Unmarshal(stdout.Bytes(), &report); decode != nil || report.Plane == nil {
			t.Fatalf("doctor under preemption %s: exit=%v decode=%v stdout=%s stderr=%s", mode, err, decode, stdout.String(), stderr.String())
		}
		plane := report.Plane
		if plane.Env.Preempt != mode || plane.Env.PreemptWaived || plane.Pin != "fmod_ret" {
			t.Fatalf("doctor preemption controls: want=%s pin=%s env=%+v", mode, plane.Pin, plane.Env)
		}
		var fmod *doctor.PlaneModeResult
		for i := range plane.Modes {
			if string(plane.Modes[i].Mode) == "fmod_ret" {
				fmod = &plane.Modes[i]
			}
		}
		if fmod == nil {
			t.Fatal("doctor omitted fmod_ret mode")
		}
		if mode == "voluntary" {
			if plane.Selected != "fmod_ret" || !fmod.OK || !fmod.Tested || fmod.Faulted {
				t.Fatalf("voluntary kernel does not admit forced fmod_ret: selected=%s mode=%+v", plane.Selected, fmod)
			}
		} else if plane.Selected == "fmod_ret" || fmod.OK || fmod.Tested || fmod.Faulted || !strings.Contains(fmod.Detail, "preempts kernel code") {
			t.Fatalf("full kernel did not reject fmod_ret for preemption: selected=%s mode=%+v", plane.Selected, fmod)
		}
		t.Logf("DOCTOR-FMOD-RET preempt=%s source=%s waived=%t selected=%s ok=%t tested=%t faulted=%t detail=%s", plane.Env.Preempt,
			plane.Env.PreemptSource, plane.Env.PreemptWaived, plane.Selected, fmod.OK, fmod.Tested, fmod.Faulted, fmod.Detail)
	}
	checkDoctor("voluntary")
	contract := filepath.Join(filepath.Dir(e.dir), "boundary.yaml")
	body := fmt.Sprintf("version: 0\nname: live-fmod-ret\ncommand: [/bin/sh]\nrecord: full\nfs:\n  write: [%q, /dev/null]\n", e.dir)
	if err := os.WriteFile(contract, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	guard := e.tegoCmd("agents", "--follow", "--adopt", "--uid", "65534", "--boundary", contract, "--json")
	var out, errs lockedBuffer
	guard.Stdout, guard.Stderr = &out, &errs
	if err := guard.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- guard.Wait() }()
	stopped := false
	t.Cleanup(func() {
		if !stopped {
			_ = guard.Process.Kill()
			<-done
		}
		if t.Failed() {
			t.Logf("guard out: %s\nguard err: %s", out.String(), errs.String())
		}
	})
	deadline := time.Now().Add(90 * time.Second)
	for !strings.Contains(errs.String(), "adopting each one") {
		select {
		case err := <-done:
			stopped = true
			t.Fatalf("guard preflight: %v: %s", err, errs.String())
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("guard startup timeout: %s", errs.String())
		}
		time.Sleep(50 * time.Millisecond)
	}
	setMode("full")
	checkDoctor("full")
	if err := os.Chmod(e.cmds, 0o666); err != nil {
		t.Fatal(err)
	}
	e.startAgentAs(65534, adoptAgentScript)
	deadline = time.Now().Add(90 * time.Second)
	found := false
	for !found {
		for _, line := range strings.Split(out.String(), "\n") {
			var s watcher.Sighting
			if json.Unmarshal([]byte(line), &s) != nil || int(s.PID) != e.agentPID {
				continue
			}
			if s.Event == watcher.EventAdopted {
				t.Fatalf("guard adopted under lapsed fmod_ret admission: %+v", s)
			}
			if s.Event == watcher.EventAdoptionFailed {
				// Tier cgroup can still be selected with a listener, but an
				// adopted boundary requires a plane and fails before movement.
				// The shared admission table names the stage that refused (since
				// f36046b91): the adoption starts after the mode changed, so its
				// own preparation finds no plane ("prepared enforcement handle");
				// a mode that lapsed after that is the "live plane admission"
				// recheck. Either way the refusal is the no-plane one.
				noPlane := tegoruntime.ErrAdoptNoPlane.Error() + ": the plane runs in no mode here or cannot hold this contract"
				prepared := `admission check "prepared enforcement handle" during preparation: ` + noPlane
				live := tegoruntime.ErrAdoptNoPlane.Error() + ": live plane admission before adoption"
				if !strings.HasPrefix(s.Note, prepared) && !strings.Contains(s.Note, live) {
					t.Fatalf("wrong failure: %+v", s)
				}
				found = true
				t.Logf("uid %s's adoption refused after live mode changed: %s", strconv.Itoa(65534), s.Note)
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("no failed adoption: %s %s", out.String(), errs.String())
		}
		if !found {
			time.Sleep(50 * time.Millisecond)
		}
	}
	if got := cgroupOfPID(e.agentPID); got != e.termRel {
		t.Fatalf("refused agent moved: %s want %s", got, e.termRel)
	}
	if syscall.Kill(e.agentPID, 0) != nil {
		t.Fatal("refused agent was killed")
	}
	_ = guard.Process.Signal(syscall.SIGTERM)
	select {
	case err := <-done:
		stopped = true
		if err != nil {
			t.Fatalf("guard stop: %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("guard stop timeout")
	}
}

// A recording-only adoption keeps its kernel record and lifecycle without
// claiming decision capabilities in the adoption run_start.
func TestIntegrationRecordingOnlyAdoptionLifecycle(t *testing.T) {
	e := newAdoptEnv(t)
	e.startAgent(adoptAgentScript)
	a, run := e.adopt()
	for _, action := range []string{"open", "exec"} {
		if status := e.send(action); status != 0 {
			t.Fatalf("record-only %s refused: %d", action, status)
		}
	}
	waitFor(t, func() bool {
		var opened, executed bool
		for _, ev := range e.lines(run) {
			if ev.Kind == record.KindFS {
				var p record.FSPayload
				opened = opened || ev.DecodePayload(&p) == nil && p.Path == e.file
			}
			if ev.Kind == record.KindExec {
				var p record.ExecPayload
				executed = executed || ev.DecodePayload(&p) == nil && p.Path == "/bin/true"
			}
		}
		return opened && executed
	})
	if out, err := e.tegoCmd("session", "stop", run).CombinedOutput(); err != nil {
		t.Fatalf("release: %v %s", err, out)
	}
	if code := a.wait(t); code != 0 {
		t.Fatalf("adopter exit %d: %s", code, a.text())
	}
	events := e.lines(run)
	start, scopeID := runStartOf(t, events)
	if left := e.leftovers(run, start.BPFHash, scopeID); len(left) != 0 {
		t.Fatalf("record-only leftovers: %v", left)
	}
	if cgroupOfPID(e.agentPID) != e.termRel || syscall.Kill(e.agentPID, 0) != nil {
		t.Fatal("released record-only agent not alive in its original cgroup")
	}
	counts := map[record.Verdict]int{}
	var sawOpen, sawExec bool
	for _, ev := range events {
		if ev.Kind != record.KindFS && ev.Kind != record.KindExec && ev.Kind != record.KindNet {
			continue
		}
		counts[ev.Verdict]++
		if ev.Verdict == record.VerdictRefused {
			t.Errorf("record-only adoption claimed refusal: %+v", ev)
		}
		if ev.Kind == record.KindFS {
			var payload record.FSPayload
			if ev.DecodePayload(&payload) == nil && payload.Path == e.file {
				sawOpen = true
			}
		}
		if ev.Kind == record.KindExec {
			var payload record.ExecPayload
			if ev.DecodePayload(&payload) == nil && payload.Path == "/bin/true" {
				sawExec = true
			}
		}
	}
	if !sawOpen || !sawExec {
		t.Errorf("record-only kernel action coverage open=%t exec=%t", sawOpen, sawExec)
	}
	if start.DecisionPlane != "" {
		t.Errorf("record-only adoption claimed decision plane %q", start.DecisionPlane)
	}
	for _, capability := range []backend.Capability{backend.CapFileWriteDeny, backend.CapFileDeleteRename,
		backend.CapReadDeny, backend.CapExecDeny, backend.CapAsk, backend.CapProtectedWriteTargets} {
		if start.Capabilities[string(capability)] {
			t.Errorf("record-only adoption claimed %s", capability)
		}
	}
	for _, capability := range []backend.Capability{backend.CapRecordExecOpenNet, backend.CapRecordReads, backend.CapLogAllowed} {
		if !start.Capabilities[string(capability)] {
			t.Errorf("record-only adoption omitted %s", capability)
		}
	}
	detail, err := json.Marshal(struct {
		Reads        *record.FSReads        `json:"fs_reads"`
		Notified     *record.ReadsNotified  `json:"reads_notified"`
		Capabilities map[string]bool        `json:"capabilities"`
		Verdicts     map[record.Verdict]int `json:"action_verdicts"`
	}{start.FSReads, start.ReadsNotified, start.Capabilities, counts})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("RECORDING-ONLY-LIFECYCLE rev=%s %s", os.Getenv("TEGO_GUEST_PROOF_REV"), detail)
}

// A real passwd home and a kernel-refused read distinguish the owner's compiler
// context from the root guard's, even when both homes use ordinary directories.
func TestIntegrationGuardBoundaryUsesOwnersHome(t *testing.T) {
	requireAdoption(t)
	if os.Getenv("TEGO_DISPOSABLE_HOST") != "kvm" {
		t.Skip("needs a disposable KVM guest to install a temporary passwd home")
	}
	e := newAdoptEnv(t)
	const uid = 65534
	home := filepath.Join(filepath.Dir(e.dir), "owner-home")
	ssh := filepath.Join(home, ".ssh")
	for _, dir := range []string{home, ssh} {
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chown(dir, uid, uid); err != nil {
			t.Fatal(err)
		}
	}
	secret := filepath.Join(ssh, "fixture-key")
	if err := os.WriteFile(secret, []byte("ordinary owner fixture\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(secret, uid, uid); err != nil {
		t.Fatal(err)
	}
	passwd, err := os.ReadFile("/etc/passwd")
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(string(passwd), "\n")
	found := false
	for i, line := range lines {
		fields := strings.Split(line, ":")
		if len(fields) == 7 && fields[2] == "65534" {
			fields[5] = home
			lines[i] = strings.Join(fields, ":")
			found = true
		}
	}
	if !found {
		t.Fatal("guest has no uid 65534 passwd fixture")
	}
	if err := os.WriteFile("/etc/passwd", []byte(strings.Join(lines, "\n")), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.WriteFile("/etc/passwd", passwd, 0o644); err != nil {
			t.Error(err)
		}
	})
	if err := os.Chmod(e.cmds, 0o666); err != nil {
		t.Fatal(err)
	}
	e.startAgentAs(uid, adoptAgentScript, "AGENT_SECRET="+secret)
	if status := e.send("secret"); status != 0 {
		t.Fatalf("owner's native read: %d", status)
	}
	contract := filepath.Join(filepath.Dir(e.dir), "owner-boundary.yaml")
	body := fmt.Sprintf("version: 0\nname: owner-home\ncommand: [/bin/sh]\nrecord: full\nfs:\n  write: [%q, /dev/null]\n", e.dir)
	if err := os.WriteFile(contract, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	guard := e.tegoCmd("agents", "--follow", "--adopt", "--uid", "65534", "--boundary", contract, "--json")
	var out, errs lockedBuffer
	guard.Stdout, guard.Stderr = &out, &errs
	if err := guard.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- guard.Wait() }()
	stopped := false
	t.Cleanup(func() {
		if !stopped {
			_ = guard.Process.Kill()
			<-done
		}
		if t.Failed() {
			t.Logf("guard out: %s\nguard err: %s", out.String(), errs.String())
		}
	})
	run := ""
	deadline := time.Now().Add(90 * time.Second)
	for run == "" {
		for _, line := range strings.Split(out.String(), "\n") {
			var s watcher.Sighting
			if json.Unmarshal([]byte(line), &s) == nil && int(s.PID) == e.agentPID {
				if s.Event == watcher.EventAdopted {
					run = s.Run
				}
				if s.Event == watcher.EventAdoptionFailed {
					t.Fatalf("owner adoption failed: %s", s.Note)
				}
			}
		}
		select {
		case err := <-done:
			stopped = true
			t.Fatalf("guard before owner adoption: %v: %s", err, errs.String())
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("owner guard adoption timeout: %s %s", out.String(), errs.String())
		}
		if run == "" {
			time.Sleep(50 * time.Millisecond)
		}
	}
	if status := e.send("secret"); status == 0 {
		t.Fatal("guard compiled a different home: owner's .ssh read was allowed")
	}
	info, err := os.Stat(filepath.Join(home, ".tego"))
	if err != nil || info.Mode().Perm() != 0o700 || info.Sys().(*syscall.Stat_t).Uid != uid {
		t.Fatalf("owner record directory: %v %v", info, err)
	}
	_ = guard.Process.Signal(syscall.SIGTERM)
	select {
	case err := <-done:
		stopped = true
		if err != nil {
			t.Fatalf("guard release: %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("owner guard release timeout")
	}
	if status := e.send("secret"); status != 0 {
		t.Fatalf("released owner's read: %d", status)
	}
	if cgroupOfPID(e.agentPID) != e.termRel {
		t.Fatal("owner not released to original cgroup")
	}
	t.Logf("OWNER-CONTEXT uid=65534 home=%s private-records=0700 native-read=allowed adopted-read=refused released-read=allowed run=%s", home, run)
}
