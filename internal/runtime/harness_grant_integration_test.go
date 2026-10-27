// SPDX-License-Identifier: Apache-2.0

//go:build integration

package runtime

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/harness"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// hookProvisioner is a Claude Code-like provision whose hook is this test binary (TestMain's harnessHookHelper runs
// it), with the binary's path and the helper's marker in the agent's environment.
func hookProvisioner() *fakeProvisioner {
	return &fakeProvisioner{fn: func(run harness.Run) harness.Provision {
		return harness.Provision{
			Env:  []string{"TEGO_T_EXE=" + run.TegoExe, harnessHookHelperEnv + "=1"},
			Hook: &harness.Hook{Argv: []string{run.TegoExe, "hook", "claude-code", "--reason", run.ReasonFile, "--mode", "json"}},
		}
	}}
}

// hookVariants are the tego commands an agent could try with the granted binary, each refused (exit 126): every
// vector but the hook's exact one, the reason path changed included.
var hookVariants = []string{"run", "approve 01J0000000000000000000000A a1", "__probe", "hook other",
	"hook claude-code --reason /tmp/other-refusal.json --mode json", ""}

// TestIntegrationHarnessHookGrantIsTheExactArgv is ADR 0064's acceptance (2) at tier landlock through the real
// runner.run, under a plain allow-list contract and under one with gate.completion: held, whose open deputy has the
// domain's own runtime exec grant of the same binary: the hook's exact argv runs, and the binary with every other
// vector is refused by the supervisor (exit 126), one refused exec line each naming exec.harness-hook[<binary>].
// run_start records the grant, and best_effort says the argv is a copied fact at this tier (ADR 0048 R5).
func TestIntegrationHarnessHookGrantIsTheExactArgv(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("a root launcher makes no runtime directory, so it provisions nothing")
	}
	requireLandlock(t)
	exe := testExe(t)
	for name, gate := range map[string]string{
		"allow-list":      "",
		"held completion": "gate:\n  completion: held\n  rules:\n    - 'fs.read matches \"*.env\"': 90\n",
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv("XDG_RUNTIME_DIR", privateTempDir(t))
			f := newFixture(t, "version: 0\nname: ihookgrant\ncommand: [/bin/sh]\ntier: landlock\nharness: generic\n"+
				"exec:\n  allow: [/bin/sh]\nenv:\n  pass: [PATH, HOME]\nlimits:\n  pids: 64\n"+gate)
			if (gate != "") != f.rt.NeedsOpenDeputy() {
				t.Fatalf("NeedsOpenDeputy %v under %q", f.rt.NeedsOpenDeputy(), gate)
			}
			deps := f.deps(t, nil)
			deps.Harness = func(harness.Name) Provisioner { return hookProvisioner() }
			out := filepath.Join(t.TempDir(), "stdout")
			o, err := os.Create(out)
			if err != nil {
				t.Fatal(err)
			}
			deps.Stdio.Out = o
			var script strings.Builder
			script.WriteString(`"$TEGO_T_EXE" hook claude-code --reason "$TEGO_REASON" --mode json || exit 3` + "\n")
			for _, v := range hookVariants {
				fmt.Fprintf(&script, "\"$TEGO_T_EXE\" %s; rc=$?; [ $rc -eq 126 ] || { echo \"[%s] exit $rc\"; exit 4; }\n", v, v)
			}
			script.WriteString("echo done\n")
			res, err := Run(context.Background(), f.rt, []string{"/bin/sh", "-c", script.String()}, deps)
			_ = o.Close()
			if err != nil {
				t.Fatalf("Run: %v", err)
			}
			b, _ := os.ReadFile(out)
			evs := events(t, runDirs(t, f.root)[0])
			start := runStartPayload(t, evs)
			if res.ExitCode != 0 || !strings.Contains(string(b), "hook ran: hook claude-code --reason "+start.Harness.ReasonFile+" --mode json\n") ||
				!strings.HasSuffix(string(b), "done\n") {
				t.Fatalf("exit %d, stdout %q: 3 the hook was refused, 4 another argv was not refused EACCES", res.ExitCode, b)
			}
			rule := "exec." + agent.HarnessHookGrant + "[" + exe + "]"
			h := start.Harness
			if h == nil || !h.Provisioned || h.Hook == nil || !h.Hook.Granted || !slices.Contains(start.RuntimeGrants, rule) ||
				!slices.Contains(start.BestEffort, agent.BestEffortExecRules) {
				t.Fatalf("run_start harness %+v, runtime_grants %q, best_effort %q", h, start.RuntimeGrants, start.BestEffort)
			}
			refused := 0
			for _, e := range evs {
				var p record.ExecPayload
				if e.Kind != record.KindExec || e.DecodePayload(&p) != nil || p.Path != exe {
					continue
				}
				switch {
				case slices.Equal(p.Argv, h.Hook.Argv):
					if e.Verdict == record.VerdictRefused {
						t.Errorf("the hook was refused: %+v", e)
					}
				case e.Verdict == record.VerdictRefused && e.Rule == rule && e.Reason == record.ReasonExecNotAllowed:
					refused++
				default:
					t.Errorf("an exec of the binary with argv %q: verdict %s rule %s", p.Argv, e.Verdict, e.Rule)
				}
			}
			if refused != len(hookVariants) {
				t.Errorf("%d refused exec lines naming %s, want %d", refused, rule, len(hookVariants))
			}
		})
	}
}

// TestIntegrationHarnessHookWritableRunsUnprovisioned is acceptance (4) at tier landlock: a write entry over the tego
// binary's directory drops the whole provision (the agent could rewrite what a grant admits), and the run still runs,
// with run_start saying why and the hook not granted.
func TestIntegrationHarnessHookWritableRunsUnprovisioned(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("a root launcher makes no runtime directory, so it provisions nothing")
	}
	requireLandlock(t)
	t.Setenv("XDG_RUNTIME_DIR", privateTempDir(t))
	dir := filepath.Dir(testExe(t))
	f := newFixture(t, "version: 0\nname: ihookwritable\ncommand: [/bin/sh]\ntier: landlock\nharness: generic\n"+
		"exec:\n  allow: [/bin/sh]\nfs:\n  write: ["+dir+"]\nenv:\n  pass: [PATH, HOME]\nlimits:\n  pids: 64\n")
	deps := f.deps(t, nil)
	deps.Harness = func(harness.Name) Provisioner { return hookProvisioner() }
	var warned []string
	deps.Warn = func(code, what string) { warned = append(warned, code+": "+what) }
	res, err := Run(context.Background(), f.rt, []string{"/bin/sh", "-c", `[ -z "$TEGO_T_EXE" ] || exit 3`}, deps)
	if err != nil || res.ExitCode != 0 {
		t.Fatalf("Run: %+v %v (3: the dropped provision's environment reached the agent)", res, err)
	}
	h := runStartPayload(t, events(t, runDirs(t, f.root)[0])).Harness
	if h == nil || h.Provisioned || h.Why != record.HarnessWhyHookWritable || h.Hook == nil || h.Hook.Granted {
		t.Fatalf("run_start harness %+v", h)
	}
	if len(warned) != 1 || !strings.Contains(warned[0], "harness-hook-writable") {
		t.Fatalf("warnings %q", warned)
	}
}

// TestIntegrationKernelExecAssuranceRefusesAlikeWithAHook:
// exec.assurance: kernel at tier landlock, which pins no exec, refuses the run (exit 125, no run_start)
// with or without a provisioner whose hook the launcher would grant, so dropping the grant could let no such run run.
func TestIntegrationKernelExecAssuranceRefusesAlikeWithAHook(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("a root launcher makes no runtime directory, so it provisions nothing")
	}
	requireLandlock(t)
	t.Setenv("XDG_RUNTIME_DIR", privateTempDir(t))
	for _, provisioned := range []bool{false, true} {
		f := newFixture(t, "version: 0\nname: ihookkernel\ncommand: [/bin/true]\ntier: landlock\nharness: generic\n"+
			"exec:\n  allow: [/bin/true]\n  assurance: kernel\nlimits:\n  pids: 64\n")
		deps := f.deps(t, nil)
		if provisioned {
			deps.Harness = func(harness.Name) Provisioner { return hookProvisioner() }
		}
		res, err := Run(context.Background(), f.rt, []string{"/bin/true"}, deps)
		if !errors.Is(err, ErrExecAssurance) || res.ExitCode != 125 || len(runDirs(t, f.root)) != 0 {
			t.Errorf("provisioned %v: %+v %v, want ErrExecAssurance, exit 125 and no run", provisioned, res, err)
		}
	}
}

// TestIntegrationTegoInsideADenyListRun is acceptance (3)'s residual at tier landlock, under a deny-list contract
// (images unrestricted, so the agent can run the tego binary with any argv, as a racing thread can at tier landlock
// under the grant): the binary runs under the run's own domain, filter and supervisor, so `tego approve` run inside
// the run cannot answer the ask the run holds: it is refused the run's lock file, since the ledger root is
// read-denied (R6a), and were it not, the broker refuses a peer in the governed cgroup
// (TestAskBrokerRefusesTegoApproveFromTheRunsCgroup); the ask stays pending until the person answers it from outside.
// A nested `tego run` fails closed (exit 125, the kernel refusing a second seccomp listener) and starts no agent.
func TestIntegrationTegoInsideADenyListRun(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("the agent, dropped to the invoking user, cannot run the tego binary root built in its own temporary directory; a root launcher grants no hook")
	}
	bin := tegoBinary(t)
	s := newDenyListScene(t, bin)
	run, dir := s.start(t)
	req := s.pending(t, filepath.Base(dir))
	id, _ := req["ask_id"].(string)
	if id == "" {
		t.Fatalf("no ask id in %v", req)
	}
	if err := os.WriteFile(filepath.Join(s.f.dir, "out", "id"), []byte(id), 0o644); err != nil {
		t.Fatal(err)
	}
	for deadline := time.Now().Add(30 * time.Second); s.out("inside.done") == ""; time.Sleep(50 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("the agent's tego commands did not finish: approve %q %q, nested %q %q", s.out("approve.rc"), s.out("approve.out"),
				s.out("nested.rc"), s.out("nested.out"))
		}
	}
	// Each refusal is held to its cause, so neither passes for an unrelated failure (a wrong config, a missing binary):
	// approve stops at the run's lock, which R6a read-denies (the broker's own refusal of a peer in the run's cgroup is
	// the next layer, TestAskBrokerRefusesTegoApproveFromTheRunsCgroup); the nested run at its tier probe, whose
	// seccomp listener the kernel refuses in a filter chain that already has one (EBUSY).
	if rc, out := strings.TrimSpace(s.out("approve.rc")), s.out("approve.out"); rc == "0" || rc == "" ||
		!strings.Contains(out, "open lock file") || !strings.Contains(out, "permission denied") {
		t.Fatalf("tego approve inside the run exited %q, want a refusal of the run's lock file (R6a):\n%s", rc, out)
	}
	if again := s.pending(t, filepath.Base(dir)); again["ask_id"] != id {
		t.Fatalf("after the agent's approve the pending request is %v, want %s still pending", again, id)
	}
	if rc, out := strings.TrimSpace(s.out("nested.rc")), s.out("nested.out"); rc != "125" || s.out("nested.started") != "" ||
		!strings.Contains(out, "[tier-unavailable]") || !strings.Contains(out, "NEW_LISTENER") || !strings.Contains(out, "device or resource busy") {
		t.Fatalf("a nested tego run exited %q, started %q, want 125 with the seccomp listener refused (EBUSY):\n%s", rc, s.out("nested.started"), out)
	}
	t.Logf("inside the run, tego approve said %q and the nested tego run %q", s.out("approve.out"), s.out("nested.out"))
	s.answer(t, "deny", filepath.Base(dir), id)
	evs := s.finish(t, run, dir)
	answers := lines(t, evs, record.KindAnswer)
	if len(answers) != 1 || answers[0]["ask_id"] != id || answers[0]["approved"] != false || !strings.HasPrefix(fmt.Sprint(answers[0]["by"]), "uid:") {
		t.Errorf("answer lines %v: want the person's one refusal of %s", answers, id)
	}
	if got := s.out("got.txt"); got != "" {
		t.Errorf("the held read delivered %q", got)
	}
}

// newDenyListScene is an askReadScene whose contract is a deny-list (no allow key: the agent runs any image, bin
// included) holding the agent's read of the secret for a person, and whose agent, once the test has written the ask's
// id to out/id, tries to approve it itself with `tego approve` and to start a nested run, and writes what each did.
// The agent gives the tego binary it starts the scene's machine config (so it looks for the ledger root this run
// records into) and the test-hook variables (so its anchor and own log stay in the test's directories): the contract
// can pass no TEGO_ variable (env-runtime-reserved), and the agent sets them for its own child as any process can.
func newDenyListScene(t *testing.T, bin string) *askReadScene {
	t.Helper()
	s := newScene(t, "60s", "", "#!/bin/sh\n")
	var cfg string
	for _, kv := range s.env {
		if v, ok := strings.CutPrefix(kv, "TEGO_CONFIG="); ok {
			cfg = v
		}
	}
	env := fmt.Sprintf("TEGO_CONFIG=%q TEGO_TEST_CHAIN_ANCHOR=%q TEGO_TEST_OWN_LOG_HOME=%q", cfg, os.Getenv("TEGO_TEST_CHAIN_ANCHOR"),
		os.Getenv("TEGO_TEST_OWN_LOG_HOME"))
	if cfg == "" || strings.Contains(env, `=""`) {
		t.Fatalf("the scene's environment lacks the machine config or a test hook: %s", env)
	}
	// The nested run's contract, which the agent can read where its own run writes.
	if err := os.MkdirAll(s.f.out, 0o755); err != nil {
		t.Fatal(err)
	}
	inner := "version: 0\nname: inested\ncommand: [/bin/sh]\nlimits:\n  pids: 8\n"
	if err := os.WriteFile(filepath.Join(s.f.out, "inner.yaml"), []byte(inner), 0o644); err != nil {
		t.Fatal(err)
	}
	script := fmt.Sprintf(`#!/bin/sh
cat %[3]q > out/got.txt 2> out/err.txt &
while [ ! -s out/id ]; do sleep 0.05; done
%[2]s %[1]q approve "$TEGO_RUN_ID" "$(cat out/id)" > out/approve.out 2>&1; echo $? > out/approve.rc
%[2]s %[1]q run out/inner.yaml -- /bin/sh -c 'echo yes > out/nested.started' > out/nested.out 2>&1; echo $? > out/nested.rc
echo done > out/inside.done
wait
`, bin, env, s.secret)
	if err := os.WriteFile(filepath.Join(s.f.dir, "agent.sh"), []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	// The scene's contract is an allow-list; this one keeps everything but the exec section, a deny-list.
	y, err := os.ReadFile(filepath.Join(s.f.dir, "agent.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	c := strings.Replace(string(y), `  allow: ["/bin/sh", "/bin/cat", "/bin/echo"]`, `  deny: ["id"]`, 1)
	if c == string(y) {
		t.Fatalf("the scene's contract changed shape:\n%s", y)
	}
	if err := os.WriteFile(filepath.Join(s.f.dir, "agent.yaml"), []byte(c), 0o600); err != nil {
		t.Fatal(err)
	}
	return s
}
