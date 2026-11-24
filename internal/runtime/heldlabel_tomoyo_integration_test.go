// SPDX-License-Identifier: Apache-2.0

//go:build integration

package runtime

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/testutil"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// This fixture activates TOMOYO only in its dedicated disposable boot. The
// disabled profile tests policy-loaded state, independently of file enforcement.
func TestIntegrationHeldOpenTOMOYO(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root only: dedicated TOMOYO policy guest")
	}
	cmdline, err := os.ReadFile("/proc/cmdline")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat("/.vm/nonce"); err != nil || !strings.Contains(string(cmdline), "TOMOYO_trigger=/vm/tomoyo-trigger") {
		t.Skip("needs the dedicated TOMOYO policy guest")
	}
	lsms, err := os.ReadFile("/sys/kernel/security/lsm")
	if err != nil || !strings.Contains(","+string(lsms)+",", ",tomoyo,") {
		t.Fatalf("TOMOYO must be active: %s %v", lsms, err)
	}
	if _, err := os.Stat("/vm/tomoyo-loader"); !os.IsNotExist(err) {
		t.Fatalf("positive control already has a policy loader: %v", err)
	}
	c := newCrossOwner(t, "itomoyo")
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	actor := filepath.Join(c.f.out, "tomoyo-agent")
	if err := os.WriteFile(actor, body, 0o755); err != nil {
		t.Fatal(err)
	}
	if os.Getenv("TEGO_VM_TOMOYO_COUNTER_ONLY") == "1" {
		tomoyoCounterWithoutActivation(t, c, actor)
		return
	}
	switch os.Getenv("TEGO_VM_TOMOYO_HALF") {
	case "enforcing_profile":
		tomoyoEnforcingProfile(t, c, actor)
		return
	case "initializer_counter":
		tomoyoInitializerCounter(t, c, actor)
		return
	case "profile_flip_race":
		t.Run("profile_flip_race", func(t *testing.T) { tomoyoProfileFlipRace(t) })
		return
	}
	t.Run("cause requires same run", func(t *testing.T) {
		const cause = "TOMOYO failed fact"
		log := "level=WARN run=r-other err=\"" + cause + "\"\nlevel=WARN run=r-this err=\"unrelated\"\n"
		if tomoyoOwnLogCause(log, "r-this", cause) {
			t.Fatal("another run satisfied the refusal cause")
		}
		if !tomoyoOwnLogCause(log, "r-other", cause) {
			t.Fatal("own run cause missing")
		}
	})
	tiers := []string{"landlock", "cgroup", "bpflsm"}
	for _, tier := range tiers {
		t.Run("positive/"+tier, func(t *testing.T) {
			testutil.RequireTier(t, c.doctorRequire(t, tier), tier)
			cmd, path := tomoyoRun(t, c, actor, tier, "positive", "--held-label-agent")
			if err := cmd.Run(); err != nil {
				t.Fatalf("positive: %v\n%s", err, output(cmd))
			}
			tomoyoResult(t, c, cmd, path, false)
		})
	}
	type waiting struct {
		cmd        *exec.Cmd
		path, tier string
		input      io.WriteCloser
		done       chan struct{}
		err        error
	}
	var runs []*waiting
	for _, tier := range tiers {
		cmd, path := tomoyoRun(t, c, actor, tier, "midrun", "--held-label-tomoyo-agent")
		input, err := cmd.StdinPipe()
		if err != nil {
			t.Fatal(err)
		}
		w := &waiting{cmd: cmd, path: path, tier: tier, input: input, done: make(chan struct{})}
		runs = append(runs, w)
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		go func() { w.err = cmd.Wait(); close(w.done) }()
		t.Cleanup(func() {
			_ = w.input.Close()
			select {
			case <-w.done:
				return
			default:
			}
			_ = w.cmd.Process.Kill()
			<-w.done
		})
		ready := false
		for deadline := time.Now().Add(120 * time.Second); time.Now().Before(deadline); time.Sleep(time.Millisecond) {
			if strings.Contains(output(cmd), "TOMOYO-READY") {
				ready = true
				break
			}
			select {
			case <-w.done:
				t.Fatalf("%s ended before first held read: %v\n%s", tier, w.err, output(cmd))
			default:
			}
		}
		if !ready {
			t.Fatalf("%s did not complete its first held read\n%s", tier, output(cmd))
		}
	}
	if err := os.Rename("/vm/tomoyo-loader.fixture", "/vm/tomoyo-loader"); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile("/sys/kernel/security/tomoyo/stat")
	if err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("/vm/tomoyo-trigger").CombinedOutput(); err != nil {
		t.Fatalf("activate TOMOYO: %v\n%s", err, out)
	}
	after, err := os.ReadFile("/sys/kernel/security/tomoyo/stat")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("TOMOYO activation: before %q; after %q", strings.SplitN(string(before), "\n", 2)[0], strings.SplitN(string(after), "\n", 2)[0])
	if strings.SplitN(string(before), "\n", 2)[0] == strings.SplitN(string(after), "\n", 2)[0] {
		t.Fatal("fixture did not count a policy update")
	}
	for _, w := range runs {
		if _, err := w.input.Write([]byte{1}); err != nil {
			t.Fatal(err)
		}
		_ = w.input.Close()
		select {
		case <-w.done:
		case <-time.After(15 * time.Second):
			t.Fatalf("%s did not finish after activation", w.tier)
		}
		if w.err != nil {
			t.Fatalf("%s midrun: %v\n%s", w.tier, w.err, output(w.cmd))
		}
		// SEC08b: the loader wrote a profile that enforces nothing (every mode disabled), and the launcher is root, which
		// can read it: the update the activation counted no longer refuses a held open, whatever domain the supervisor
		// is in now. tomoyoEnforcingProfile is the same boot with a profile that enforces.
		tomoyoResult(t, c, w.cmd, w.path, false)
	}
	for _, tier := range tiers {
		t.Run("loaded/"+tier, func(t *testing.T) {
			cmd, path := tomoyoRun(t, c, actor, tier, "loaded", "--held-label-agent")
			if err := cmd.Run(); err != nil {
				t.Fatalf("loaded: %v\n%s", err, output(cmd))
			}
			tomoyoResult(t, c, cmd, path, false)
		})
	}
}

func tomoyoRun(t *testing.T, c *crossOwner, actor, tier, phase, mode string) (*exec.Cmd, string) {
	t.Helper()
	return tomoyoRunAs(t, c, actor, tier, phase, mode, false)
}

// tomoyoRunAs is tomoyoRun with the launcher the invoking user when asUser: tier landlock's run, which cannot read
// TOMOYO's profile.
func tomoyoRunAs(t *testing.T, c *crossOwner, actor, tier, phase, mode string, asUser bool) (*exec.Cmd, string) {
	t.Helper()
	path := filepath.Join(c.f.out, "tomoyo-"+phase+"-"+tier)
	if err := os.WriteFile(path, []byte("preserve-me"), 0o644); err != nil {
		t.Fatal(err)
	}
	agentOwns(t, path)
	contract := contractFor("itomoyo", []string{actor, mode, path}, []string{actor})
	contract = strings.Replace(contract, "tier: landlock", "tier: "+tier, 1)
	contract = strings.Replace(contract, `write: ["./out/"]`, fmt.Sprintf("write: [%q]", c.f.out), 1)
	contract = strings.Replace(contract, "fs:\n", "fs:\n  deny_read: []\n  deny_write: []\n  reads: held\n", 1)
	contract += "gate:\n  completion: held\n  rules:\n    - 'fs.read matches \"*.never\"': 90\n    - 'fs.write outside worktree': 90\n"
	name := filepath.Join(c.f.dir, "agent-"+phase+"-"+tier+".yaml")
	if err := os.WriteFile(name, []byte(contract), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := c.command(t, asUser, "run", name)
	cmd.Dir = "/"
	return cmd, path
}

func tomoyoResult(t *testing.T, c *crossOwner, cmd *exec.Cmd, path string, refused bool) {
	t.Helper()
	_, report, ok := strings.Cut(output(cmd), "LABEL-RESULT ")
	if !ok {
		t.Fatalf("no agent result:\n%s", output(cmd))
	}
	var got map[string]int
	if err := json.Unmarshal([]byte(strings.SplitN(report, "\n", 2)[0]), &got); err != nil {
		t.Fatal(err)
	}
	want := 0
	if refused {
		want = int(unix.EACCES)
	}
	if len(got) != 3 || got["read"] != want || got["truncate"] != want || got["create"] != want {
		t.Fatalf("operations=%v, want errno %d\n%s", got, want, output(cmd))
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	_, createErr := os.Stat(path + ".new")
	if refused {
		if string(data) != "preserve-me" || !os.IsNotExist(createErr) {
			t.Fatalf("refused open changed bytes or created leaf: %q %v", data, createErr)
		}
		count := 0
		var runID string
		for _, dir := range runDirs(t, c.f.root) {
			for _, ev := range events(t, dir) {
				if ev.Kind != record.KindFS || ev.Rule != "held-label-unavailable" || ev.Verdict != record.VerdictRefused {
					continue
				}
				var p struct{ Path string }
				if err := json.Unmarshal(ev.Payload, &p); err != nil {
					t.Fatal(err)
				}
				if p.Path == path || p.Path == path+".new" {
					count++
					if runID != "" && runID != filepath.Base(dir) {
						t.Fatal("operations belong to multiple runs")
					}
					runID = filepath.Base(dir)
				}
			}
		}
		log, err := os.ReadFile(filepath.Join(c.logHome, ".tego", "tego.log"))
		if err != nil {
			t.Fatal(err)
		}
		cause := "TOMOYO observed domain"
		if strings.Contains(path, "tomoyo-midrun-") || strings.Contains(path, "tomoyo-counter-") {
			cause = "TOMOYO's policy has been updated since boot; held file opens are refused on this machine until TOMOYO is unused again after a restart"
		}
		if strings.Contains(path, "tomoyo-enforcing-") {
			cause = "TOMOYO profile /sys/kernel/security/tomoyo/profile enforces"
		}
		if runID == "" || !tomoyoOwnLogCause(string(log), runID, cause) {
			t.Fatalf("TOMOYO own log lacks %q: %s", cause, log)
		}
		// A launcher that cannot read the profile says why a root tier would not have been refused.
		if strings.HasSuffix(path, "-counter-landlock") && !tomoyoOwnLogCause(string(log), runID, "this tier cannot read TOMOYO's profile") {
			t.Fatalf("TOMOYO own log lacks the sentence of a thread that cannot read the profile: %s", log)
		}
		if count != 3 {
			t.Fatalf("%s: got %d held-label-unavailable refusals, want 3", path, count)
		}
	} else if len(data) != 0 || createErr != nil {
		t.Fatalf("held truncate/create did not complete: %q %v", data, createErr)
	}
}

// A different run's refusal must not establish the cause of this tier's result.
func tomoyoOwnLogCause(log, runID, cause string) bool {
	for _, line := range strings.Split(log, "\n") {
		if !strings.Contains(line, cause) {
			continue
		}
		for _, field := range strings.Fields(line) {
			if field == "run="+runID {
				return true
			}
		}
	}
	return false
}

// A separate fresh boot isolates a counted policy write from policy activation.
// No loader is installed or invoked; all domains remain in the kernel domain.
func tomoyoCounterWithoutActivation(t *testing.T, c *crossOwner, actor string) {
	const statPath = "/sys/kernel/security/tomoyo/stat"
	before, err := os.ReadFile(statPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(before), "Policy update:                                 0\n") {
		t.Fatalf("not a fresh counter: %q", before)
	}
	f, err := os.OpenFile("/sys/kernel/security/tomoyo/exception_policy", os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, writeErr := f.WriteString("initialize_domain /vm/tomoyo-counter-only\n")
	closeErr := f.Close()
	if writeErr != nil || closeErr != nil {
		t.Fatalf("counted write: %v %v", writeErr, closeErr)
	}
	after, err := os.ReadFile(statPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("counted policy write, no loader: before %q; after %q", strings.SplitN(string(before), "\n", 2)[0], strings.SplitN(string(after), "\n", 2)[0])
	if strings.SplitN(string(before), "\n", 2)[0] == strings.SplitN(string(after), "\n", 2)[0] {
		t.Fatal("write did not move counter")
	}
	if _, err := os.Stat("/vm/tomoyo-loader"); !os.IsNotExist(err) {
		t.Fatalf("loader present: %v", err)
	}
	domain, err := os.ReadFile("/sys/kernel/security/tomoyo/self_domain")
	if err != nil || string(domain) != "<kernel>" {
		t.Fatalf("domain=%q: %v", domain, err)
	}
	// SEC08b: a launcher that can read the profile (root, the root tiers') proves nothing enforces and is admitted; tier
	// landlock's, the invoking user, cannot, and keeps the refusal, now with the sentence that says why.
	for _, tier := range []string{"landlock", "cgroup", "bpflsm"} {
		t.Run("counter without activation/"+tier, func(t *testing.T) {
			testutil.RequireTier(t, c.doctorRequire(t, tier), tier)
			asUser := tier == "landlock"
			cmd, path := tomoyoRunAs(t, c, actor, tier, "counter", "--held-label-agent", asUser)
			if err := cmd.Run(); err != nil {
				t.Fatalf("counter: %v\n%s", err, output(cmd))
			}
			tomoyoResult(t, c, cmd, path, asUser)
		})
	}
}

// tomoyoEnforcingProfile is the same activation as the main test's, in a fresh boot whose loader also defines profile 7
// in mode enforcing, a profile no domain uses and so denies nothing (the guest keeps running): SEC08b's proof refuses a
// mode enforcing anywhere in the profile, in every namespace, profile and category, so every tier, root's included,
// refuses its held opens naming it. The loader writes the line when /vm/tomoyo-enforcing is there (the policy can only
// be written at activation: afterwards TOMOYO admits writes from its registered managers alone).
func tomoyoEnforcingProfile(t *testing.T, c *crossOwner, actor string) {
	if err := os.WriteFile("/vm/tomoyo-enforcing", []byte("1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename("/vm/tomoyo-loader.fixture", "/vm/tomoyo-loader"); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("/vm/tomoyo-trigger").CombinedOutput(); err != nil {
		t.Fatalf("activate TOMOYO: %v\n%s", err, out)
	}
	profile, err := os.ReadFile("/sys/kernel/security/tomoyo/profile")
	if err != nil || !strings.Contains(string(profile), "7-CONFIG={ mode=enforcing ") {
		t.Fatalf("the loader did not define the enforcing profile (%v):\n%s", err, profile)
	}
	for _, tier := range []string{"landlock", "cgroup", "bpflsm"} {
		t.Run("enforcing_profile/"+tier, func(t *testing.T) {
			testutil.RequireTier(t, c.doctorRequire(t, tier), tier)
			cmd, path := tomoyoRun(t, c, actor, tier, "enforcing", "--held-label-agent")
			if err := cmd.Run(); err != nil {
				t.Fatalf("enforcing: %v\n%s", err, output(cmd))
			}
			tomoyoResult(t, c, cmd, path, true)
		})
	}
}
