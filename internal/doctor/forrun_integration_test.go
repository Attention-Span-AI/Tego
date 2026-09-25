// SPDX-License-Identifier: Apache-2.0

//go:build integration

package doctor

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
	"testing"
	"time"

	"golang.org/x/sys/unix"

	bpfobj "github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/internal/runtime/capture/uprobe"
	"github.com/attention-span-ai/tego/internal/testutil"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// TestIntegrationForRunAsRoot is ACC-F2-probe-per-run on a real kernel, as root: a run at reach landlock runs
// no program-load, LSM or fanotify probe; a run at reach cgroup probes D7's tier-2 rows and D8 once, keeps the
// answer in /run/tego, and the next run reads it; every tier at or below the reach is offered and explained
// as doctor.Run offers and explains it; and an entry anyone but root could have written is never read.
func TestIntegrationForRunAsRoot(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("a run's probe differs from doctor's only as root, where D6, D7 and D8 load programs (CAP_BPF, CAP_SYS_ADMIN)")
	}
	ctx := context.Background()
	full, err := Run(ctx, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	same := func(name string, rep *Report, reach backend.Tier) {
		t.Helper()
		for _, tier := range backend.Tiers() {
			if tier.AtOrBelow(reach) && (rep.Probe()[tier] != full.Probe()[tier] || rep.WhyNot(tier) != full.WhyNot(tier)) {
				t.Errorf("%s: tier %s offered=%v %q; doctor %v %q", name, tier, rep.Probe()[tier], rep.WhyNot(tier),
					full.Probe()[tier], full.WhyNot(tier))
			}
		}
	}

	start := time.Now()
	ll, err := ForRun(ctx, nil, backend.TierLandlock)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("reach landlock: %v", time.Since(start))
	for _, r := range ll.Results {
		switch r.ID {
		case CheckBTF, CheckLSM, CheckPrograms, CheckFanotify:
			if !strings.HasPrefix(r.Detail, "not probed by tego run") {
				t.Errorf("reach landlock ran %s: %s", r.ID, r.Detail)
			}
		}
	}
	if len(ll.Programs) != 0 || ll.FromCache() {
		t.Errorf("reach landlock has %d D7 rows, from cache %v", len(ll.Programs), ll.FromCache())
	}
	same("reach landlock", ll, backend.TierLandlock)

	c := defaultRunCache()
	uid, _ := config.InvokingUID()
	key, ok := c.key(full.Kernel, uid)
	if !ok {
		if bpfobj.Available() {
			t.Fatal("a root build with the objects could not read the run-probe cache's key")
		}
		t.Skip("no bpf_hash in a build without the objects, so there is no run-probe cache to test")
	}
	path := filepath.Join("/run/tego", c.name(key))
	c.drop(key)
	start = time.Now()
	first, err := ForRun(ctx, nil, backend.TierCgroup)
	if err != nil {
		t.Fatal(err)
	}
	probed := time.Since(start)
	start = time.Now()
	second, err := ForRun(ctx, nil, backend.TierCgroup)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("reach cgroup: probed %v, then %v (from cache %v)", probed, time.Since(start), second.FromCache())
	same("reach cgroup, probed", first, backend.TierCgroup)
	same("reach cgroup, second", second, backend.TierCgroup)
	// The plane's rows are read at reach cgroup: they select tier cgroup's plane mode (enforce-plane R19).
	var tierRows []HookResult
	for _, r := range first.Programs {
		if r.Plane != "" {
			continue
		}
		tierRows = append(tierRows, r)
		if r.Tier != backend.TierCgroup || r.Capture {
			t.Errorf("reach cgroup probed %s (tier %q, capture %v), which no tier up to cgroup reads", r.Hook, r.Tier, r.Capture)
		}
	}
	if first.Plane == nil || first.Plane.Source != planeSourceProbed {
		t.Errorf("reach cgroup after a drop: plane %+v, want a probed answer", first.Plane)
	}
	if first.FromCache() {
		t.Error("the first run after a drop read the cache")
	}
	var fan FanotifyState
	if first.Fanotify != nil {
		fan = *first.Fanotify
	}
	vouched := vouches(first.Results[6], tierRows, first.Results[7], fan)
	if !vouched {
		if second.FromCache() {
			t.Error("an answer that does not vouch for tier cgroup was read back")
		}
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Errorf("an answer that does not vouch for tier cgroup was kept: %v", err)
		}
		t.Skipf("this machine does not give tier cgroup, so nothing is kept: %s", full.WhyNot(backend.TierCgroup))
	}
	if !second.FromCache() {
		t.Fatal("the second run at reach cgroup probed again instead of reading the answer the first kept")
	}
	if second.Plane == nil || second.Plane.Source != planeSourceRunCache || second.Plane.Selected != first.Plane.Selected {
		t.Errorf("the second run's plane %+v, want the first's answer from the cache", second.Plane)
	}
	// doctor always probes afresh, with an answer kept beside it.
	if again, err := Run(ctx, nil, ""); err != nil || again.FromCache() {
		t.Errorf("doctor.Run with a kept answer: %v, from cache %v", err, again != nil && again.FromCache())
	}
	var st unix.Stat_t
	if err := unix.Lstat(path, &st); err != nil || st.Uid != 0 || st.Mode&0o077 != 0 || st.Mode&unix.S_IFMT != unix.S_IFREG {
		t.Fatalf("the kept answer %s: %v, uid %d, mode %#o", path, err, st.Uid, st.Mode)
	}

	// An entry anyone but root could have written is not read, and the fresh answer replaces it.
	untrusted := map[string]func() error{
		"readable by others": func() error { return os.Chmod(path, 0o644) },
		"owned by a user":    func() error { return os.Chown(path, 65534, 65534) },
		"its directory writable by others": func() error {
			return os.Chmod(filepath.Dir(path), 0o777)
		},
	}
	kept := second // the last report read from the cache
	for name, tamper := range untrusted {
		if err := tamper(); err != nil {
			t.Fatal(err)
		}
		rep, err := ForRun(ctx, nil, backend.TierCgroup)
		if err != nil {
			t.Fatal(err)
		}
		if rep.FromCache() {
			t.Errorf("%s: the entry was read", name)
		}
		same("reach cgroup, "+name, rep, backend.TierCgroup)
		if err := os.Chmod(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		// With the directory trusted again, the next run keeps its own answer and reads it after that.
		if _, err := ForRun(ctx, nil, backend.TierCgroup); err != nil {
			t.Fatal(err)
		}
		if rep, err := ForRun(ctx, nil, backend.TierCgroup); err != nil || !rep.FromCache() {
			t.Errorf("%s: after the directory was trusted again, the kept answer was not read (%v)", name, err)
		} else {
			kept = rep
		}
	}

	// DiscardCache removes only the file its report was read from (R27). The runs above renamed fresh answers over
	// the entry second was read from, so second's discard leaves the entry, and the report read from it removes it.
	if kept == second {
		t.Fatal("no report was read from the entry the runs after tampering kept")
	}
	second.DiscardCache()
	if _, err := os.Stat(path); err != nil {
		t.Errorf("DiscardCache of a report read from a replaced entry removed the fresh one at %s: %v", path, err)
	}
	kept.DiscardCache()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("DiscardCache left %s: %v", path, err)
	}
}

// TestIntegrationRestrictedRootRunAfterFullRoot runs what was found as root in the KVM guest on 6.17 the way it was
// found (R27 "What a run probes", E30): a tegobpf tego as root under sudo, an auto contract, and a second root
// process started with CAP_BPF, CAP_SYS_ADMIN, CAP_PERFMON and CAP_NET_ADMIN out of its bounding set (setpriv, as a
// systemd unit's CapabilityBoundingSet= would start it). With a key of the machine alone, the restricted run read the
// answer the full-root run had kept, was offered tier cgroup, and stopped at Prepare with "load program: operation not
// permitted", exit 125, every time a full-root run had kept the answer again. Each process's own privilege is in the
// key now: the full-root runs run at the machine's highest tier (bpflsm where LSM mode passes, else cgroup: an auto
// run as root reaches tier bpflsm since TIER3-PLAN T7, and its scope keeps the answer as reach cgroup's does), the
// second from the answer the first kept, and the restricted runs run at tier landlock with exit 0 and leave that
// answer in place.
func TestIntegrationRestrictedRootRunAfterFullRoot(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("the restricted and full-root runs are both root: run as `sudo go test -tags integration,tegobpf` or `make vm-root-test`")
	}
	uid, uerr := strconv.Atoi(os.Getenv("SUDO_UID"))
	gid, gerr := strconv.Atoi(os.Getenv("SUDO_GID"))
	if uerr != nil || gerr != nil || uid <= 0 {
		t.Skip("a root `tego run` drops the agent to the sudo caller and refuses without SUDO_UID and SUDO_GID")
	}
	setpriv, err := exec.LookPath("setpriv")
	if err != nil {
		t.Skipf("the restricted root process is started by setpriv (util-linux): %v", err)
	}
	hash, err := bpfobj.Hash()
	if err != nil {
		t.Skipf("this test binary carries no BPF objects; the run belongs to the tegobpf suite: %v", err)
	}
	base, err := os.MkdirTemp("", "tego-probe-priv-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	// The full-root runs place the capture probes on libssl and leave their removal to a detacher that waits out
	// uprobe.ProbeGrace after the last run has left (internal/runtime/capture/uprobe). This test's runs are its own
	// to finish: left in flight, they were pinned when the next test in the suite read /sys/fs/bpf and gone when it
	// read it again, and TestIntegrationDoctorCancelledDuringThePlaneLeavesNothing failed on both boots for state
	// this test left. The built tego embeds this binary's objects, so its pins are under this hash.
	t.Cleanup(func() {
		waitDetached(t, filepath.Join("/sys/fs/bpf/tego", hash, uprobe.UprobePinDir), uprobe.ProbeGrace+30*time.Second)
	})
	if err := os.Chmod(base, 0o755); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(base, "tego")
	build := exec.Command("go", "build", "-tags", "tegobpf,tegotesthooks", "-trimpath", "-o", bin, "github.com/attention-span-ai/tego/cmd/tego")
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Skipf("cannot build the tegobpf tego binary: %v: %s", err, out)
	}
	// No tier cgroup, no answer to keep. Either check fails the test when doctor gives no answer about the machine
	// (testutil.DoctorOffers): read as "not offered", a refused config once made bpflsm look absent.
	testutil.RequireTier(t, isolatedTego(t, bin, "doctor", "--require", "cgroup"), "cgroup")
	full := string(backend.TierCgroup)
	offered, out, err := testutil.DoctorOffers(isolatedTego(t, bin, "doctor", "--require", "bpflsm"))
	if err != nil {
		t.Fatalf("tego doctor --require bpflsm gave no answer about this machine: %v\n%s", err, out)
	}
	if offered {
		full = string(backend.TierBPFLSM)
	}
	project := filepath.Join(base, "project")
	if err := os.Mkdir(project, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Lchown(project, uid, gid); err != nil {
		t.Fatal(err)
	}
	contract := filepath.Join(project, "agent.yaml")
	if err := os.WriteFile(contract, []byte("version: 0\nname: probe-priv\ncommand: [\"true\"]\nexec:\n  allow: [\"true\"]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	ledgerRoot := filepath.Join(base, "ledger")
	if err := os.Mkdir(ledgerRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(base, "config.yaml")
	if err := os.WriteFile(cfg, []byte(fmt.Sprintf("version: 0\nledger_root: %s\n", ledgerRoot)), 0o644); err != nil {
		t.Fatal(err)
	}
	// Start from no kept answer, so the first full-root run is the one that keeps it.
	entries := func() []string {
		names, _ := filepath.Glob("/run/tego/doctor-probe-*.json")
		return names
	}
	for _, name := range entries() {
		_ = os.Remove(name)
	}

	seen := map[string]bool{}
	run := func(what string, prefix ...string) string {
		t.Helper()
		argv := append(append([]string(nil), prefix...), bin, "run", contract, "--", "true")
		cmd := exec.Command(argv[0], argv[1:]...)
		cmd.Dir = project
		cmd.Env = testutil.TegoEnv(t, base, "TEGO_CONFIG="+cfg)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		start := time.Now()
		err := cmd.Run()
		t.Logf("%s: %v, %v", what, time.Since(start), err)
		if err != nil {
			t.Fatalf("%s: `tego run` of an auto contract: %v\n%s", what, err, stderr.String())
		}
		runs, _ := filepath.Glob(filepath.Join(ledgerRoot, "*", "events.jsonl"))
		for _, r := range runs {
			if seen[r] {
				continue
			}
			seen[r] = true
			line, _, _ := bytes.Cut(mustRead(t, r), []byte("\n"))
			var start struct {
				Kind string `json:"kind"`
				Tier string `json:"tier"`
			}
			if err := json.Unmarshal(line, &start); err != nil || start.Kind != "run_start" {
				t.Fatalf("%s: the ledger's first line %q: %v", what, line, err)
			}
			return start.Tier
		}
		t.Fatalf("%s: no new ledger under %s\n%s", what, ledgerRoot, stderr.String())
		return ""
	}
	restricted := []string{setpriv, "--no-new-privs", "--bounding-set", "-bpf,-sys_admin,-perfmon,-net_admin", "--"}

	var kept string
	var keptAt os.FileInfo
	for round := 1; round <= 2; round++ {
		if tier := run(fmt.Sprintf("round %d, full root", round)); tier != full {
			t.Fatalf("round %d: the full-root auto run ran at %q, want %s", round, tier, full)
		}
		names := entries()
		if len(names) != 1 {
			t.Fatalf("round %d: after the full-root run the kept answers are %v, want one", round, names)
		}
		fi, err := os.Stat(names[0])
		if err != nil {
			t.Fatal(err)
		}
		if round == 1 {
			kept, keptAt = names[0], fi
		} else if names[0] != kept || !os.SameFile(fi, keptAt) || !fi.ModTime().Equal(keptAt.ModTime()) {
			// A run that read the answer writes nothing; one that probed would have replaced the file.
			t.Errorf("round 2: the full-root run did not run from the answer round 1 kept (%s, then %s)", kept, names[0])
		}
		if tier := run(fmt.Sprintf("round %d, restricted root", round), restricted...); tier != string(backend.TierLandlock) {
			t.Errorf("round %d: the restricted root auto run ran at %q, want landlock", round, tier)
		}
		if names := entries(); len(names) != 1 || names[0] != kept {
			t.Errorf("round %d: after the restricted run the kept answers are %v, want only %s", round, names, kept)
		}
	}
}

// isolatedTego is exec.Command for a tego built with tegotesthooks, for a command the test starts before it has a
// machine config of its own (doctor, asked which tier this machine offers). It gets the isolation the test's runs get,
// in a directory of its own: a machine config naming a ledger root there, and testutil.TegoEnv's chain anchor and
// own-log home beside it. A test build refuses a machine config whose ledger root lies inside the invoking user's own
// ~/.tego, the built-in ~/.tego/runs included (identity-config.md R27), and under sudo that user is the sudo caller:
// given no machine config, doctor exited 125, the test skipped as though the machine offered no tier cgroup, and
// `--require bpflsm` would have read as no tier bpflsm.
func isolatedTego(t *testing.T, bin string, args ...string) *exec.Cmd {
	t.Helper()
	dir, err := os.MkdirTemp("", "tego-iso-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	ledger := filepath.Join(dir, "ledger")
	if err := os.Mkdir(ledger, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfg, []byte(fmt.Sprintf("version: 0\nledger_root: %s\n", ledger)), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, args...)
	cmd.Env = testutil.TegoEnv(t, dir, "TEGO_CONFIG="+cfg)
	return cmd
}

// waitDetached waits until dir, a build's directory of pinned capture probes, holds nothing (or is gone), and fails
// the test when the probes are still pinned at the deadline: a run's probes outliving their grace by that much is a
// finding, not a wait to lengthen.
func waitDetached(t *testing.T, dir string, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	for {
		entries, err := os.ReadDir(dir)
		if os.IsNotExist(err) || (err == nil && len(entries) == 0) {
			return
		}
		if time.Now().After(deadline) {
			names := make([]string, 0, len(entries))
			for _, e := range entries {
				names = append(names, e.Name())
			}
			t.Errorf("the runs' capture probes under %s were still pinned %v after the last run: %v (%v)", dir, within, names, err)
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// mustRead is a file's contents.
func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
