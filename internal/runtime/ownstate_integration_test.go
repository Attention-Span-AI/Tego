// SPDX-License-Identifier: Apache-2.0

//go:build integration

package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestIntegrationOwnStateModesAreRestored is GAPS C52 at tier landlock, through the real binary. No Landlock ABI has a
// chmod right, so an agent with no write entry over tego's own state can still take its owner's rights away: this one
// runs chmod 000 on its run's events.jsonl, its run directory, the live index, the ledger root, chain.log and the
// directory that holds it. Its run ended 125 with the anchor unwritten, and every later run exited 125 at compile until
// the modes were restored by hand. Now the run ends with the modes restored, its anchor written and a gap line for
// each; a run that starts on modes taken away (here by the test, as an agent whose launcher died would leave them)
// restores them first and says so on stderr and in its ledger; and a link planted in place of chain.log is not
// followed.
func TestIntegrationOwnStateModesAreRestored(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("a root launcher restores no mode: it reads and writes through any (CAP_DAC_OVERRIDE), and " +
			"TestRestoreOwnStateLeavesWhatIsNotTheLaunchers holds it to that")
	}
	bin := tegoBinary(t)
	home := t.TempDir()
	state := filepath.Join(home, StateDir)
	anchor := filepath.Join(state, ledger.ChainLogFile)
	script := `r="$TEGO_LEDGER"; /bin/chmod 000 "$r/events.jsonl" "$r" "${r%/*}/` + ledger.LiveDir + `" "${r%/*}" '` +
		anchor + `' '` + state + `'`
	f := newFixture(t, contractFor("iownstate", []string{"/bin/sh", "-c", script}, []string{"/bin/sh", "/bin/chmod", "/bin/true"}))
	cfg := writeMachineConfig(t, f)
	t.Setenv("TEGO_TEST_CHAIN_ANCHOR", anchor)
	env := append(os.Environ(), "TEGO_CONFIG="+cfg)
	requireIsolatedEnv(t, env)
	// Registered after both directories, so it runs before their removal whatever a failed run left.
	t.Cleanup(func() { ownerRightsBack(home); ownerRightsBack(f.root) })
	live := filepath.Join(f.root, ledger.LiveDir)
	tegoRun := func(args ...string) (string, error) {
		run := exec.Command(bin, append([]string{"run", filepath.Join(f.dir, "agent.yaml")}, args...)...)
		run.Dir = f.dir
		run.Env = env
		out, err := run.CombinedOutput()
		return string(out), err
	}

	out, err := tegoRun()
	if err != nil {
		t.Fatalf("the run whose agent took tego's modes away: %v\n%s", err, out)
	}
	dirs := runDirs(t, f.root)
	if len(dirs) != 1 {
		t.Fatalf("run directories %v, want one", dirs)
	}
	first := dirs[0]
	events1 := filepath.Join(first, ledger.EventsFile)
	wantModes(t, map[string]os.FileMode{state: 0o700, anchor: 0o600, f.root: 0o700, live: 0o700, first: 0o700, events1: 0o600})
	// One line per mode restored, naming its path, the last lines before run_end.
	evs := events(t, first)
	end := len(evs) - 1
	if evs[end].Kind != record.KindRunEnd {
		t.Fatalf("the last line is %s, not run_end", evs[end].Kind)
	}
	var tail []string
	for i := end - 1; i > 0 && ownStateGap(evs[i]) != ""; i-- {
		tail = append(tail, ownStateGap(evs[i]))
	}
	wantPaths(t, "the lines before run_end", tail, state, anchor, f.root, live, first, events1)
	if rep, err := ledger.VerifyRunDir(context.Background(), first, ledger.NewFileChainAnchor(anchor)); err != nil || !rep.Anchored {
		t.Fatalf("the run does not verify against its anchor: %+v %v", rep, err)
	}

	// The next run starts, on modes something took away while no run was there to restore them at its end.
	for _, p := range []string{live, f.root, anchor, state} {
		if err := os.Chmod(p, 0); err != nil {
			t.Fatal(err)
		}
	}
	out, err = tegoRun("--", "/bin/true")
	if err != nil {
		t.Fatalf("the next run: %v\n%s", err, out)
	}
	if strings.Count(out, "[own-state-mode]") != 4 || !strings.Contains(out, anchor+" had mode 0000") {
		t.Errorf("the next run did not say what it restored:\n%s", out)
	}
	wantModes(t, map[string]os.FileMode{state: 0o700, anchor: 0o600, f.root: 0o700, live: 0o700})
	var second string
	for _, d := range runDirs(t, f.root) {
		if d != first {
			second = d
		}
	}
	var restored []string
	for _, ev := range events(t, second) {
		if p := ownStateGap(ev); p != "" {
			restored = append(restored, p)
		}
	}
	wantPaths(t, "the next run's lines", restored, state, anchor, f.root, live)
	// Those lines lost no action: the receipt says what tego restored in a note, and status in words, and neither
	// counts them among the gaps that make the counts a minimum (gaps.Restored).
	const words = "tego restored the modes of 4 of its own files"
	for _, args := range [][]string{{"receipt", filepath.Base(second), "--json"}, {"status", filepath.Base(second), "--json"}} {
		c := exec.Command(bin, args...)
		c.Dir, c.Env = f.dir, env
		o, err := c.Output()
		if err != nil {
			t.Fatalf("tego %s: %v\n%s", strings.Join(args, " "), err, o)
		}
		var view struct {
			Notes    []string `json:"notes"`
			GapWords string   `json:"gap_words"`
		}
		if err := json.Unmarshal(o, &view); err != nil {
			t.Fatalf("tego %s: %v\n%s", strings.Join(args, " "), err, o)
		}
		if !strings.Contains(strings.Join(view.Notes, "\n")+view.GapWords, words) {
			t.Errorf("tego %s does not say %q:\n%s", strings.Join(args, " "), words, o)
		}
	}

	// A link in place of chain.log is not followed: the file it names keeps its mode, and the run is refused as before.
	victim := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(victim, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(victim, 0); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(anchor, anchor+".kept"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, anchor); err != nil {
		t.Fatal(err)
	}
	if out, err = tegoRun("--", "/bin/true"); err == nil || !strings.Contains(out, "chain anchor: ") || !strings.Contains(out, ledger.ErrLinkRefused.Error()) {
		t.Errorf("a run anchored through a link planted at chain.log: %v, want the anchor's link refused\n%s", err, out)
	}
	wantModes(t, map[string]os.FileMode{victim: 0})
}

// TestIntegrationOwnStateConfigLayerIsRestoredFirst is GAPS C52's ~/.tego through the real binary, laid out as a home
// is: the machine config the runs read lives in ~/.tego, beside chain.log and tego.log (the test build reads it through
// TEGO_CONFIG, the trust check's same path, and keeps its own state under TEGO_TEST_OWN_LOG_HOME). The config is read
// before anything else, so a run started on its mode or ~/.tego's taken was refused [config-untrusted] before it
// restored anything, and so was every run after it. Here an agent takes both from inside its own run, whose end gives
// both back, so the commands after it read the layer and the next run starts with nothing to give back; then a run
// starts on both taken while no run was there to give them back (a root launcher's agent, or one whose launcher died;
// here the test's chmod) and gives them back before it reads the config. A ~/.tego that group or others could write
// is still refused: the restore gives the owner their bits back and leaves the rest to the trust check.
func TestIntegrationOwnStateConfigLayerIsRestoredFirst(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("a root launcher restores no mode: it reads and writes through any (CAP_DAC_OVERRIDE)")
	}
	bin := tegoBinary(t)
	home := t.TempDir()
	state := filepath.Join(home, StateDir)
	anchor := filepath.Join(state, ledger.ChainLogFile)
	layer := filepath.Join(home, config.UserRelPath)
	script := `/bin/chmod 000 '` + layer + `' '` + state + `'`
	f := newFixture(t, contractFor("iownlayer", []string{"/bin/sh", "-c", script}, []string{"/bin/sh", "/bin/chmod", "/bin/true"}))
	body, err := os.ReadFile(writeMachineConfig(t, f))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(state, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(layer, body, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TEGO_TEST_CHAIN_ANCHOR", anchor)
	t.Setenv("TEGO_TEST_OWN_LOG_HOME", home)
	env := append(os.Environ(), "TEGO_CONFIG="+layer)
	requireIsolatedEnv(t, env)
	t.Cleanup(func() { ownerRightsBack(home); ownerRightsBack(f.root) })
	tegoRun := func(args ...string) (string, error) {
		run := exec.Command(bin, append([]string{"run", filepath.Join(f.dir, "agent.yaml")}, args...)...)
		run.Dir, run.Env = f.dir, env
		out, err := run.CombinedOutput()
		return string(out), err
	}

	if out, err := tegoRun(); err != nil {
		t.Fatalf("the run whose agent took the modes of the config and of ~/.tego: %v\n%s", err, out)
	}
	// Its end gave both back, ~/.tego as chain.log's directory and the layer's home, and named them on its last lines.
	wantModes(t, map[string]os.FileMode{state: 0o700, layer: 0o400})
	first := runDirs(t, f.root)
	if len(first) != 1 {
		t.Fatalf("run directories %v, want one", first)
	}
	evs := events(t, first[0])
	var tail []string
	for i := len(evs) - 2; i > 0 && ownStateGap(evs[i]) != ""; i-- {
		tail = append(tail, ownStateGap(evs[i]))
	}
	wantPaths(t, "the agent's run's lines before run_end", tail, state, layer)
	if out, err := tegoRun("--", "/bin/true"); err != nil || strings.Contains(out, "[own-state-mode]") {
		t.Fatalf("the run after the agent's: %v, want it started with nothing to give back\n%s", err, out)
	}

	// A run started on both taken while no run was there to give them back.
	for _, p := range []string{layer, state} { // ~/.tego last: its owner can no longer search it
		if err := os.Chmod(p, 0); err != nil {
			t.Fatal(err)
		}
	}
	before := runDirs(t, f.root)
	out, err := tegoRun("--", "/bin/true")
	if err != nil || strings.Count(out, "[own-state-mode]") != 2 || !strings.Contains(out, state+" had mode 0000") ||
		!strings.Contains(out, layer+" had mode 0000") {
		t.Fatalf("a run started on ~/.tego and the config at mode 0000: %v, want both given back and the run started\n%s", err, out)
	}
	wantModes(t, map[string]os.FileMode{state: 0o700, layer: 0o400})
	var restored []string
	for _, d := range runDirs(t, f.root) {
		if slices.Contains(before, d) {
			continue
		}
		for _, ev := range events(t, d) {
			if p := ownStateGap(ev); p != "" {
				restored = append(restored, p)
			}
		}
	}
	wantPaths(t, "that run's lines", restored, state, layer)

	// Group-writable with the owner's bits taken: the owner's come back, the group's stay, and the trust check refuses.
	if err := os.Chmod(state, 0o070); err != nil {
		t.Fatal(err)
	}
	if out, err := tegoRun("--", "/bin/true"); err == nil || !strings.Contains(out, "[config-untrusted]") ||
		!strings.Contains(out, "group or other writable") {
		t.Errorf("a run on a ~/.tego its group could write: %v, want it refused by the trust check\n%s", err, out)
	}
	wantModes(t, map[string]os.FileMode{state: 0o770})
}

// TestIntegrationOwnStateRuntimeParentIsRestored: every run of a user makes its runtime directory in
// $XDG_RUNTIME_DIR/tego, and an agent can chmod that parent and its own directory in it. The parent at 0000 refused
// every later run [run] ("create run socket dir: ... permission denied"), and the run's own directory at 0000 could not
// be removed at its end. Now the run gives both back before its Close, names them on its last lines and removes its
// directory; the next run starts; and so does one started on a parent taken while no run was there to give it back.
func TestIntegrationOwnStateRuntimeParentIsRestored(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("a root launcher makes no runtime directory (createRuntimeDir) and restores no mode")
	}
	bin := tegoBinary(t)
	xdg := t.TempDir()
	if err := os.Chmod(xdg, 0o700); err != nil { // as logind makes it: only its user can write it
		t.Fatal(err)
	}
	parent := filepath.Join(xdg, agent.RuntimeDirName)
	script := `/bin/chmod 000 "${TEGO_REASON%/*}" '` + parent + `'`
	f := newFixture(t, contractFor("iownruntime", []string{"/bin/sh", "-c", script}, []string{"/bin/sh", "/bin/chmod", "/bin/true"}))
	cfg := writeMachineConfig(t, f) // before os.Environ is read: it sets the variables that keep the binary in the test
	env := append(os.Environ(), "TEGO_CONFIG="+cfg, "XDG_RUNTIME_DIR="+xdg)
	requireIsolatedEnv(t, env)
	t.Cleanup(func() { ownerRightsBack(xdg); ownerRightsBack(f.root) })
	tegoRun := func(args ...string) (string, error) {
		run := exec.Command(bin, append([]string{"run", filepath.Join(f.dir, "agent.yaml")}, args...)...)
		run.Dir, run.Env = f.dir, env
		out, err := run.CombinedOutput()
		return string(out), err
	}

	if out, err := tegoRun(); err != nil {
		t.Fatalf("the run whose agent took the modes of the runtime parent and its own runtime directory: %v\n%s", err, out)
	}
	dirs := runDirs(t, f.root)
	if len(dirs) != 1 {
		t.Fatalf("run directories %v, want one", dirs)
	}
	own := filepath.Join(parent, filepath.Base(dirs[0]))
	wantModes(t, map[string]os.FileMode{parent: 0o700})
	if _, err := os.Lstat(own); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the run's runtime directory %s is still there (%v): its end could not remove it", own, err)
	}
	evs := events(t, dirs[0])
	var tail []string
	for i := len(evs) - 2; i > 0 && ownStateGap(evs[i]) != ""; i-- {
		tail = append(tail, ownStateGap(evs[i]))
	}
	wantPaths(t, "the lines before run_end", tail, parent, own)
	if out, err := tegoRun("--", "/bin/true"); err != nil {
		t.Fatalf("the run after the agent's: %v\n%s", err, out)
	}

	// A run started on a parent whose mode was taken while no run was there to give it back.
	if err := os.Chmod(parent, 0); err != nil {
		t.Fatal(err)
	}
	if out, err := tegoRun("--", "/bin/true"); err != nil || !strings.Contains(out, parent+" had mode 0000") {
		t.Fatalf("a run started on the runtime parent at mode 0000: %v, want it restored and the run started\n%s", err, out)
	}
	wantModes(t, map[string]os.FileMode{parent: 0o700})
}

// ownStateGap is the path ev names when it is a gap what=record why=own-state-mode-restored, else "".
func ownStateGap(ev *record.Event) string {
	if ev.Kind != record.KindGap {
		return ""
	}
	var g record.GapPayload
	if err := ev.DecodePayload(&g); err != nil || g.What != record.GapRecord || g.Why != record.GapOwnStateModeRestored {
		return ""
	}
	return g.Binary
}

// wantPaths fails the test unless got holds exactly the paths want, in any order.
func wantPaths(t *testing.T, what string, got []string, want ...string) {
	t.Helper()
	got, want = slices.Sorted(slices.Values(got)), slices.Sorted(slices.Values(want))
	if !slices.Equal(got, want) {
		t.Errorf("%s name the restored modes %q, want %q", what, got, want)
	}
}

// wantModes fails the test unless each path has exactly its permission bits.
func wantModes(t *testing.T, want map[string]os.FileMode) {
	t.Helper()
	for p, m := range want {
		st, err := os.Lstat(p)
		if err != nil {
			t.Errorf("%s: %v", p, err)
		} else if st.Mode().Perm() != m {
			t.Errorf("%s has mode %04o, want %04o", p, st.Mode().Perm(), m)
		}
	}
}
