// SPDX-License-Identifier: Apache-2.0

package rows

import (
	"crypto/sha256"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/policy/execmatch"
)

// Review 1: Node's config and env-file scanners do not stop at the entry
// script. These are the reviewer's exact vectors under allow A / deny B.
func TestNodeReviewPrescans(t *testing.T) {
	ix := rules(t, "allow: a.js *", "deny: b.js")
	for _, argv := range [][]string{
		{"node", "./a.js", "--ci", "--experimental-config-file=evil.json"},
		{"node", "--", "./a.js", "--experimental-default-config-file"},
		{"node", "./a.js", "x", "--experimental-default-config-file=1"},
		{"node", "./a.js", "--experimental-config-file", "evil.json"},
		{"node", "-", "--experimental-config-file=evil.json"},
		{"node", "./a.js", "--env-file", "evil.env"},
		{"node", "./a.js", "--env-file-if-exists=evil.env"},
	} {
		t.Run(argv[len(argv)-1], func(t *testing.T) {
			f := facts("node", "node", argv...)
			if r := ix.Decide(&f); r.Outcome != execmatch.OutcomeRefused || r.Rule() != execmatch.RuleCommandUnresolved {
				t.Fatalf("%q: %s; want command-unresolved", argv, decided(r))
			}
			for k := 1; k < len(argv); k++ {
				f.Argv, f.ArgvComplete = argv[:k], false
				if r := ix.Decide(&f); r.Final && r.Outcome != execmatch.OutcomeRefused {
					t.Fatalf("prefix %q settles %s before the scanner sees the suffix", f.Argv, decided(r))
				}
			}
		})
	}
}

// TestNodeReviewDifferential executes the exact reported argv. Additional
// runtimes are supplied as a directory of Node distribution directories; they
// are never added to the known build registry merely because they were probed.
func TestNodeReviewDifferential(t *testing.T) {
	nodePath, err := exec.LookPath("node")
	if err != nil {
		t.Skip("no node installed")
	}
	bins := []string{nodePath}
	if dir := os.Getenv("TEGO_NODE_REVIEW_DIR"); dir != "" {
		extra, err := filepath.Glob(filepath.Join(dir, "node-*", "bin", "node"))
		if err != nil {
			t.Fatal(err)
		}
		bins = append(bins, extra...)
	}
	ix := rules(t, "allow: a.js *", "deny: b.js")
	master := nodeMasterRules(t, "allow: a.js *", "deny: b.js")
	base := t.TempDir()
	for _, nodePath := range bins {
		v, err := exec.Command(nodePath, "--version").Output()
		if err != nil {
			t.Fatal(err)
		}
		version := strings.TrimSpace(string(v))
		attested := nodeAttestedBuild(t, nodePath)
		// Predict execution only on the exact measured review runtimes.
		// Other versions may reject these options. Raw scans refuse on every
		// build; unknown attached code-loading options retain master's residual.
		configRuntime := version == "v22.21.1" || version == "v24.22.2" || version == "v25.9.0"
		envRuntime := version == "v20.19.4" || configRuntime
		testRuntime := version == "v24.22.2" || version == "v25.9.0"
		t.Run(version, func(t *testing.T) {
			cases := [][]string{
				{"./a.js", "--ci", "--experimental-config-file=evil.json"},
				{"--", "./a.js", "--experimental-default-config-file"},
				{"./a.js", "x", "--experimental-default-config-file=1"},
				{"./a.js", "--experimental-config-file", "evil.json"},
				{"-", "--experimental-config-file=evil.json"},
				{"./a.js", "--env-file", "evil.env"},
				{"./a.js", "--env-file-if-exists=evil.env"},
			}
			if attested == "" {
				cases = append(cases, []string{"--test", "--test-global-setup=./b.js", "./a.js"},
					[]string{"--test", "--test-isolation=none", "./a.js", "./b.js"}, []string{"./a.js"})
			}
			cases = append(cases, []string{"@ARGV0@--experimental-config-file=evil.json", "./a.js"},
				[]string{"@ARGV0@--env-file=evil.env", "./a.js"})
			for i, args := range cases {
				argv, main, pre, err := runNodeLine(nodePath, base, args)
				if err != nil {
					t.Fatal(err)
				}
				ranB := main.script == "b.js" || slices.ContainsFunc(pre, func(r nodeRan) bool { return r.script == "b.js" })
				mustRunB := i < 5 && configRuntime || i >= 5 && i < 7 && envRuntime || i >= 7 && i < 9 && testRuntime
				// This exact Node 24 build rejects the =1 spelling before
				// execution; Node 22 and 25 execute B. All must refuse it.
				if i == 2 && version == "v24.22.2" {
					mustRunB = false
				}
				if strings.HasPrefix(args[0], "@ARGV0@") {
					mustRunB = configRuntime || envRuntime && strings.Contains(args[0], "env-file")
				}
				if mustRunB && !ranB {
					t.Fatalf("%q did not execute B; main=%+v pre=%+v", args, main, pre)
				}
				f := facts("node", "node", append([]string{"node"}, argv...)...)
				f.NodeVersion = attested
				if strings.HasPrefix(args[0], "@ARGV0@") {
					f.Argv0 = strings.TrimPrefix(args[0], "@ARGV0@")
					f.Argv[0] = f.Argv0
				}
				r := ix.Decide(&f)
				if attested == "" && i >= 7 && i <= 9 {
					want := master.Decide(&f)
					// Future attached code-loading options retain the
					// master residual only on the unknown-build path.
					if r.Outcome != want.Outcome || r.Rule() != want.Rule() {
						t.Fatalf("%q (real B=%v): %s, master %s", argv, ranB, decided(r), decided(want))
					}
					t.Logf("%q: real B=%v, %s (master compatibility)", argv, ranB, decided(r))
				} else if r.Outcome != execmatch.OutcomeRefused || r.Rule() != execmatch.RuleCommandUnresolved {
					t.Fatalf("%q (real B=%v): %s", argv, ranB, decided(r))
				}
			}
			if attested != "" {
				// These two newer spellings are absent from the pinned
				// inventories. Prove the actual pinned CLI rejects them before
				// JavaScript runs; do not pretend they are inventoried arities.
				for _, args := range [][]string{
					{"--test", "--test-global-setup=./b.js", "./a.js"},
					{"--test", "--test-isolation=none", "./a.js", "./b.js"},
				} {
					cmd := exec.Command(nodePath, args...)
					cmd.Dir, cmd.Env = base, []string{"HOME=" + base, "TMPDIR=" + base, "PATH=/usr/bin:/bin"}
					out, err := cmd.CombinedOutput()
					name, _, _ := strings.Cut(args[1], "=")
					if err == nil || !strings.Contains(string(out), "bad option: "+name) {
						t.Fatalf("pinned %s %q must reject the unsupported option: err=%v output=%s", version, args, err, out)
					}
				}
			}

		})
	}
}

func TestNodePrescanArgv0(t *testing.T) {
	ix := rules(t, "allow: a.js *", "deny: b.js")
	for _, arg0 := range []string{"--experimental-config-file=evil.json", "--experimental-default-config-file", "--env-file=evil.env"} {
		f := facts("node", "node", arg0, "./a.js")
		if r := ix.Decide(&f); r.Rule() != execmatch.RuleCommandUnresolved {
			t.Errorf("argv0 %q: %s", arg0, decided(r))
		}
	}
}

func TestNodeVersionedNamesAndAttestationScopes(t *testing.T) {
	ix := rules(t, "allow: a.js *", "deny: b.js")
	for _, name := range []string{"node", "nodejs", "node-22", "node-24.22.2"} {
		for _, version := range []string{"", "18.20.8", "24.22.2", "25.9.0", "22.21.1"} {
			f := facts(name, name, name, "./a.js")
			f.NodeVersion = version
			r := ix.Decide(&f)
			if r.Outcome != execmatch.OutcomeAllowed {
				t.Errorf("%s, attested %q: %s", name, version, decided(r))
			}
		}
	}
	// Attestation for an outer image must not vouch for its interpreter or
	// a loader's program, nor may a known shebang stage vouch for another.
	f := facts("wrapper", "wrapper", "wrapper")
	f.Form = execmatch.FormScript
	f.Interp = []execmatch.Stage{{Path: "node", NodeVersion: "22.21.1"}, {Path: "node"}}
	seenUnknown := false
	for _, inv := range ix.Interpretations(&f) {
		if inv.Tool == "node" && inv.NodeVersion == "" {
			seenUnknown = true
			if inv.Row != Builtin().Lookup("node").Interp.Fallback {
				t.Fatal("unknown stage borrowed the outer inventory")
			}
		}
	}
	if !seenUnknown {
		t.Fatal("unknown stage was dropped")
	}
	if r := ix.Decide(&f); r.Outcome == execmatch.OutcomeRefused {
		t.Fatalf("unknown second stage: %s", decided(r))
	}
	f.Form = execmatch.FormDirect
	f.Interp = nil
	f.Loaded = &execmatch.Loaded{Path: "node", Image: "node", Argv: []string{"node", "./a.js"}}
	if r := ix.Decide(&f); r.Outcome != execmatch.OutcomeAllowed {
		t.Fatalf("unknown loaded image: %s", decided(r))
	}
	for _, inv := range ix.Interpretations(&f) {
		if inv.Tool == "node" && inv.Row != Builtin().Lookup("node").Interp.Fallback {
			t.Fatal("unknown loaded image borrowed the outer inventory")
		}
	}
}

// Live tests use exactly the same build registry as the descriptor producer.
// Merely observing --version never makes a runtime known.
func nodeAttestedBuild(t testing.TB, bin string) string {
	t.Helper()
	file, err := os.Open(bin)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.New()
	_, readErr := io.Copy(h, file)
	closeErr := file.Close()
	if readErr != nil || closeErr != nil {
		t.Fatalf("hash: %v / %v", readErr, closeErr)
	}
	var sum [32]byte
	copy(sum[:], h.Sum(nil))
	return NodeBuildVersion(sum)
}
