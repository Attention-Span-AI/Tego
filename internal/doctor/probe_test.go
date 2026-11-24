// SPDX-License-Identifier: Apache-2.0

package doctor

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/selfbin"
	"github.com/attention-span-ai/tego/internal/shellword"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// TestProbeShape is §4's post-condition: exactly nine results, D1..D9 in R27's fixed order, each
// with a detail, and a fix on every failure.
func TestProbeShape(t *testing.T) {
	rs := Probe(context.Background(), os.Getuid())
	want := []CheckID{CheckKernel, CheckBTF, CheckCgroupV2, CheckLandlock,
		CheckSeccomp, CheckLSM, CheckPrograms, CheckFanotify, CheckSwap}
	if len(rs) != len(want) {
		t.Fatalf("got %d results, want %d: %+v", len(rs), len(want), rs)
	}
	for i, r := range rs {
		if r.ID != want[i] {
			t.Errorf("result %d id %q want %q", i, r.ID, want[i])
		}
		if r.Detail == "" {
			t.Errorf("%s: empty detail", r.ID)
		}
		if !r.OK && r.Fix == "" {
			t.Errorf("%s: failed without a fix", r.ID)
		}
		if r.OK && r.Fix != "" {
			t.Errorf("%s: ok with a fix", r.ID)
		}
	}
}

func TestProbeCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if rs := Probe(ctx, os.Getuid()); len(rs) != 0 {
		t.Fatalf("cancelled probe ran %d checks", len(rs))
	}
}

func TestWriteResults(t *testing.T) {
	var buf bytes.Buffer
	err := WriteResults(&buf, []Result{
		{ID: CheckKernel, OK: true, Detail: "6.17.0 (>= 5.14.0)"},
		{ID: CheckLandlock, Detail: "ENOSYS", Fix: "boot a newer kernel"},
		// A probe that could not run is not a machine that cannot do the thing: it prints skip, and
		// still carries its fix, because the fix is how the operator turns the unknown into an answer.
		{ID: CheckPrograms, Skipped: true, Detail: "requires root to test", Fix: "sudo tego machine check"},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := "ok   kernel: 6.17.0 (>= 5.14.0)\n" +
		"FAIL landlock: ENOSYS; fix: boot a newer kernel\n" +
		"skip programs: requires root to test; fix: sudo tego machine check\n"
	if buf.String() != want {
		t.Fatalf("got %q want %q", buf.String(), want)
	}
	if !strings.HasPrefix(buf.String(), "ok   kernel") {
		t.Fatal("state column misaligned")
	}
}

// TestSudoFixNamesThisBinary: the fix lines said `sudo tego doctor`, and sudo's secure_path on Ubuntu leaves out
// $HOME/.local/bin, where the install script puts tego, so the line answered "command not found". Every root-only
// probe's fix names this binary by its absolute path.
func TestSudoFixNamesThisBinary(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "tego")
	if err := os.WriteFile(bin, nil, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func(e func() (string, error), n func() (string, string)) func() {
		return func() { executable, namedSelf = e, n }
	}(executable, namedSelf))
	// The real checks may refuse a test binary beneath a shared, writable build directory.
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	executable = func() (string, error) { return self, nil }
	want := "sudo " + shellword.Quote(mustResolve(t, self)) + " machine check"
	word, why := selfbin.Named(executable)
	if why == "" {
		if got := sudoDoctor(); got != "sudo "+word+" machine check" {
			t.Fatalf("sudoDoctor() = %q, want %q", got, "sudo "+word+" machine check")
		}
	} else {
		if word != "" || why != selfbin.Untrusted {
			t.Fatalf("Named(test binary) = %q, %q", word, why)
		}
		if got := sudoDoctor(); got != "run this tego as root with sudo ("+strings.TrimSuffix(why, ".")+")" {
			t.Fatalf("sudoDoctor() = %q: want no command and %q", got, why)
		}
	}
	// Probe rendering has its own trusted fixture, so build-directory permissions cannot hide its command branch.
	namedSelf = func() (string, string) { return shellword.Quote(mustResolve(t, self)), "" }
	fan, _ := probeFanotify(false, Version{6, 17, 0})
	progs, _ := probeHooks(false, os.Getuid(), Version{6, 17, 0}, nil, nil)
	for _, r := range []Result{fan, progs} {
		if r.Fix != "re-run as root: "+want {
			t.Errorf("%s fix %q, want it to name %s", r.ID, r.Fix, self)
		}
	}
	if got := state(func(st *probeState) { st.root = false }).fix(backend.TierLandlock); !strings.HasSuffix(got, want) {
		t.Errorf("tier fix %q does not end in %q", got, want)
	}
	// A path the shell would split is one quoted word.
	namedSelf = func() (string, string) { return "'/opt/my tools/tego'", "" }
	if got := sudoDoctor(); got != "sudo '/opt/my tools/tego' machine check" {
		t.Errorf("sudoDoctor() = %q", got)
	}
	// Every way the binary cannot be named gives no command, and never a lookup in the reader's PATH or a path that was
	// not checked (an earlier version printed sudo "$(command -v tego)" and an unresolved path).
	namedSelf = func() (string, string) { return selfbin.Named(executable) }
	unlinked := filepath.Join(dir, "gone")
	for name, exe := range map[string]func() (string, error){
		"unreadable":  func() (string, error) { return "", os.ErrNotExist },
		"missing":     func() (string, error) { return unlinked, nil },
		"not a file":  func() (string, error) { return dir, nil },
		"not running": func() (string, error) { return bin, nil }, // a real file, but not the running binary
		"unsafe":      func() (string, error) { return filepath.Join(dir, "x\n  sudo -i\ntego"), nil },
	} {
		executable = exe
		if name == "unsafe" {
			if err := os.WriteFile(filepath.Join(dir, "x\n  sudo -i\ntego"), nil, 0o755); err != nil {
				t.Fatal(err)
			}
		}
		got := sudoDoctor()
		if strings.Contains(got, "command -v") || strings.Contains(got, "sudo tego") || strings.Contains(got, "sudo /") ||
			strings.Contains(got, "sudo '") || !strings.HasPrefix(got, "run this tego as root with sudo (") {
			t.Errorf("%s: sudoDoctor() = %q: want no command", name, got)
		}
	}
}

func mustResolve(t *testing.T, p string) string {
	t.Helper()
	r, err := filepath.EvalSymlinks(p)
	if err != nil {
		t.Fatal(err)
	}
	return r
}
