// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// rewriteStart replaces old with new in the run's run_start line (the first), standing in for a run started another
// way; the block commands read run_start and never verify the chain.
func rewriteStart(t *testing.T, dir, old, new string) {
	t.Helper()
	p := filepath.Join(dir, ledger.EventsFile)
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	if !strings.Contains(s, old) {
		t.Fatalf("run_start lacks %q", old)
	}
	if err := os.WriteFile(p, []byte(strings.Replace(s, old, new, 1)), 0o600); err != nil {
		t.Fatal(err)
	}
}

// appendGap appends the launcher's line confirming a live block's serial.
func appendGap(t *testing.T, dir, run string, seq int, kind, value string, serial int) {
	t.Helper()
	l := fmt.Sprintf(`{"v":1,"seq":%d,"id":"%064x","prev":"%064x","ts":"%s","mono_ns":%d,"run":"%s","agent":"tester","pid":10,"tid":10,"cgroup":1,"kind":"gap","source":"launcher",`+
		`"what":"enforce","why":"live-block-added","live_block":{"op":"add","kind":"%s","value":"%s","rule":"live.block[%s:%s]","by":"uid:1000 pid:9 cli","serial":%d,"at":"2026-10-27T12:00:00Z"}}`+"\n",
		seq, seq+1, seq, time.Now().UTC().Format(time.RFC3339Nano), seq+1, run, kind, value, kind, value, serial)
	f, err := os.OpenFile(filepath.Join(dir, ledger.EventsFile), os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if _, err := f.WriteString(l); err != nil {
		t.Fatal(err)
	}
}

// TestBlockWatchedRun: a block on a tego watch run is written (the first line keeps its form) and says it is recorded,
// not enforced; --list says the same of it.
func TestBlockWatchedRun(t *testing.T) {
	dir, id, _ := liveRun(t)
	rewriteStart(t, dir, `"tier":"landlock"`, `"tier":"observe"`)
	code, out, errs := run(t, "block", id, "exec", "curl")
	if code != identity.ExitOK || !strings.HasPrefix(out, id+": blocked live.block[exec:curl]\n") ||
		!strings.Contains(out, "recorded, not enforced: run "+id+" is a tego watch run") || strings.Contains(out, "puts it in force") {
		t.Fatalf("block on a watched run: exit %d stdout %q stderr %q", code, out, errs)
	}
	code, out, _ = run(t, "block", "--list", id)
	if code != identity.ExitOK || !strings.Contains(out, "Recorded, not enforced: this run is only watched") {
		t.Errorf("list of a watched run: exit %d stdout %q", code, out)
	}
}

// TestBlockStatesInList: --list says a block waits until the launcher's line confirms its serial, then is in force; a
// path block on a run whose reads are not seen refuses changes only. --json carries the same state.
func TestBlockStatesInList(t *testing.T) {
	dir, id, _ := liveRun(t)
	if code, out, _ := run(t, "block", id, "path", "/srv/data"); code != identity.ExitOK ||
		!strings.Contains(out, "check with: tego block --list "+id) || !strings.Contains(out, "reading it still works") {
		t.Fatalf("block path: exit %d stdout %q", code, out)
	}
	if code, out, _ := run(t, "block", "--list", id); code != identity.ExitOK || !strings.Contains(out, "Waiting for the run to put it in force") {
		t.Fatalf("list before the launcher's line: exit %d stdout %q", code, out)
	}
	appendGap(t, dir, id, 1, "path", "/srv/data", 1)
	if code, out, _ := run(t, "block", "--list", id); code != identity.ExitOK || !strings.Contains(out, "Refuses changes now; reads are not seen in this run") {
		t.Fatalf("list after the launcher's line: exit %d stdout %q", code, out)
	}
	code, out, _ := run(t, "block", "--list", "--json", id)
	var got struct {
		Blocks []struct{ State, Sentence string }
	}
	if err := json.Unmarshal([]byte(out), &got); code != identity.ExitOK || err != nil || len(got.Blocks) != 1 || got.Blocks[0].State != "partial" {
		t.Fatalf("list --json: exit %d %q: %v", code, out, err)
	}
}

// TestBlockHeldReadsInForce: on a run that holds its reads a confirmed path block is in force, reads included.
func TestBlockHeldReadsInForce(t *testing.T) {
	dir, id, _ := liveRun(t)
	rewriteStart(t, dir, `"tier":"landlock"`, `"tier":"landlock","fs_reads":{"reads":"held","why":"contract"}`)
	if code, out, _ := run(t, "block", id, "path", "/srv/data"); code != identity.ExitOK || strings.Contains(out, "reading it still works") {
		t.Fatalf("block path on a held-reads run: exit %d stdout %q", code, out)
	}
	appendGap(t, dir, id, 1, "path", "/srv/data", 1)
	if code, out, _ := run(t, "block", "--list", id); code != identity.ExitOK || !strings.Contains(out, "In force: tego refuses it until the run ends") {
		t.Fatalf("list: exit %d stdout %q", code, out)
	}
}

// TestBlockRelativePath: a relative path is read against the working directory and said as the absolute path.
func TestBlockRelativePath(t *testing.T) {
	_, id, _ := liveRun(t)
	wd := t.TempDir()
	t.Chdir(wd)
	abs := filepath.Join(wd, "secret.txt")
	code, out, errs := run(t, "block", id, "path", "./secret.txt")
	if code != identity.ExitOK || !strings.Contains(out, "live.block[path:"+abs+"]") || !strings.Contains(errs, "path ./secret.txt is "+abs) {
		t.Fatalf("relative path: exit %d stdout %q stderr %q", code, out, errs)
	}
	if code, out, _ := run(t, "unblock", id, "path", "secret.txt"); code != identity.ExitOK || !strings.Contains(out, "block removed live.block[path:"+abs+"]") {
		t.Fatalf("relative unblock: exit %d stdout %q", code, out)
	}
}

// TestAbsPathValueTilde: a ~ the shell left unexpanded (quoted) is the caller's home, not a folder named "~" under the
// working directory, and ~name is refused rather than guessed.
func TestAbsPathValueTilde(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Chdir(t.TempDir())
	for in, want := range map[string]string{"~": home, "~/": home, "~/.aws": filepath.Join(home, ".aws"), " ~/a/b ": filepath.Join(home, "a", "b")} {
		if got, err := absPathValue(in); err != nil || got != want {
			t.Errorf("absPathValue(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	if got, err := absPathValue("~root/.ssh"); err == nil || !strings.Contains(err.Error(), "write the full path") {
		t.Errorf("absPathValue(~root/.ssh) = %q, %v; want a refusal with a hint", got, err)
	}
}

// TestUnblockEndedRunWording: unblock on a run that has ended says its blocks ended with it, not that a block would
// enforce nothing.
func TestUnblockEndedRunWording(t *testing.T) {
	root := gcRoot(t)
	id := endedRun(t, root, time.Now())
	code, out, errs := run(t, "unblock", id, "exec", "curl")
	if code != identity.ExitFinding || out != "" || !strings.Contains(errs, "its live blocks ended with it") ||
		strings.Contains(errs, "would enforce nothing") || !strings.Contains(errs, "[not-running]") {
		t.Fatalf("unblock on an ended run: exit %d stdout %q stderr %q", code, out, errs)
	}
}
