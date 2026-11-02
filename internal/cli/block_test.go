// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/liveblock"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// TestBlockLifecycle: against a run whose lock a stand-in launcher holds, block adds a live block (By "cli"), a second
// block of the same thing is "already blocked", --list shows it in both forms, unblock removes it, and a second
// unblock says it was not blocked. Each leaves the overlay a launcher reads.
func TestBlockLifecycle(t *testing.T) {
	dir, id, _ := liveRun(t)

	code, out, errs := run(t, "block", id, "exec", "curl")
	if code != identity.ExitOK || !strings.Contains(out, id+": blocked live.block[exec:curl]") {
		t.Fatalf("block: exit %d stdout %q stderr %q", code, out, errs)
	}
	o, err := liveblock.Read(dir, id)
	if err != nil || len(o.Blocks) != 1 || o.Blocks[0].Key() != "exec:curl" || !strings.HasSuffix(o.Blocks[0].By, " cli") {
		t.Fatalf("overlay %+v, %v: want one exec:curl block added by the cli", o, err)
	}
	if code, out, _ := run(t, "block", id, "exec", "curl"); code != identity.ExitOK || !strings.Contains(out, "already blocked") {
		t.Errorf("a second block: exit %d stdout %q, want 0 and \"already blocked\"", code, out)
	}
	if code, _, _ := run(t, "block", id, "net", "Example.com:443"); code != identity.ExitOK {
		t.Fatalf("block net: exit %d", code)
	}
	if code, _, _ := run(t, "block", id, "path", "/srv/data/../secret/"); code != identity.ExitOK {
		t.Fatalf("block path: exit %d", code)
	}

	code, out, errs = run(t, "block", "--list", id)
	if code != identity.ExitOK || errs != "" || !strings.Contains(out, "3 live block(s)") ||
		!strings.Contains(out, "exec  curl") || !strings.Contains(out, "net   example.com:443") ||
		!strings.Contains(out, "path  /srv/secret") {
		t.Fatalf("list: exit %d stdout %q stderr %q", code, out, errs)
	}
	code, out, _ = run(t, "block", id, "--list", "--json")
	var got struct {
		V       int  `json:"v"`
		Running bool `json:"running"`
		Blocks  []struct{ Kind, Value, Rule, By string }
	}
	if err := json.Unmarshal([]byte(out), &got); code != identity.ExitOK || err != nil {
		t.Fatalf("list --json: exit %d %q: %v", code, out, err)
	}
	if got.V != 1 || !got.Running || len(got.Blocks) != 3 || got.Blocks[0].Rule != "live.block[exec:curl]" {
		t.Errorf("list --json %+v", got)
	}

	if code, out, _ := run(t, "unblock", id, "exec", "curl"); code != identity.ExitOK || !strings.Contains(out, "block removed") {
		t.Errorf("unblock: exit %d stdout %q", code, out)
	}
	if code, out, _ := run(t, "unblock", id, "exec", "curl"); code != identity.ExitOK || !strings.Contains(out, "was not blocked") {
		t.Errorf("a second unblock: exit %d stdout %q", code, out)
	}
	o, err = liveblock.Read(dir, id)
	if err != nil || len(o.Blocks) != 2 {
		t.Errorf("overlay %+v, %v: want the two blocks left", o, err)
	}
}

// TestBlockRefusesAnEndedRun: nothing enforces a live block of a run that has ended, so block and unblock exit 1 and
// write no overlay; --list still shows what the run had, and says it ended.
func TestBlockRefusesAnEndedRun(t *testing.T) {
	root := gcRoot(t)
	id := endedRun(t, root, time.Now())
	for _, args := range [][]string{{"block", id, "exec", "curl"}, {"unblock", id, "exec", "curl"}} {
		code, out, errs := run(t, args...)
		if code != identity.ExitFinding || out != "" || !strings.Contains(errs, "is not running") || !strings.Contains(errs, "[not-running]") {
			t.Errorf("%v: exit %d stdout %q stderr %q, want 1 and [not-running]", args, code, out, errs)
		}
	}
	if _, err := os.Lstat(filepath.Join(root, id, liveblock.FileName)); !os.IsNotExist(err) {
		t.Errorf("an overlay was written for an ended run: %v", err)
	}
	if code, out, _ := run(t, "block", "--list", id); code != identity.ExitOK || !strings.Contains(out, "no live blocks") {
		t.Errorf("list of an ended run with none: exit %d stdout %q", code, out)
	}
	// An overlay left from while it ran is listed, and said to be no longer enforced.
	if _, err := liveblock.Update(t.Context(), filepath.Join(root, id), id, func(o *liveblock.Overlay) (bool, error) {
		_, ok, err := o.Add(liveblock.KindExec, "curl", liveblock.By("cli"), time.Now())
		return ok, err
	}); err != nil {
		t.Fatal(err)
	}
	code, out, _ := run(t, "block", "--list", id)
	if code != identity.ExitOK || !strings.Contains(out, "no longer enforced") || !strings.Contains(out, "curl") {
		t.Errorf("list of an ended run: exit %d stdout %q", code, out)
	}
	if code, out, _ := run(t, "block", "--list", "--json", id); code != identity.ExitOK || !strings.Contains(out, `"running":false`) {
		t.Errorf("list --json of an ended run: exit %d stdout %q", code, out)
	}
}

// TestBlockRefusalsAreLiveblocks: the lines `tego block` and `tego unblock` refuse an ended run with are liveblock's
// refusals (CheckBlock, RunWords), the ones runact gives the dashboard's Block now and Remove, with the terminal's
// hint after them; neither writes the overlay.
func TestBlockRefusalsAreLiveblocks(t *testing.T) {
	root := gcRoot(t)
	id := endedRun(t, root, time.Now())
	for _, tc := range []struct {
		args []string
		add  bool
		hint string
	}{
		{[]string{"block", id, "exec", "curl"}, true, "; for its next run, make it a rule of the contract (tego rule)"},
		{[]string{"unblock", id, "exec", "curl"}, false, " (tego block --list " + id + " shows what it had)"},
	} {
		refused := liveblock.CheckBlock(liveblock.Target{Run: id}, liveblock.KindExec, tc.add, time.Time{})
		want := "tego " + tc.args[0] + ": " + liveblock.RunWords(refused) + tc.hint + " [not-running]\n"
		if code, out, errs := run(t, tc.args...); code != identity.ExitFinding || out != "" || errs != want {
			t.Errorf("%v: exit %d stdout %q stderr %q, want 1 and %q", tc.args, code, out, errs, want)
		}
	}
	if _, err := os.Lstat(filepath.Join(root, id, liveblock.FileName)); !os.IsNotExist(err) {
		t.Errorf("an overlay was written for an ended run: %v", err)
	}
}

// TestBlockUsageErrors: arguments that are not a run, a kind and a value are usage errors, exit 2, before any run is
// touched.
func TestBlockUsageErrors(t *testing.T) {
	root := gcRoot(t)
	id := endedRun(t, root, time.Now())
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"no arguments", []string{"block"}, "exactly <run> <exec|net|path|read|write> <value>"},
		{"two arguments", []string{"block", id, "exec"}, "exactly <run>"},
		{"unblock with two", []string{"unblock", id, "exec"}, "tego unblock: exactly"},
		{"unknown kind", []string{"block", id, "file", "/x"}, `kind "file" is not exec, net, path, read or write`},
		{"relative program", []string{"block", id, "exec", "x/y"}, "neither an absolute path nor a bare program name"},
		{"empty value", []string{"block", id, "net", " "}, "[usage]"},
		{"malformed run", []string{"block", "r-1", "exec", "curl"}, "[usage]"},
		{"unknown run", []string{"block", "r-00000000000000-0000000000000000", "exec", "curl"}, "[usage]"},
		{"list without a run", []string{"block", "--list"}, "--list takes exactly one run id"},
		{"list with a block", []string{"block", "--list", id, "exec", "curl"}, "--list takes exactly one run id"},
		{"json without list", []string{"block", id, "exec", "curl", "--json"}, "--json goes with --list"},
		{"list of a malformed run", []string{"block", "--list", "r-1"}, "[usage]"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, out, errs := run(t, tc.args...)
			if code != identity.ExitUsage || out != "" || !strings.Contains(errs, tc.want) {
				t.Errorf("exit %d stdout %q stderr %q, want 2 and %q", code, out, errs, tc.want)
			}
		})
	}
}

// TestBlockUsageGolden pins the two commands' usage text, which `tego help` summarizes and `-h` prints.
func TestBlockUsageGolden(t *testing.T) {
	var got strings.Builder
	for _, name := range []string{"block", "unblock"} {
		code, out, errs := run(t, name, "-h")
		if code != identity.ExitOK || out != "" {
			t.Fatalf("%s -h: exit %d stdout %q", name, code, out)
		}
		got.WriteString(errs)
	}
	_, help, _ := run(t, "help")
	for _, l := range strings.Split(help, "\n") {
		if strings.HasPrefix(l, "  block ") || strings.HasPrefix(l, "  unblock ") {
			got.WriteString(l + "\n")
		}
	}
	golden := filepath.Join("testdata", "block-usage.golden")
	if *updateGolden {
		if err := os.WriteFile(golden, []byte(got.String()), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	if got.String() != string(want) {
		t.Errorf("usage drifted from %s (go test -run BlockUsageGolden -update):\ngot:\n%s\nwant:\n%s", golden, got.String(), want)
	}
}
