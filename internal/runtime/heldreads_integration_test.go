// SPDX-License-Identifier: Apache-2.0

//go:build integration

package runtime

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/reason"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// heldReadsSecret is the bytes of every secret the held-reads tests plant: no file the agent writes may hold them.
const heldReadsSecret = "s3cr3t"

// heldReadsScene is one run of TestIntegrationHeldReadsAtLandlock through the real binary at tier landlock: fs.write
// ["./out/"] with fs.reads mode, and, when nested, an out/.env the compile's .env scan finds inside that write entry.
// The agent reads the secret with each tool a person would (cat, python, grep -r, cp, tar, a symlink it makes,
// /proc/self/cwd), reads out/src/a.txt, copies its reason file, then waits while the test, a process outside the run,
// makes out/.env.local, and reads that. Each try leaves <name>.out, <name>.err and <name>.rc under out/res; tries
// names the ones of the secret the machine had the tool for (the KVM guest's userland has no tar), cat, the symlink
// and /proc/self/cwd always among them.
func heldReadsScene(t *testing.T, mode string, nested bool) (s *askReadScene, evs []*record.Event, tries []string) {
	t.Helper()
	bin := tegoBinary(t)
	have := map[string]string{}
	var allow, missing []string
	for _, name := range []string{"sh", "cat", "sleep", "python3", "grep", "cp", "tar", "ln"} {
		p, err := exec.LookPath(name)
		if err != nil {
			if name == "sh" || name == "cat" || name == "sleep" {
				t.Skipf("no %s: %v", name, err)
			}
			missing = append(missing, name)
			continue
		}
		real, err := filepath.EvalSymlinks(p)
		if err != nil {
			t.Fatal(err)
		}
		have[name] = real
		for _, q := range []string{p, real} {
			if !slices.Contains(allow, q) {
				allow = append(allow, q)
			}
		}
	}
	if len(missing) > 0 {
		t.Logf("not on this machine's PATH, so not tried: %v", missing)
	}
	reads := ""
	if mode != "" {
		reads = "  reads: " + mode + "\n"
	}
	quoted := make([]string, len(allow))
	for i, p := range allow {
		quoted[i] = fmt.Sprintf("%q", p)
	}
	contract := fmt.Sprintf(`version: 0
name: iheldreads
command: ["/bin/sh"]
tier: landlock
fs:
  write: ["./out/"]
%sexec:
  allow: [%s]
env:
  pass: ["PATH", "HOME"]
limits:
  pids: 64
record: summary
`, reads, strings.Join(quoted, ", "))
	project, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s = &askReadScene{bin: bin}
	s.f = newFixtureIn(t, project, contract, nil)
	files := map[string]string{"out/src/a.txt": "benign"}
	if nested {
		files["out/.env"] = "TOKEN=" + heldReadsSecret
	}
	for name, body := range files {
		p := filepath.Join(project, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(s.f.out, "res"), 0o755); err != nil {
		t.Fatal(err)
	}
	// Each try of the secret, by the tool it needs; the symlink is the agent's own where ln is there, else the test's.
	script := "#!/bin/sh\nr=out/res\nt() { n=$1; shift; \"$@\" > $r/$n.out 2> $r/$n.err; echo $? > $r/$n.rc; }\n"
	for _, try := range []struct{ name, tool, line string }{
		{"cat", "cat", "cat out/.env"},
		{"python", "python3", fmt.Sprintf("%q -c 'import sys; sys.stdout.write(open(\"out/.env\").read())'", have["python3"])},
		{"grep", "grep", "grep -r " + heldReadsSecret + " out --exclude-dir=res"},
		{"cp", "cp", "cp out/.env $r/cp.copy"},
		{"tar", "tar", "tar cf $r/t.tar -C out .env src"},
		{"link", "cat", "cat out/link"},
		{"proc", "cat", "cat /proc/self/cwd/out/.env"},
	} {
		if have[try.tool] == "" {
			continue
		}
		if try.name == "link" && have["ln"] != "" {
			script += "ln -s .env out/link\n"
		} else if try.name == "link" {
			if err := os.Symlink(".env", filepath.Join(s.f.out, "link")); err != nil {
				t.Fatal(err)
			}
		}
		script += "t " + try.name + " " + try.line + "\n"
		tries = append(tries, try.name)
	}
	script += `t src cat out/src/a.txt
if [ -n "$TEGO_REASON" ]; then
  i=0
  while [ ! -s "$TEGO_REASON" ] && [ $i -lt 100 ]; do sleep 0.05; i=$((i+1)); done
  cat "$TEGO_REASON" > $r/reason.json 2> $r/reason.err
fi
echo ready > $r/ready
while [ ! -e out/go ]; do sleep 0.05; done
t local cat out/.env.local
echo done > $r/done
`
	if err := os.WriteFile(filepath.Join(project, "agent.sh"), []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	agentOwnsTree(t, s.f.out)
	agentOwns(t, filepath.Join(project, "agent.sh"))
	s.env = isolatedEnv(t, s.f)
	run, dir := s.start(t)
	for deadline := time.Now().Add(30 * time.Second); s.out("res/ready") == ""; time.Sleep(20 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("the agent never reached its wait\n%s", s.diagnose(t, dir))
		}
	}
	// A process outside the run makes a file a deny_read name rule covers, after compile and after the run started.
	local := filepath.Join(s.f.out, ".env.local")
	if err := os.WriteFile(local, []byte("LOCAL="+heldReadsSecret), 0o644); err != nil {
		t.Fatal(err)
	}
	agentOwns(t, local)
	if err := os.WriteFile(filepath.Join(s.f.out, "go"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	evs = s.finish(t, run, dir)
	if s.out("res/done") == "" {
		t.Fatalf("the agent did not run to its end\n%s", s.diagnose(t, dir))
	}
	return s, evs, tries
}

// heldReadsLeak fails the test when a file the agent wrote under out/res holds the secret's bytes.
func heldReadsLeak(t *testing.T, s *askReadScene) {
	t.Helper()
	_ = filepath.WalkDir(filepath.Join(s.f.out, "res"), func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		if b, _ := os.ReadFile(p); bytes.Contains(b, []byte(heldReadsSecret)) {
			t.Errorf("%s holds the secret: %q", strings.TrimPrefix(p, s.f.out+"/"), b)
		}
		return nil
	})
}

// heldReadsStart is the run's run_start payload.
func heldReadsStart(t *testing.T, evs []*record.Event) record.RunStartPayload {
	t.Helper()
	var start record.RunStartPayload
	if len(evs) == 0 || evs[0].Kind != record.KindRunStart {
		t.Fatal("the run has no run_start line")
	}
	if err := evs[0].DecodePayload(&start); err != nil {
		t.Fatal(err)
	}
	if start.RecordMinor < record.MinorHeldReads {
		t.Errorf("run_start.record_minor = %d, want at least %d", start.RecordMinor, record.MinorHeldReads)
	}
	return start
}

// heldReadsRefusals counts the run's refused fs lines under out/ by path, each read-denied with a deny_read rule and
// the rule's authority; any other refused fs line there, and any allowed read line there, fails the test.
func heldReadsRefusals(t *testing.T, evs []*record.Event, out string) map[string]int {
	t.Helper()
	refused := map[string]int{}
	for _, e := range evs {
		var p record.FSPayload
		if e.Kind != record.KindFS || e.DecodePayload(&p) != nil {
			continue
		}
		// Only the project's out/ is the case's: a tool's own refusals elsewhere (the KVM guest's python3 makes
		// __pycache__ beside its library, outside every write entry) are no held read.
		if !strings.HasPrefix(p.Path, out+"/") {
			continue
		}
		if e.Verdict != record.VerdictRefused {
			if p.Op == record.FSOpen && isReadOpen(p.Flags) {
				t.Errorf("record: summary wrote an allowed read line: %s %s", p.Path, e.Rule)
			}
			continue
		}
		if e.Reason != record.ReasonReadDenied || !strings.HasPrefix(e.Rule, "fs.deny_read") || e.Authority != record.AuthorityRule {
			t.Errorf("refused %s: reason %s rule %s authority %s, want read_denied by a deny_read rule", p.Path, e.Reason, e.Rule, e.Authority)
		}
		refused[strings.TrimPrefix(p.Path, out+"/")]++
	}
	return refused
}

// isReadOpen reports whether open flags can read (O_RDONLY, O_RDWR, no O_PATH).
func isReadOpen(flags int) bool {
	return flags&unix.O_PATH == 0 && flags&unix.O_ACCMODE != unix.O_WRONLY
}

// TestIntegrationHeldReadsAtLandlock is ADR 0069 through the real binary at tier landlock. fs.reads: auto with a .env
// inside the write entry holds the run's reads: cat, python, grep -r, cp, tar, a symlink and /proc/self/cwd are each
// refused the secret with read_denied by the deny_read rule, on the object the open deputy reached, while out/src/a.txt
// reads normally with no line under record: summary; a .env.local a process outside the run makes during it is refused
// by the name rule; the reason file names the refusal; run_start says held, nested, and the capability rows hold.
// fs.reads: held does the same for the .env.local with no target nested at compile; fs.reads: direct leaves the nested
// .env readable, as compile warned and run_start records.
func TestIntegrationHeldReadsAtLandlock(t *testing.T) {
	t.Run("auto", func(t *testing.T) {
		s, evs, tries := heldReadsScene(t, "", true)
		for _, n := range append(slices.Clone(tries), "local") {
			if rc := strings.TrimSpace(s.out("res/" + n + ".rc")); rc == "0" || rc == "" {
				t.Errorf("%s: status %q, want a refusal (%q)", n, rc, s.out("res/"+n+".err"))
			}
			if e := s.out("res/" + n + ".err"); !strings.Contains(e, "Permission denied") && !strings.Contains(e, "PermissionError") {
				t.Errorf("%s: error %q, want EACCES", n, e)
			}
		}
		if got := s.out("res/src.out"); got != "benign" {
			t.Errorf("cat out/src/a.txt gave %q (%q), want benign", got, s.out("res/src.err"))
		}
		heldReadsLeak(t, s)
		start := heldReadsStart(t, evs)
		if start.FSReads == nil || start.FSReads.Reads != record.FSReadsHeld || start.FSReads.Why != agent.ReadsWhyNested ||
			!slices.ContainsFunc(start.FSReads.Nested, func(r string) bool { return strings.Contains(r, ".env") }) {
			t.Errorf("run_start.fs_reads = %+v, want held, nested, naming the .env", start.FSReads)
		}
		for c, want := range map[backend.Capability]bool{backend.CapReadDenyNested: true, backend.CapReadDenyCreatedLater: true,
			backend.CapReadDenyMoved: false} {
			if got := start.Capabilities[string(c)]; got != want {
				t.Errorf("capabilities[%s] = %t, want %t", c, got, want)
			}
		}
		refused := heldReadsRefusals(t, evs, s.f.out)
		t.Logf("refused fs lines by path: %v; tar said %q", refused, strings.TrimSpace(s.out("res/tar.err")))
		// One refused open of the secret at least per try of it.
		if refused[".env"] < len(tries) || refused[".env.local"] < 1 {
			t.Errorf("refused fs lines by path %v: want at least %d for .env and 1 for .env.local", refused, len(tries))
		}
		if os.Geteuid() == 0 {
			return // a root launcher makes no runtime directory, so no TEGO_REASON (REASON-CHANNEL §2)
		}
		// The file names the refusal among its recent ones, not necessarily as the latest: a tool's own refusal
		// elsewhere may follow it (tar's passwd lookup connects to nscd's socket, refused host-sockets under ADR
		// 0070's unix-only state for a contract with no net: section), and the mirror is written after the agent
		// already saw EACCES, so the read may come before the later tries' refusals reach it.
		raw := s.out("res/reason.json")
		f, err := reason.Decode(strings.NewReader(raw))
		if err != nil || !slices.ContainsFunc(f.Recent, func(e reason.Entry) bool {
			return e.Reason == record.ReasonReadDenied && strings.HasPrefix(e.Rule, "fs.deny_read") &&
				strings.HasPrefix(e.Target, s.f.out+"/")
		}) {
			t.Errorf("the reason file read inside the run: %q (%q, %v), want a read_denied refusal of out/ by the deny_read rule among its recent ones",
				raw, s.out("res/reason.err"), err)
			for _, e := range evs {
				if e.Kind == record.KindFS && e.Verdict == record.VerdictRefused {
					t.Logf("refused line: rule %s reason %s authority %s: %s", e.Rule, e.Reason, e.Authority, e.Payload)
				}
			}
		}
	})
	t.Run("held", func(t *testing.T) {
		s, evs, _ := heldReadsScene(t, "held", false)
		if rc := strings.TrimSpace(s.out("res/local.rc")); rc == "0" || !strings.Contains(s.out("res/local.err"), "Permission denied") {
			t.Errorf("cat out/.env.local: status %q, error %q, want EACCES", rc, s.out("res/local.err"))
		}
		if got := s.out("res/src.out"); got != "benign" {
			t.Errorf("cat out/src/a.txt gave %q, want benign", got)
		}
		heldReadsLeak(t, s)
		start := heldReadsStart(t, evs)
		if start.FSReads == nil || start.FSReads.Reads != record.FSReadsHeld || start.FSReads.Why != agent.ReadsWhyContract {
			t.Errorf("run_start.fs_reads = %+v, want held by the contract", start.FSReads)
		}
		if refused := heldReadsRefusals(t, evs, s.f.out); refused[".env.local"] < 1 {
			t.Errorf("refused fs lines by path %v: want the .env.local's", refused)
		}
	})
	t.Run("direct", func(t *testing.T) {
		s, evs, _ := heldReadsScene(t, "direct", true)
		// The nested target stays unenforced at tier landlock, as compile warned: the residual fs.reads: direct chooses.
		if got := s.out("res/cat.out"); got != "TOKEN="+heldReadsSecret {
			t.Errorf("cat out/.env under fs.reads: direct gave %q (%q); want the file, which the ruleset leaves readable", got, s.out("res/cat.err"))
		}
		start := heldReadsStart(t, evs)
		if start.FSReads == nil || start.FSReads.Reads != record.FSReadsDirect || start.FSReads.Why != agent.ReadsWhyDirect ||
			len(start.FSReads.Nested) == 0 {
			t.Errorf("run_start.fs_reads = %+v, want direct by the contract, naming the nested .env", start.FSReads)
		}
		if start.Capabilities[string(backend.CapReadDenyNested)] || start.Capabilities[string(backend.CapReadDenyCreatedLater)] {
			t.Errorf("capabilities: nested %t, created_later %t under fs.reads: direct, want both false",
				start.Capabilities[string(backend.CapReadDenyNested)], start.Capabilities[string(backend.CapReadDenyCreatedLater)])
		}
	})
}
