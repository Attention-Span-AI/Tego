// SPDX-License-Identifier: Apache-2.0

//go:build integration

package runtime

import (
	"debug/elf"
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// programInterp is the PT_INTERP an ELF names: the dynamic loader the kernel maps for it.
func programInterp(t *testing.T, p string) string {
	t.Helper()
	f, err := elf.Open(p)
	if err != nil {
		t.Skipf("%s: %v", p, err)
	}
	defer f.Close()
	for _, ph := range f.Progs {
		if ph.Type != elf.PT_INTERP {
			continue
		}
		b := make([]byte, ph.Filesz)
		if _, err := ph.ReadAt(b, 0); err != nil {
			t.Fatal(err)
		}
		return strings.TrimRight(string(b), "\x00")
	}
	t.Skipf("%s names no loader", p)
	return ""
}

// staticPIE is the smallest static-pie program the kernel runs: an ELF64 of type ET_DYN with one PT_LOAD and no
// PT_INTERP, whose code is exit(0). It has the shape of a dynamic loader, of a shared library and of any static-pie
// build (Rust's musl release builds, gcc -static-pie, Ubuntu's ldconfig.real).
func staticPIE(t *testing.T) []byte {
	t.Helper()
	var machine uint16
	var code []byte
	switch runtime.GOARCH {
	case "amd64":
		machine, code = uint16(elf.EM_X86_64), []byte{0xb8, 0x3c, 0, 0, 0, 0x31, 0xff, 0x0f, 0x05} // mov $60,%eax; xor %edi,%edi; syscall
	case "arm64":
		machine = uint16(elf.EM_AARCH64)
		for _, w := range []uint32{0xd2800000, 0xd2800ba8, 0xd4000001} { // mov x0,#0; mov x8,#93; svc #0
			code = binary.LittleEndian.AppendUint32(code, w)
		}
	default:
		t.Skipf("no static-pie fixture for %s", runtime.GOARCH)
	}
	const ehsize, phsize = 64, 56
	size := uint64(ehsize + phsize + len(code))
	b := make([]byte, ehsize+phsize, size)
	copy(b, "\x7fELF")
	b[4], b[5], b[6] = 2, 1, 1 // ELFCLASS64, little-endian, EV_CURRENT
	le := binary.LittleEndian
	le.PutUint16(b[16:], uint16(elf.ET_DYN))
	le.PutUint16(b[18:], machine)
	le.PutUint32(b[20:], 1)
	le.PutUint64(b[24:], ehsize+phsize) // e_entry
	le.PutUint64(b[32:], ehsize)        // e_phoff
	le.PutUint16(b[52:], ehsize)
	le.PutUint16(b[54:], phsize)
	le.PutUint16(b[56:], 1)
	ph := b[ehsize:]
	le.PutUint32(ph[0:], uint32(elf.PT_LOAD))
	le.PutUint32(ph[4:], uint32(elf.PF_R|elf.PF_X))
	le.PutUint64(ph[32:], size)   // p_filesz
	le.PutUint64(ph[40:], size)   // p_memsz
	le.PutUint64(ph[48:], 0x1000) // p_align
	return append(b, code...)
}

// TestIntegrationExecRuleLoader: a dynamic loader run as a command runs its program in-process, with no execve of
// the program's own (ADR 0048 (3)), and only a loader is read that way.
// Under deny: [rm -r, git push], `<loader> <rm> -rf out/tree` is refused at its execve (126) via loader and the tree
// survives. A static-pie program has a loader's ELF shape, and its words are its own: `./out/sp git push` and
// `./out/sp <rm> -rf out/tree2` run (exit 0) and are allowed unmatched, where before the fourth round's fix the
// supervisor read them as a loader's and refused them as git push and rm -r.
func TestIntegrationExecRuleLoader(t *testing.T) {
	rm, err := exec.LookPath("rm")
	if err != nil {
		t.Skip("no rm")
	}
	if rm, err = filepath.EvalSymlinks(rm); err != nil {
		t.Fatal(err)
	}
	ld := programInterp(t, rm)
	f := newFixture(t, execRulesContract("xloader", "/bin/sh", "  deny: [rm -r, git push]"))
	for _, d := range []string{"tree/sub", "tree2/sub"} {
		if err := os.MkdirAll(filepath.Join(f.out, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	sp := filepath.Join(f.out, "sp")
	if err := os.WriteFile(sp, staticPIE(t), 0o755); err != nil {
		t.Fatal(err)
	}
	agentOwns(t, sp)
	runScript(t, f, ld+" "+rm+` -rf out/tree >>out/log 2>&1; echo "ld $?" >> out/st
./out/sp git push >>out/log 2>&1; echo "sp $?" >> out/st
./out/sp `+rm+` -rf out/tree2 >>out/log 2>&1; echo "sprm $?" >> out/st`)
	st := statuses(t, f)
	for c, want := range map[string]int{"ld": 126, "sp": 0, "sprm": 0} {
		if st[c] != want {
			t.Errorf("%s: exit %d, want %d\n%s", c, st[c], want, logOf(f))
		}
	}
	for _, d := range []string{"tree", "tree2"} {
		if _, err := os.Stat(filepath.Join(f.out, d, "sub")); err != nil {
			t.Errorf("out/%s/sub is gone", d)
		}
	}
	lines := map[string]string{}
	for _, l := range execLines(t, f.root) {
		if len(l.argv) > 1 {
			lines[l.argv[0]+" "+l.argv[1]] = string(l.verdict) + " " + l.rule + " " + l.commandVia
		}
	}
	for k, want := range map[string]string{
		ld + " " + rm:    "refused exec.deny[rm -r] loader",
		"./out/sp git":   "allow unmatched ",
		"./out/sp " + rm: "allow unmatched ",
	} {
		if got := lines[k]; got != want {
			t.Errorf("%s line: %q, want %q", k, got, want)
		}
	}
}

// TestIntegrationExecRuleStaticPieRestricted re-checks the fourth round's static-pie fix (a406e838) where the images
// are restricted (`exec.allow` grants ./out/ and constrains git to git status): a granted static-pie program is a
// loader to no reading, so with a ruled tool's name, a ruled tool's
// path or a path no entry grants as its first word it runs (exit 0) on its own grant, never refused
// loader-program-unmatched or as the tool, and a #! script whose interpreter it is runs too. The loader itself, which
// no entry grants, is refused (126) as before.
func TestIntegrationExecRuleStaticPieRestricted(t *testing.T) {
	git := needGit(t)
	rm, err := exec.LookPath("rm")
	if err != nil {
		t.Skip("no rm")
	}
	if rm, err = filepath.EvalSymlinks(rm); err != nil {
		t.Fatal(err)
	}
	ld := programInterp(t, rm)
	f := newFixture(t, execRulesContract("xpie", "/bin/sh", `  allow: ["/bin/sh", "/usr/bin/sh", "./out/", "git status"]`))
	if err := os.MkdirAll(filepath.Join(f.out, "tree", "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	sp := filepath.Join(f.out, "sp")
	if err := os.WriteFile(sp, staticPIE(t), 0o755); err != nil {
		t.Fatal(err)
	}
	s := filepath.Join(f.out, "s")
	if err := os.WriteFile(s, []byte("#!"+sp+" git\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	agentOwns(t, sp, s)
	runScript(t, f, `./out/sp git push >>out/log 2>&1; echo "word $?" >> out/st
./out/sp `+git+` push >>out/log 2>&1; echo "gitpath $?" >> out/st
./out/sp `+rm+` -rf out/tree >>out/log 2>&1; echo "rmpath $?" >> out/st
./out/s push >>out/log 2>&1; echo "script $?" >> out/st
`+ld+` `+rm+` -rf out/tree >>out/log 2>&1; echo "ld $?" >> out/st`)
	st := statuses(t, f)
	for c, want := range map[string]int{"word": 0, "gitpath": 0, "rmpath": 0, "script": 0, "ld": 126} {
		if st[c] != want {
			t.Errorf("%s: exit %d, want %d\n%s", c, st[c], want, logOf(f))
		}
	}
	if _, err := os.Stat(filepath.Join(f.out, "tree", "sub")); err != nil {
		t.Errorf("out/tree/sub is gone")
	}
	for _, l := range execLines(t, f.root) {
		if len(l.argv) > 0 && (l.argv[0] == "./out/sp" || l.argv[0] == "./out/s") && (l.verdict != record.VerdictAllow || l.commandVia == "loader") {
			t.Errorf("%v: %s %s via %q, want allowed on its own grant", l.argv, l.verdict, l.rule, l.commandVia)
		}
	}
}

// TestIntegrationExecRuleDispatchDepth: a multicall binary that re-dispatches to itself (busybox has a `busybox`
// applet) must not let a denied applet slip past the matcher's dispatch-depth bound (2026-10-06).
// Under deny: [rm -r], `busybox rm -r out/tree` is refused via multicall, and so is `busybox`x5 + `rm -r out/deep`,
// which before the fix was allowed unmatched and deleted the tree in-process (one execve of busybox, no execve of
// rm); the exec is refused command-unresolved (fail closed). A nested busybox that runs a non-denied applet
// (`busybox rm -f out/file`) still runs.
func TestIntegrationExecRuleDispatchDepth(t *testing.T) {
	bb, err := exec.LookPath("busybox")
	if err != nil {
		// The KVM guest's root carries a static busybox off PATH (test/vm/kvm-run.sh); without it the root suites
		// skipped this test, unlisted.
		const guest = "/usr/lib/tego-vm/busybox"
		if _, serr := os.Stat(guest); serr != nil {
			t.Skip("no busybox")
		}
		bb = guest
	}
	f := newFixture(t, execRulesContract("xbbdepth", "/bin/sh", "  deny: [rm -r]"))
	for _, d := range []string{"tree/sub", "deep/sub"} {
		if err := os.MkdirAll(filepath.Join(f.out, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(f.out, "file"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	nest := bb + " " + bb + " " + bb + " " + bb + " " + bb // 5 leading busybox words, then rm -r
	runScript(t, f, bb+` rm -r out/tree >>out/log 2>&1; echo "bb1 $?" >> out/st
`+nest+` rm -r out/deep >>out/log 2>&1; echo "bb5 $?" >> out/st
`+bb+` rm -f out/file >>out/log 2>&1; echo "bbf $?" >> out/st`)
	st := statuses(t, f)
	for c, want := range map[string]int{"bb1": 126, "bb5": 126, "bbf": 0} {
		if st[c] != want {
			t.Errorf("%s: exit %d, want %d\n%s", c, st[c], want, logOf(f))
		}
	}
	for _, d := range []string{"tree", "deep"} {
		if _, err := os.Stat(filepath.Join(f.out, d, "sub")); err != nil {
			t.Errorf("out/%s/sub is gone: a denied applet ran", d)
		}
	}
	if _, err := os.Stat(filepath.Join(f.out, "file")); err == nil {
		t.Error("out/file survived: the non-denied busybox rm -f did not run")
	}
	// The shallow dispatch names the entry; the nested one fails closed under command-unresolved, via overflow.
	var shallow, nested string
	for _, l := range execLines(t, f.root) {
		if len(l.argv) < 2 || filepath.Base(l.argv[0]) != "busybox" {
			continue
		}
		verdict := string(l.verdict) + " " + l.rule + " " + l.commandVia
		switch l.argv[1] {
		case "rm": // busybox rm -r / busybox rm -f
			if l.rule == "exec.deny[rm -r]" {
				shallow = verdict
			}
		case bb: // busybox busybox ... (the nested one)
			nested = verdict
		}
	}
	if shallow != "refused exec.deny[rm -r] multicall" {
		t.Errorf("busybox rm -r line: %q, want refused exec.deny[rm -r] multicall", shallow)
	}
	if nested != "refused command-unresolved overflow" {
		t.Errorf("nested busybox line: %q, want refused command-unresolved overflow", nested)
	}
}

// TestIntegrationAnObserveRunFlagsWhatAWouldBeRefusalLoads is the dropped flag end to end at tier landlock. In an observe run
// with command rules whose exec.allow grants neither the loader nor the script,
// `<loader> ./out/tool` and `./out/s`, whose #! names ./out/interp, are the image floor's would-be refusals, and they
// run (exit 0). tool and interp are copies of true that the agent makes during the run under its ./out/ write entry,
// while the loader and the script are older. Both lines are observed and carry dropped, judged on the program the
// loader maps and on the interpreter the kernel loads. Before the fix neither was walked: the walk was inside the
// command decision, which the floor's allow alone reached.
func TestIntegrationAnObserveRunFlagsWhatAWouldBeRefusalLoads(t *testing.T) {
	tru, err := exec.LookPath("true")
	if err != nil {
		t.Skip("no true")
	}
	if tru, err = filepath.EvalSymlinks(tru); err != nil {
		t.Fatal(err)
	}
	ld := programInterp(t, tru)
	f := newFixture(t, execRulesContract("xobsdrop", "/bin/sh", `  allow: ["/bin/sh"]
  deny: ["rm -r"]`))
	s := filepath.Join(f.out, "s")
	if err := os.WriteFile(s, []byte("#!"+filepath.Join(f.out, "interp")+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	agentOwns(t, s)
	run := exec.Command(tegoBinary(t), "run", "--observe", filepath.Join(f.dir, "agent.yaml"), "--", "/bin/sh", "-c",
		"cp "+tru+" out/tool; cp "+tru+` out/interp
`+ld+` ./out/tool; echo "ld $?" >> out/st
./out/s; echo "s $?" >> out/st`)
	run.Dir = f.dir
	run.Env = isolatedEnv(t, f)
	if out, err := run.CombinedOutput(); err != nil {
		t.Fatalf("tego run --observe: %v\n%s", err, out)
	}
	st := statuses(t, f)
	for _, c := range []string{"ld", "s"} {
		if st[c] != 0 {
			t.Errorf("%s: exit %d, want 0: an observe run refuses nothing\n%s", c, st[c], logOf(f))
		}
	}
	got := map[string]string{}
	for _, e := range runDirs(t, f.root) {
		for _, ev := range events(t, e) {
			if ev.Kind != record.KindExec {
				continue
			}
			var p struct {
				Argv    []string `json:"argv"`
				Dropped bool     `json:"dropped"`
			}
			if err := ev.DecodePayload(&p); err != nil {
				t.Fatal(err)
			}
			if len(p.Argv) > 0 && (p.Argv[0] == ld || p.Argv[0] == "./out/s") {
				got[p.Argv[0]] = string(ev.Verdict) + " " + ev.Rule + " dropped=" + map[bool]string{false: "false", true: "true"}[p.Dropped]
			}
		}
	}
	for _, c := range []string{ld, "./out/s"} {
		if want := "observed unmatched dropped=true"; got[c] != want {
			t.Errorf("%s line: %q, want %q: the file it loads is a binary the run wrote", c, got[c], want)
		}
	}
}
