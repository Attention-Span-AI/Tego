// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/runtime/ask"
	"github.com/attention-span-ai/tego/internal/runtime/cgroup"
	"github.com/attention-span-ai/tego/pkg/policy/execmatch"
	"github.com/attention-span-ai/tego/pkg/policy/execmatch/rows"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/harness"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// harnessHookHelperEnv marks an exec of this test binary as a granted harness hook (TestMain's harnessHookHelper).
const harnessHookHelperEnv = "TEGO_T_HOOK"

// harnessHookHelper is this test binary started as a run's harness hook (`<test binary> hook ...` with
// TEGO_T_HOOK=1, the integration tests' provision): it prints its argv after "hook ran:" and exits 0. It returns at
// once when the binary was not started so, and never returns when it was.
func harnessHookHelper() {
	if len(os.Args) < 2 || os.Args[1] != "hook" || os.Getenv(harnessHookHelperEnv) != "1" {
		return
	}
	fmt.Println("hook ran:", strings.Join(os.Args[1:], " "))
	os.Exit(0)
}

// testExe is this test binary, the tego binary a run of the tests provisions a hook for (harness.Run.TegoExe).
func testExe(t *testing.T) string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return exe
}

// TestHarnessHookGrantAtEveryTier is ADR 0064 (acceptance (1), (5)) as compile --test and the supervisor decide it: an
// allow-list contract's hook is granted at every tier, the granted table admits the hook's exact argv, and it refuses
// every other vector of the tego binary under the grant's own rule (tego run, tego approve, __probe, another hook, the
// hook with another reason path, tego alone), whichever floor the tier's column uses.
func TestHarnessHookGrantAtEveryTier(t *testing.T) {
	exe := testExe(t)
	hook := []string{exe, "hook", "claude-code", "--reason", "/run/user/1000/tego/R/last-refusal.json", "--mode", "json"}
	rt := compileTable(t, harnessContract(harness.ClaudeCode, &agent.ExecSection{Allow: []string{"/bin/sh"}}))
	rule := "exec." + agent.HarnessHookGrant + "[" + exe + "]"
	for _, tier := range []backend.Tier{backend.TierLandlock, backend.TierCgroup, backend.TierBPFLSM} {
		d := AdmitHook(rt, tier, exe, &harness.Hook{Argv: hook})
		if !d.Granted || d.Why != "" || d.Table == rt || d.Table.HarnessHookRule() != rule {
			t.Fatalf("%s: %+v, want the grant", tier, d)
		}
		for _, other := range [][]string{{exe, "run", "c.yaml"}, {exe, "approve", "01J0000000000000000000000A", "a1"}, {exe, "__probe"},
			{exe, "hook", "other"}, {exe, "hook", "claude-code", "--reason", "/tmp/x.json", "--mode", "json"}, {exe}} {
			if why, got := hookRuled(d.Table, tier, &harness.Hook{Argv: other}); why != record.HarnessWhyHookRefused || got != rule {
				t.Errorf("%s: %q: %q %q, want refused under %s", tier, other, why, got, rule)
			}
		}
	}
}

// TestHarnessHookWritableIsNotGranted is acceptance (4)'s harness-hook-writable: when the tego binary lies at or below a
// write or ask entry (here, one on the directory that holds it), the agent could rewrite what a grant admits, so the
// launcher grants nothing: the whole provision is dropped, the run carries on with its table unchanged, run_start says
// why with the hook not granted, and the warning names the entry. A write entry elsewhere leaves the grant.
func TestHarnessHookWritableIsNotGranted(t *testing.T) {
	exe := testExe(t)
	dir := filepath.Dir(exe)
	for _, c := range []struct {
		name string
		fs   *agent.FSSection
		rule string
	}{
		{"a write entry over the binary", &agent.FSSection{Write: []string{dir}}, "fs.write[" + dir + "]"},
		{"an ask entry over the binary", &agent.FSSection{Ask: []string{dir}}, "fs.ask[" + dir + "]"},
		{"a write entry elsewhere", &agent.FSSection{Write: []string{t.TempDir()}}, ""},
	} {
		ct := harnessContract(harness.ClaudeCode, &agent.ExecSection{Allow: []string{"/bin/sh"}})
		ct.FS = c.fs
		rt := compileTable(t, ct)
		var warned []string
		r := harnessRunner(t, rt, []string{"/bin/sh"}, &fakeProvisioner{fn: claudeLike})
		r.deps.Warn = func(code, what string) { warned = append(warned, code+": "+what) }
		if err := r.provisionHarness(); err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		s := r.harness.start
		if c.rule == "" {
			if !s.Provisioned || s.Hook == nil || !s.Hook.Granted || r.rt == rt {
				t.Errorf("%s: run_start.harness %+v, want the hook granted", c.name, s)
			}
			continue
		}
		if s.Provisioned || s.Why != record.HarnessWhyHookWritable || s.Hook == nil || s.Hook.Granted || !sameHarnessPolicy(r.rt, rt) {
			t.Errorf("%s: run_start.harness %+v (hook %+v), want unprovisioned, %s, the table unchanged", c.name, s, s.Hook, record.HarnessWhyHookWritable)
		}
		if len(warned) != 1 || !strings.Contains(warned[0], "rule "+c.rule+":") || !strings.Contains(warned[0], "could rewrite") {
			t.Errorf("%s: warnings %q, want one naming %s", c.name, warned, c.rule)
		}
	}
}

// TestHarnessHookOtherNamesAreNotGranted (ADR 0064 D2): the write and ask entries
// are compared with the names the launcher sees, and a file has others. Landlock's write rights are path-based, so a
// second hard link of the tego binary, or of its loader, under a write entry lets the agent rewrite the inode the
// grant executes, and so does a bind mount of the binary's directory into one. A hard link's other names cannot be
// listed, so a file with more than one link is never granted; a bind mount's names are in the mount table, so each is
// held to the entries like the hook's own. Each drops the provision harness-hook-writable, saying which name.
func TestHarnessHookOtherNamesAreNotGranted(t *testing.T) {
	src, err := filepath.EvalSymlinks("/bin/true")
	if err != nil {
		t.Skip(err)
	}
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	bin, lib, ws := filepath.Join(base, "bin"), filepath.Join(base, "lib"), filepath.Join(base, "ws")
	for _, d := range []string{bin, lib, ws} {
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	exe := filepath.Join(bin, "tego")
	copyFile(t, src, exe)
	hook := func(exe string) *harness.Hook {
		return &harness.Hook{Argv: []string{exe, "hook", "claude-code", "--reason", "/run/r/last-refusal.json"}}
	}
	ct := harnessContract(harness.ClaudeCode, &agent.ExecSection{Allow: []string{"/bin/sh"}})
	ct.FS = &agent.FSSection{Write: []string{ws}}
	rt := compileTable(t, ct)
	block := fakeBlock(t)
	noMounts := onTable(block, rootMount)
	if d := admitHook(rt, backend.TierLandlock, exe, hook(exe), noMounts); !d.Granted {
		t.Fatalf("one name, no bind mount: %+v, want the grant", d)
	}
	writable := hookWritable(t, rt)
	bind := onTable(block, rootMount+"2 1 8:2 "+bin+" "+ws+"/bin rw - ext4 /dev/sda2 rw\n")
	writable("a bind mount of its directory under the write entry", admitHook(rt, backend.TierLandlock, exe, hook(exe), bind),
		"fs.write["+ws+"]", filepath.Join(ws, "bin", "tego"))
	// A table that shows no mount holding the file (a chroot whose root is no mount point skips the mount
	// above it) cannot say where the file lies in its filesystem, so the bind it does show, of the binary's directory
	// into the write entry, is not recognised: the launcher cannot see every name, and does not grant.
	unheld := onTable(block, "2 1 8:2 "+bin+" "+ws+"/bin rw - ext4 /dev/sda2 rw\n")
	writable("a table without the mount holding it", admitHook(rt, backend.TierLandlock, exe, hook(exe), unheld),
		"exec."+agent.HarnessHookGrant, "mount table")
	empty := onTable(block, "")
	writable("an empty mount table", admitHook(rt, backend.TierLandlock, exe, hook(exe), empty),
		"exec."+agent.HarnessHookGrant, "mount table")
	unreadable := hookHost{mounts: func() ([]byte, error) { return nil, os.ErrPermission }, block: block}
	writable("an unreadable mount table", admitHook(rt, backend.TierLandlock, exe, hook(exe), unreadable),
		"exec."+agent.HarnessHookGrant, "mount table")

	if err := os.Link(exe, filepath.Join(ws, "tego-copy")); err != nil {
		t.Fatal(err)
	}
	writable("a hard link under the write entry", admitHook(rt, backend.TierLandlock, exe, hook(exe), noMounts),
		"exec."+agent.HarnessHookGrant, exe+" has 2 links")
	writable("a hard link, the machine's own mount table", AdmitHook(rt, backend.TierLandlock, exe, hook(exe)),
		"exec."+agent.HarnessHookGrant, exe+" has 2 links")

	// The loader: an ELF whose PT_INTERP names a file with a second link under the write entry.
	ld := filepath.Join(lib, "ld.so")
	copyFile(t, src, ld)
	if err := os.Link(ld, filepath.Join(ws, "ld-copy")); err != nil {
		t.Fatal(err)
	}
	dyn := filepath.Join(bin, "tego-dyn")
	if err := os.WriteFile(dyn, elfInterp(ld), 0o755); err != nil {
		t.Fatal(err)
	}
	writable("a loader with a hard link", admitHook(rt, backend.TierLandlock, dyn, hook(dyn), noMounts),
		"exec."+agent.HarnessHookGrant, ld+" has 2 links")
}

func TestHarnessHookRejectsIncompleteMountFacts(t *testing.T) {
	exe := filepath.Join(t.TempDir(), "tego")
	copyFile(t, testExe(t), exe)
	rt := compileTable(t, harnessContract(harness.ClaudeCode, &agent.ExecSection{Allow: []string{"/bin/sh"}}))
	hook := &harness.Hook{Argv: []string{exe, "hook", "claude-code", "--reason", "/run/r/last-refusal.json"}}
	block := fakeBlock(t)
	if d := admitHook(rt, backend.TierLandlock, exe, hook, onTable(block, rootMount)); !d.Granted {
		t.Fatalf("complete facts: %+v, want the grant", d)
	}
	for name, table := range map[string]string{
		"truncated record": rootMount + "3 1 8:2 /secret /alias rw - ext4\n",
		"invalid device":   rootMount + "3 1 disk:one /secret /alias rw - ext4 /dev/sda2 rw\n",
		"duplicate id":     rootMount + "1 1 8:2 /secret /alias rw - ext4 /dev/sda2 rw\n",
	} {
		t.Run(name, func(t *testing.T) {
			d := admitHook(rt, backend.TierLandlock, exe, hook, onTable(block, table))
			if d.Granted || d.Table != rt || d.Why != record.HarnessWhyHookWritable || !strings.Contains(d.Detail, "mount table") {
				t.Fatalf("%+v, want the grant refused because mount facts are incomplete", d)
			}
		})
	}
}

// TestHarnessHookStackedNamesAreNotGranted (ADR 0064 D2): a filesystem can show
// another file's content, which the agent rewrites by that file's own name, and no mount of the binary's device lists
// it. An overlay's layers (its options name them; a layer's place in the table and a bind of part of it count too),
// the backing file of a loop device beneath the filesystem (itself, a partition's disk, or a device-mapper device built
// on it), and an image file the filesystem is mounted from are each held to the write entries, by covering or by lying
// beneath one; a stacking filesystem whose layers no option names (FUSE), an overlay naming a relative layer, and
// block devices sysfs cannot show are names the launcher cannot see. Each drops the provision harness-hook-writable.
func TestHarnessHookStackedNamesAreNotGranted(t *testing.T) {
	src, err := filepath.EvalSymlinks("/bin/true")
	if err != nil {
		t.Skip(err)
	}
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	merged, ws, lower := filepath.Join(base, "merged"), filepath.Join(base, "ws"), filepath.Join(base, "lower")
	for _, d := range []string{filepath.Join(merged, "bin"), ws, filepath.Join(lower, "sub")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	exe := filepath.Join(merged, "bin", "tego")
	copyFile(t, src, exe)
	hook := &harness.Hook{Argv: []string{exe, "hook", "claude-code", "--reason", "/run/r/last-refusal.json"}}
	ct := harnessContract(harness.ClaudeCode, &agent.ExecSection{Allow: []string{"/bin/sh"}})
	ct.FS = &agent.FSSection{Write: []string{ws}}
	rt := compileTable(t, ct)
	block := fakeBlock(t)
	writable := hookWritable(t, rt)
	on := func(row string) hookHost { return onTable(block, rootMount+row+"\n") }
	admit := func(h hookHost) HookDecision { return admitHook(rt, backend.TierLandlock, exe, hook, h) }
	overlay := func(super string) hookHost { return on("3 1 0:50 / " + merged + " rw - overlay overlay rw," + super) }

	if d := admit(overlay("lowerdir=/nonexistent/l,upperdir=/nonexistent/u,workdir=/nonexistent/w")); !d.Granted {
		t.Errorf("an overlay whose layers lie outside every entry: %+v, want the grant", d)
	}
	writable("the reproduction: an overlay whose upper layer lies under the write entry",
		admit(overlay("lowerdir=/l,upperdir="+ws+"/u,workdir="+ws+"/w")), "fs.write["+ws+"]", ws+"/u")
	writable("a lower layer under the write entry (lowerdir+, Linux 6.7 on)",
		admit(overlay("lowerdir+=/l,lowerdir+="+ws+"/l2")), "fs.write["+ws+"]", ws+"/l2")
	writable("a data-only layer under the write entry",
		admit(overlay("lowerdir=/l::"+ws+"/data")), "fs.write["+ws+"]", ws+"/data")
	writable("a layer that holds the write entry", admit(overlay("lowerdir="+base)), "fs.write["+ws+"]", base)
	layerBound := onTable(block, rootMount+"3 1 0:50 / "+merged+" rw - overlay overlay rw,lowerdir="+lower+"\n"+
		"4 1 8:2 "+lower+" "+ws+"/l rw - ext4 /dev/sda2 rw\n")
	writable("a bind of the lower layer into the write entry", admit(layerBound), "fs.write["+ws+"]", ws+"/l")
	partBound := onTable(block, rootMount+"3 1 0:50 / "+merged+" rw - overlay overlay rw,lowerdir="+lower+"\n"+
		"4 1 8:2 "+lower+"/sub "+ws+"/s rw - ext4 /dev/sda2 rw\n")
	writable("a bind of part of the lower layer into the write entry", admit(partBound), "fs.write["+ws+"]", ws+"/s")
	writable("an overlay naming a relative layer", admit(overlay("lowerdir=l1")), "exec."+agent.HarnessHookGrant, "layers named relative to a folder the mount table does not record")
	writable("an overlay naming no lower layer", admit(overlay("xino=off")), "exec."+agent.HarnessHookGrant, "no lower layer")
	writable("a FUSE mirror", admit(on("3 1 0:51 / "+merged+" rw - fuse.bindfs "+ws+" rw,user_id=1000")),
		"exec."+agent.HarnessHookGrant, "fuse.bindfs")

	// A loop device's backing file under the write entry: the filesystem's own device, a partition's disk, and a
	// device-mapper device built on one.
	mkfile := func(p, body string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	mkfile(filepath.Join(block, "7:3", "loop", "backing_file"), ws+"/img.sqfs\n")
	writable("a loop device backed by a file under the write entry",
		admit(on("3 1 7:3 / "+merged+" ro - squashfs /dev/loop3 ro")), "fs.write["+ws+"]", ws+"/img.sqfs")
	mkfile(filepath.Join(block, "devices", "loop5", "loop", "backing_file"), ws+"/disk.img\n")
	mkfile(filepath.Join(block, "devices", "loop5", "loop5p1", "partition"), "1\n")
	if err := os.Symlink(filepath.Join(block, "devices", "loop5", "loop5p1"), filepath.Join(block, "259:9")); err != nil {
		t.Fatal(err)
	}
	writable("a partition of a loop device", admit(on("3 1 259:9 / "+merged+" rw - ext4 /dev/loop5p1 rw")),
		"fs.write["+ws+"]", ws+"/disk.img")
	mkfile(filepath.Join(block, "253:0", "slaves", "loop4", "loop", "backing_file"), ws+"/crypt.img\n")
	writable("a device-mapper device on a loop device", admit(on("3 1 253:0 / "+merged+" rw - ext4 /dev/mapper/c rw")),
		"fs.write["+ws+"]", ws+"/crypt.img")
	mkfile(filepath.Join(block, "7:6", "loop", "backing_file"), "/var/lib/snapd/snaps/tego_1.snap\n")
	if d := admit(on("3 1 7:6 / " + merged + " ro - squashfs /dev/loop6 ro")); !d.Granted {
		t.Errorf("a loop device backed by a file outside every entry: %+v, want the grant", d)
	}
	writable("a block device sysfs does not show", admit(on("3 1 8:7 / "+merged+" rw - ext4 /dev/sda7 rw")),
		"exec."+agent.HarnessHookGrant, "8:7")
	img := filepath.Join(ws, "img.erofs")
	mkfile(img, "")
	writable("an image file the filesystem is mounted from", admit(on("3 1 0:60 / "+merged+" ro - erofs "+img+" ro")),
		"fs.write["+ws+"]", img)
}

// rootMount is a mount table row of the root filesystem, the mount holding every file of the tests' synthetic tables.
const rootMount = "1 0 8:2 / / rw - ext4 /dev/sda2 rw\n"

// fakeBlock is a sysfs block directory by number (/sys/dev/block) for the tests' synthetic tables: it shows device 8:2,
// the root filesystem's, with nothing beneath it.
func fakeBlock(t *testing.T) string {
	t.Helper()
	block := t.TempDir()
	if err := os.Mkdir(filepath.Join(block, "8:2"), 0o700); err != nil {
		t.Fatal(err)
	}
	return block
}

// onTable is the machine admitHook reads with the mount table table and the sysfs block directory block.
func onTable(block, table string) hookHost {
	return hookHost{mounts: func() ([]byte, error) { return []byte(table), nil }, block: block}
}

// hookWritable returns a check that a decision drops the provision harness-hook-writable under rule, its detail
// naming detail, and keeps rt.
func hookWritable(t *testing.T, rt *agent.RuleTable) func(name string, d HookDecision, rule, detail string) {
	return func(name string, d HookDecision, rule, detail string) {
		t.Helper()
		if d.Granted || d.Why != record.HarnessWhyHookWritable || d.Rule != rule || !strings.Contains(d.Detail, detail) || d.Table != rt {
			t.Errorf("%s: %+v, want harness-hook-writable under %s saying %q", name, d, rule, detail)
		}
	}
}

// copyFile copies src to dst, mode 0755.
func copyFile(t *testing.T, src, dst string) {
	t.Helper()
	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, data, 0o755); err != nil {
		t.Fatal(err)
	}
}

// elfInterp is a minimal little-endian ELF64 executable header with one program header, a PT_INTERP naming interp.
func elfInterp(interp string) []byte {
	le := binary.LittleEndian
	b := make([]byte, 64+56)
	copy(b, "\x7fELF")
	b[4], b[5], b[6] = 2, 1, 1                     // ELFCLASS64, little-endian, EV_CURRENT
	le.PutUint16(b[16:], 2)                        // ET_EXEC
	le.PutUint16(b[18:], 0x3e)                     // EM_X86_64
	le.PutUint32(b[20:], 1)                        // e_version
	le.PutUint64(b[32:], 64)                       // e_phoff
	le.PutUint16(b[52:], 64)                       // e_ehsize
	le.PutUint16(b[54:], 56)                       // e_phentsize
	le.PutUint16(b[56:], 1)                        // e_phnum
	le.PutUint32(b[64:], 3)                        // PT_INTERP
	le.PutUint64(b[64+8:], uint64(len(b)))         // p_offset
	le.PutUint64(b[64+32:], uint64(len(interp)+1)) // p_filesz
	return append(append(b, interp...), 0)
}

// TestAskBrokerRefusesTegoApproveFromTheRunsCgroup is the second layer of acceptance (3)'s residual (ADR 0064 D4).
// Inside a run, `tego approve` is refused the run's lock file first (R6a; TestIntegrationTegoInsideADenyListRun holds
// it to that cause). Were the lock readable, approve's own call, ask.AnswerFor, made from a process in the run's
// cgroup, reaches the run's broker built as startAsk builds it (Authorize: the runner's askPeerAuthorize), and is
// refused unauthorized, and the ask stays pending. The test process stands for the agent: the runner's cgroup is the
// one it runs in, so it both holds the request and tries to answer it.
func TestAskBrokerRefusesTegoApproveFromTheRunsCgroup(t *testing.T) {
	cg, err := unifiedAskCgroup(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	r := &runner{cg: cgroup.Cgroup{Path: "/sys/fs/cgroup" + cg}}
	asked := make(chan string, 1)
	dir := t.TempDir()
	b, err := ask.New(dir, ask.Options{UID: uint32(os.Getuid()), Timeout: time.Minute, Authorize: r.askPeerAuthorize,
		Emit: func(ask.Event) error { return nil },
		// Pending runs once the broker holds the request, so Waiting is true from then on. The ask line's Emit runs
		// before that: a test that answered on it could read Waiting false before the broker marked the ask held (the
		// race job read "no longer holds" so, on GitHub, 2026-11-02).
		Pending: func(req ask.Request) { asked <- req.AskID }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = b.Close() })
	r.askBroker = b
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		_, err := r.askRequest(ctx, ask.Request{Op: "connect", Target: "127.0.0.1:443", Rule: "net.ask[0]", Hold: "connect",
			PID: os.Getpid(), TID: os.Getpid()})
		done <- err
	}()
	var id string
	select {
	case id = <-asked:
	case err := <-done:
		t.Fatalf("the governed process's request was not held: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("no ask was published")
	}
	if _, err := ask.AnswerFor(t.Context(), dir, os.Getpid(), id, true, false); !errors.Is(err, ask.ErrUnauthorized) {
		t.Errorf("tego approve's answer from the run's cgroup: %v, want ask.ErrUnauthorized", err)
	}
	if _, err := ask.ListFor(t.Context(), dir, os.Getpid()); !errors.Is(err, ask.ErrUnauthorized) {
		t.Errorf("tego ask's list from the run's cgroup: %v, want ask.ErrUnauthorized", err)
	}
	select {
	case err := <-done:
		t.Fatalf("the ask was decided by the answer from the run's cgroup: %v", err)
	default:
	}
	if !b.Waiting() {
		t.Error("the broker no longer holds the ask its refused answer named")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the held request outlived its cancelled context")
	}
}

// TestHarnessHookUnderDenyReadOrDenyIsRefused: a grant never overrides a refusal the contract states. The tego binary
// under a deny_read entry is a read-denied exec; an exec.deny entry naming it refuses it beside the allow list.
// Either drops the provision, hook-refused, naming the contract's rule.
func TestHarnessHookUnderDenyReadOrDenyIsRefused(t *testing.T) {
	exe := testExe(t)
	hook := &harness.Hook{Argv: []string{exe, "hook", "claude-code", "--reason", "/run/r/last-refusal.json"}}
	ct := harnessContract(harness.ClaudeCode, &agent.ExecSection{Allow: []string{"/bin/sh"}})
	ct.FS = &agent.FSSection{DenyRead: []string{filepath.Dir(exe)}}
	d := AdmitHook(compileTable(t, ct), backend.TierLandlock, exe, hook)
	if d.Granted || d.Why != record.HarnessWhyHookRefused || !strings.HasPrefix(d.Rule, "fs.deny_read[") {
		t.Errorf("deny_read over the binary: %+v", d)
	}
	ct = harnessContract(harness.ClaudeCode, &agent.ExecSection{Allow: []string{"/bin/sh"}, Deny: []string{filepath.Base(exe) + " hook"}})
	d = AdmitHook(compileTable(t, ct), backend.TierLandlock, exe, hook)
	if d.Granted || d.Why != record.HarnessWhyHookRefused || !strings.HasPrefix(d.Rule, "exec.deny[") {
		t.Errorf("exec.deny naming the hook: %+v", d)
	}
}

// TestHarnessHookUnconstrainedIsNotGranted: a table that keeps the tego binary's name at any arguments (here an
// implicit grant naming it, which no contract of the tests' own binary can write) cannot be granted exactly, so the
// provision is dropped hook-not-granted, saying why.
func TestHarnessHookUnconstrainedIsNotGranted(t *testing.T) {
	exe := testExe(t)
	rt := compileTable(t, harnessContract(harness.ClaudeCode, &agent.ExecSection{Allow: []string{"/bin/sh"}}))
	lifted := *rt
	tool := filepath.Base(exe)
	lifted.ExecCommands = &agent.ExecCommands{Unconstrained: map[string]string{tool: "command"},
		Index: execmatch.NewIndex(rows.Builtin(), nil, execmatch.IndexOptions{Unconstrained: map[string]bool{tool: true}})}
	d := AdmitHook(&lifted, backend.TierLandlock, exe, &harness.Hook{Argv: []string{exe, "hook"}})
	if d.Granted || d.Why != record.HarnessWhyHookNotGranted || !strings.Contains(d.Detail, "unconstrained") || d.Table != &lifted {
		t.Errorf("%+v, want hook-not-granted saying the name stays unconstrained", d)
	}
}

// TestHarnessHookOfAnotherBinaryIsNotGranted: the launcher grants its own binary only. A provision whose hook names
// another program (here /bin/true, an ELF no write entry covers) is dropped hook-not-granted under an allow-list
// contract, never granted that program with the hook's argv.
func TestHarnessHookOfAnotherBinaryIsNotGranted(t *testing.T) {
	other, err := filepath.EvalSymlinks("/bin/true")
	if err != nil {
		t.Skip(err)
	}
	rt := compileTable(t, harnessContract(harness.ClaudeCode, &agent.ExecSection{Allow: []string{"/bin/sh"}}))
	d := AdmitHook(rt, backend.TierLandlock, testExe(t), &harness.Hook{Argv: []string{other, "hook"}})
	if d.Granted || d.Why != record.HarnessWhyHookNotGranted || !strings.Contains(d.Detail, "not the tego binary") {
		t.Errorf("%+v, want hook-not-granted: the launcher grants only its own binary", d)
	}
}

// TestExecAssuranceKernelIsRefusedAlikeWithTheGrant:
// exec.assurance: kernel refuses every run whose tier cannot pin execs before the child starts, whether
// or not its table holds a command rule (ADR 0048 (3): a run with nothing to pin claims the tier's ability), so a
// hook grant adds no refusal there and dropping it would let no run run. The granted and the ungranted table are
// refused alike at tier landlock, and both start on a handle that claims pins.
func TestExecAssuranceKernelIsRefusedAlikeWithTheGrant(t *testing.T) {
	exe := testExe(t)
	ct := harnessContract(harness.ClaudeCode, &agent.ExecSection{Allow: []string{"/bin/sh"}, Assurance: agent.ExecAssuranceKernel})
	rt := compileTable(t, ct)
	d := AdmitHook(rt, backend.TierLandlock, exe, &harness.Hook{Argv: []string{exe, "hook"}})
	if !d.Granted {
		t.Fatalf("%+v", d)
	}
	for name, table := range map[string]*agent.RuleTable{"ungranted": rt, "granted": d.Table} {
		r := &runner{rt: table, handle: &fakeHandle{}, deps: Deps{Enforce: tierBackend{tier: backend.TierLandlock}}}
		if err := r.requireExecAssurance(); !errors.Is(err, ErrExecAssurance) {
			t.Errorf("%s at tier landlock: %v, want ErrExecAssurance", name, err)
		}
		r.handle = &execClaimHandle{claim: true}
		if err := r.requireExecAssurance(); err != nil {
			t.Errorf("%s on a pinning handle: %v", name, err)
		}
	}
	if !slices.Contains(runtimeGrants(d.Table), d.Table.HarnessHookRule()) {
		t.Errorf("runtime_grants %q lack the grant", runtimeGrants(d.Table))
	}
}

// Binding the run's private runtime directory clones only immutable boundary
// metadata. A rejected harness provision must leave every executable/fs grant
// unchanged, without requiring pointer identity for that metadata clone.
func sameHarnessPolicy(a, b *agent.RuleTable) bool {
	copy := *a
	if a.Builtins != nil && b.Builtins != nil {
		boundary := *a.Builtins
		boundary.OwnRuntime = b.Builtins.OwnRuntime
		boundary.OwnRuntimeResolved = b.Builtins.OwnRuntimeResolved
		copy.Builtins = &boundary
	}
	return reflect.DeepEqual(&copy, b)
}
