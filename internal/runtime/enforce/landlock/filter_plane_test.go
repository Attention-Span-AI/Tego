// SPDX-License-Identifier: Apache-2.0

package landlock

import (
	"context"
	"path/filepath"
	"slices"
	"testing"

	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// planeVerdict runs the filter a plane with hooks leaves (filterOpts.plane) over one syscall.
func planeVerdict(t *testing.T, arch Arch, o filterOpts, nr uint32, args ...uint64) uint32 {
	t.Helper()
	insts, err := buildFilter(arch, o)
	if err != nil {
		t.Fatal(err)
	}
	vm, err := bpf.NewVM(insts)
	if err != nil {
		t.Fatalf("NewVM: %v", err)
	}
	ret, err := vm.Run(seccompData(arch, nr, args...))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	return uint32(ret)
}

func TestCompiledSeparateAskKeepsWriteOpenNotifications(t *testing.T) {
	root := tempDir(t)
	mkTree(t, root, "work/", "home/", "config/")
	work := filepath.Join(root, "work")
	c, ds, err := agent.LoadBytes(filepath.Join(root, "config", "agent.yaml"), []byte("version: 0\nname: ask-filter\ncommand: [/bin/true]\nfs: {deny_read: []}\n"), nil)
	if err != nil {
		t.Fatalf("load %v %v", err, ds)
	}
	c.FS.Ask = []string{work}
	for _, mode := range []agent.RecordMode{agent.RecordSummary, agent.RecordOff} {
		t.Run(string(mode), func(t *testing.T) {
			c.Record = mode
			rt, ds, err := agent.Compile(c, &config.Machine{}, agent.Offline(), agent.WithCwd(work), agent.WithHome(filepath.Join(root, "home")), agent.WithMountInfo(""), agent.WithTiers(backend.TierBPFLSM))
			if err != nil {
				t.Fatalf("compile %v %v", err, ds)
			}
			if len(rt.FSAsk) != 1 {
				t.Fatal("no compiled separate ask scope")
			}
			for _, r := range rt.FS {
				if r.Kind == agent.FSAsk {
					t.Fatal("regression fixture depends on legacy flattened asks")
				}
			}
			h, err := New(Options{syscalls: &fakeSyscalls{abi: 7}}).Prepare(context.Background(), rt, Run{})
			if err != nil {
				t.Fatal(err)
			}
			defer h.Close()
			all := hookSet(append(append([]string(nil), stepAHooks...), stepBHooks...)...)
			if _, dropped, err := h.PlaneFilter(all); err != nil || len(dropped) != 0 {
				t.Fatalf("ask planefilter dropped %v err %v", dropped, err)
			}
			for _, arch := range []Arch{ArchX86_64, ArchARM64} {
				tab, _ := tableFor(arch)
				for _, flags := range []uint64{unix.O_WRONLY, unix.O_WRONLY | unix.O_CREAT, unix.O_RDWR | unix.O_TRUNC} {
					if got := planeVerdict(t, arch, h.filterOpts, tab.OpenAt, uint64(^uint32(99)), 0x1000, flags); got != retNotify {
						t.Fatalf("%s flags%#x verdict %#x want notify", arch, flags, got)
					}
				}
				if got := planeVerdict(t, arch, h.filterOpts, tab.OpenAt, uint64(^uint32(99)), 0x1000, unix.O_RDONLY); got != retAllow {
					t.Fatalf("%s read-only open verdict %#x want allow", arch, got)
				}
			}
		})
	}
}

// planeCall is one syscall a filter is run over.
type planeCall struct {
	name string
	nr   uint32
	args []uint64
}

func hookSet(names ...string) map[string]bool {
	m := map[string]bool{}
	for _, n := range names {
		m[n] = true
	}
	return m
}

var (
	stepAHooks = []string{HookFileOpen, "bprm_check", HookPathRename, HookPathLink, HookPathUnlink, HookPathRmdir}
	stepBHooks = []string{HookPathMknod, HookPathMkdir, HookPathSymlink, HookPathTruncate}
)

// TestPlaneFilterDropsOnlyWhatLoadedHooksDecide is enforce-plane R27's notification half (TIER3-PLAN T16): with a
// plane's hooks loaded, the filter stops notifying each fs mutation whose every form a loaded hook decides, and
// nothing else. Step A's hooks alone take unlink, rmdir, rename and link, and leave write-opens (a refused O_CREAT
// needs path_mknod), mkdir, mknod, symlink and truncate notified; step B's add those. Execs, connects and the
// mount family stay notified at every step, and no hook set means every notification (fail closed).
//
// Spec: docs/p0/enforce-plane.md R22, R27.
func TestPlaneFilterDropsOnlyWhatLoadedHooksDecide(t *testing.T) {
	const (
		x86Open, x86OpenAt, x86Creat, x86Truncate                 = 2, 257, 85, 76
		x86Unlink, x86Unlinkat, x86Rmdir, x86Rename, x86Renameat2 = 87, 263, 84, 82, 316
		x86Link, x86Linkat, x86Mkdir, x86Mknod, x86Symlink        = 86, 265, 83, 133, 88
		x86Execve, x86Connect, x86Mount                           = 59, 42, 165
		armOpenAt, armUnlinkat, armMkdirat, armTruncate           = 56, 35, 34, 45
	)
	wr := uint64(unix.O_WRONLY)
	type call = planeCall
	x86 := []call{
		{"open-write", x86Open, []uint64{0, wr}}, {"openat-write", x86OpenAt, []uint64{0, 0, wr}},
		{"creat", x86Creat, nil}, {"truncate", x86Truncate, nil},
		{"unlink", x86Unlink, nil}, {"unlinkat", x86Unlinkat, nil}, {"rmdir", x86Rmdir, nil},
		{"rename", x86Rename, nil}, {"renameat2", x86Renameat2, nil}, {"link", x86Link, nil},
		{"linkat", x86Linkat, nil}, {"mkdir", x86Mkdir, nil}, {"mknod", x86Mknod, nil},
		{"symlink", x86Symlink, nil}, {"execve", x86Execve, nil}, {"connect", x86Connect, nil},
		{"mount", x86Mount, nil},
	}
	cases := []struct {
		name     string
		hooks    []string
		full     bool
		ask      bool
		notified []string // of x86's calls; every other one is allowed
	}{
		{name: "no plane", hooks: nil, notified: callNames(x86)},
		{name: "step A", hooks: stepAHooks, notified: []string{"open-write", "openat-write", "creat", "truncate",
			"mkdir", "mknod", "symlink", "execve", "connect", "mount"}},
		{name: "steps A and B", hooks: append(append([]string(nil), stepAHooks...), stepBHooks...),
			notified: []string{"execve", "connect", "mount"}},
		// unlinkat removes a directory under AT_REMOVEDIR: without path_rmdir it stays notified.
		{name: "no path_rmdir", hooks: []string{HookFileOpen, HookPathUnlink, HookPathRename, HookPathLink},
			notified: []string{"open-write", "openat-write", "creat", "truncate", "unlinkat", "rmdir", "mkdir",
				"mknod", "symlink", "execve", "connect", "mount"}},
		// A write-open needs file_open and path_mknod both.
		{name: "path_mknod without file_open", hooks: []string{HookPathMknod},
			notified: []string{"open-write", "openat-write", "creat", "truncate", "unlink", "unlinkat", "rmdir",
				"rename", "renameat2", "link", "linkat", "mkdir", "symlink", "execve", "connect", "mount"}},
		// record: full keeps the open family whole (every open is notified), and leaves the plane the rest.
		{name: "record: full keeps the open family", full: true,
			hooks:    append(append([]string(nil), stepAHooks...), stepBHooks...),
			notified: []string{"open-write", "openat-write", "creat", "execve", "connect", "mount"}},
		{name: "an ask entry keeps every notification", ask: true,
			hooks: append(append([]string(nil), stepAHooks...), stepBHooks...), notified: callNames(x86)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			o := filterOpts{full: tc.full, abi: minTruncateABI, plane: planeSkips(hookSet(tc.hooks...), tc.full, tc.ask)}
			for _, c := range x86 {
				got := planeVerdict(t, ArchX86_64, o, c.nr, c.args...)
				want := uint32(retAllow)
				if slices.Contains(tc.notified, c.name) {
					want = retNotify
				}
				if got != want {
					t.Errorf("%s: got %#x, want %#x", c.name, got, want)
				}
			}
		})
	}
	// arm64: its generic table's unlinkat, mkdirat, openat and truncate follow the same hooks.
	all := planeSkips(hookSet(append(append([]string(nil), stepAHooks...), stepBHooks...)...), false, false)
	for _, c := range []call{{"openat-write", armOpenAt, []uint64{0, 0, wr}}, {"unlinkat", armUnlinkat, nil},
		{"mkdirat", armMkdirat, nil}, {"truncate", armTruncate, nil}} {
		if got := planeVerdict(t, ArchARM64, filterOpts{abi: minTruncateABI, plane: all}, c.nr, c.args...); got != retAllow {
			t.Errorf("arm64 %s under steps A and B: got %#x, want allow", c.name, got)
		}
		if got := planeVerdict(t, ArchARM64, filterOpts{abi: minTruncateABI}, c.nr, c.args...); got != retNotify {
			t.Errorf("arm64 %s with no plane: got %#x, want notify", c.name, got)
		}
	}
}

func callNames(cs []planeCall) []string {
	var out []string
	for _, c := range cs {
		out = append(out, c.name)
	}
	return out
}

// TestPlaneFilterKeepsTheErrnoArms: the plane skips notifications only. The truncation arms below ABI 3 (an O_TRUNC
// on a read-only open refused, truncate(2) refused) and every errno arm stay as they are, since they decide
// without a round trip and hold with no listener.
//
// Spec: docs/p0/enforce-plane.md R22 (the Landlock domain and the filter are not weakened, I3).
func TestPlaneFilterKeepsTheErrnoArms(t *testing.T) {
	all := planeSkips(hookSet(append(append([]string(nil), stepAHooks...), stepBHooks...)...), false, false)
	o := filterOpts{abi: 2, plane: all}
	if got := planeVerdict(t, ArchX86_64, o, 76); got != retEPERM {
		t.Errorf("truncate(2) below ABI 3: got %#x, want EPERM", got)
	}
	if got := planeVerdict(t, ArchX86_64, o, 257, 0, 0, uint64(unix.O_RDONLY|unix.O_TRUNC)); got != retEPERM {
		t.Errorf("O_RDONLY|O_TRUNC below ABI 3: got %#x, want EPERM", got)
	}
	o.rootTier = true
	if got := planeVerdict(t, ArchX86_64, o, 321); got != retEPERM {
		t.Errorf("bpf(2) at the root tiers: got %#x, want EPERM", got)
	}
}

// TestHandlePlaneFilter: a Handle's PlaneFilter is its filter less what the hooks decide, names what it dropped,
// and is the filter itself when nothing is dropped (no hooks, an ask entry); under record: full it keeps the open
// family and drops the rest.
func TestHandlePlaneFilter(t *testing.T) {
	base := filterOpts{abi: minTruncateABI, procScope: true, rootTier: true}
	raw, err := assembleFilter(NativeArch(), base)
	if err != nil {
		t.Fatal(err)
	}
	h := &Handle{filter: raw, filterOpts: base}
	prog, dropped, err := h.PlaneFilter(nil)
	if err != nil || len(dropped) != 0 || !slices.Equal(prog, raw) {
		t.Fatalf("no hooks: dropped %v, same filter %v, err %v", dropped, slices.Equal(prog, raw), err)
	}
	prog, dropped, err = h.PlaneFilter(hookSet(stepAHooks...))
	if err != nil {
		t.Fatal(err)
	}
	if slices.Equal(prog, raw) {
		t.Fatal("step A's hooks left the filter as it was")
	}
	for _, want := range []string{"rename", "renameat", "renameat2", "linkat", "unlinkat"} {
		if !slices.Contains(dropped, want) {
			t.Errorf("dropped %v, want %s among them", dropped, want)
		}
	}
	for _, not := range []string{"open-write", "truncate", "mkdirat", "execve"} {
		if slices.Contains(dropped, not) {
			t.Errorf("dropped %v, want no %s", dropped, not)
		}
	}
	h.ask = true
	if _, dropped, _ := h.PlaneFilter(hookSet(stepAHooks...)); len(dropped) != 0 {
		t.Errorf("an ask entry: dropped %v, want none", dropped)
	}
	h.ask, h.filterOpts.full = false, true
	all := hookSet(append(append([]string(nil), stepAHooks...), stepBHooks...)...)
	if _, dropped, _ := h.PlaneFilter(all); !slices.Contains(dropped, "renameat2") ||
		slices.Contains(dropped, "creat") || slices.Contains(dropped, "open-write") {
		t.Errorf("record: full: dropped %v, want the mutations without the open family", dropped)
	}
	if !hasAsk(&agent.RuleTable{FS: []agent.FSRule{{Path: "/x", Kind: agent.FSAsk}}}) || hasAsk(&agent.RuleTable{}) {
		t.Error("hasAsk does not read the table's ask entries")
	}
}
