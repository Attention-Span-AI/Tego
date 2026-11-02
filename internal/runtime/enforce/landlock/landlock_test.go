// SPDX-License-Identifier: Apache-2.0

package landlock

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

func TestNewAndTier(t *testing.T) {
	b := New(Options{})
	if b.Tier() != backend.TierLandlock {
		t.Errorf("Tier = %s", b.Tier())
	}
	// A threaded ABI is used without probing (R19).
	fake := &fakeSyscalls{probeErr: unix.ENOSYS}
	bb := New(Options{ABI: 6, syscalls: fake})
	if abi, err := bb.ABI(); abi != 6 || err != nil {
		t.Errorf("ABI = %d, %v; want 6", abi, err)
	}
}

// TestProbeUnsupported is LL-E1/LL-E2 (landlock=0 at boot, kernel < 5.13: ENOSYS; not in the LSM list:
// EOPNOTSUPP): the probe fails with ErrLandlockUnsupported, no capability is offered, and Prepare refuses.
//
// Spec: docs/p0/enforce-landlock.md R1, E1, E2.
func TestProbeUnsupported(t *testing.T) {
	for _, errno := range []error{unix.ENOSYS, unix.EOPNOTSUPP, unix.EPERM} {
		fake := &fakeSyscalls{probeErr: errno}
		b := New(Options{syscalls: fake})
		if caps := b.Capabilities(); len(caps) != 0 {
			t.Errorf("%v: Capabilities = %v, want nothing", errno, caps)
		}
		_, err := b.Prepare(context.Background(), &agent.RuleTable{}, Run{})
		if !errors.Is(err, ErrLandlockUnsupported) || !errors.Is(err, errno) {
			t.Errorf("%v: Prepare error %v", errno, err)
		}
	}
	if _, err := probeABI(&fakeSyscalls{abi: 0}); !errors.Is(err, ErrLandlockUnsupported) {
		t.Errorf("zero ABI: %v", err)
	}
}

// TestCapabilitiesPerABI is R19/I10: one assertion per ABI band.
//
// Spec: docs/p0/enforce-landlock.md I10, E4.
func TestCapabilitiesPerABI(t *testing.T) {
	cases := []struct {
		abi                 int
		net, udpKernel, uni bool
	}{
		{1, false, false, true}, {3, false, false, true}, {4, true, false, true}, {8, true, false, true},
		{9, true, false, true}, {10, true, true, true}, {11, true, true, true}, {40, true, true, true},
	}
	for _, tc := range cases {
		b := New(Options{ABI: tc.abi, syscalls: &fakeSyscalls{abi: tc.abi}})
		got := b.Capabilities()
		if got.Has(backend.CapNetHostDeny) != tc.net || got.Has(backend.CapUDPPortInKernel) != tc.udpKernel || got.Has(backend.CapUnixSockets) != tc.uni {
			t.Errorf("ABI %d: net=%v udp=%v unix=%v", tc.abi, got.Has(backend.CapNetHostDeny), got.Has(backend.CapUDPPortInKernel), got.Has(backend.CapUnixSockets))
		}
		if !got.Has(backend.CapFileWriteDeny) || !got.Has(backend.CapReadDeny) || got.Has(backend.CapNamespaceSandbox) {
			t.Errorf("ABI %d: static rows changed: %v", tc.abi, got)
		}
		for c := range got {
			if !got[c] {
				t.Errorf("ABI %d: row %s present but false", tc.abi, c)
			}
		}
	}
}

// TestRulesetHandlesNoQuietMask is R20's other half: at no ABI does a ruleset quiet what it handles, since the
// masks would mute the refusals landlock.audit exists to record, and below ABI 10 a non-zero mask is E2BIG.
//
// Spec: docs/p0/enforce-landlock.md R20.
func TestRulesetHandlesNoQuietMask(t *testing.T) {
	for abi := 1; abi <= 11; abi++ {
		_, fake := prepare(t, abi, &agent.RuleTable{Record: agent.RecordSummary})
		if len(fake.created) != 1 {
			t.Fatalf("ABI %d: %d rulesets created", abi, len(fake.created))
		}
		if a := fake.created[0]; a.Quiet_access_fs != 0 || a.Quiet_access_net != 0 || a.Quiet_scoped != 0 {
			t.Errorf("ABI %d: quiet masks fs=%#x net=%#x scoped=%#x, want none", abi, a.Quiet_access_fs, a.Quiet_access_net, a.Quiet_scoped)
		}
	}
}

// TestPrepareEmptyTable is I4: an empty table still handles the whole write side, grants "/" the
// read set, builds a non-empty filter and yields a ruleset fd.
//
// Spec: docs/p0/enforce-landlock.md I4.
func TestPrepareEmptyTable(t *testing.T) {
	rt := &agent.RuleTable{Record: agent.RecordSummary}
	h, fake := prepare(t, 7, rt)
	if len(fake.created) != 1 {
		t.Fatalf("%d rulesets created", len(fake.created))
	}
	if got := accessFS(fake.created[0].Handled_access_fs); got != profileFor(7).FS {
		t.Errorf("handled fs = %#x, want %#x", got, profileFor(7).FS)
	}
	if fake.created[0].Handled_access_net != uint64(profileFor(7).Net) {
		t.Errorf("handled net = %#x (nil Contract fails closed)", fake.created[0].Handled_access_net)
	}
	if fake.created[0].Scoped != uint64(scopeSignal|scopeAbstractUnixSocket) {
		t.Errorf("scoped = %#x", fake.created[0].Scoped)
	}
	root, ok := h.entry("/")
	if !ok || root.Kind != kindReadRoot || root.Access != readSet {
		t.Errorf("root grant = %+v", root)
	}
	if len(fake.paths) != 1 || fake.paths[0].Access != uint64(readSet) {
		t.Errorf("path rules = %+v, want the single root read grant", fake.paths)
	}
	if fd, ok := h.LandlockRuleset(); !ok || fd < 0 {
		t.Errorf("LandlockRuleset = %d, %v", fd, ok)
	}
	if prog, ok := h.SeccompFilter(); !ok || len(prog) == 0 {
		t.Error("SeccompFilter empty")
	}
	if h.abi != 7 || len(h.unenforced) != 0 {
		t.Errorf("ABI %d unenforced %v", h.abi, h.unenforced)
	}
	if err := h.Attach(1); err != nil {
		t.Error(err)
	}
	if err := h.Detach(); err != nil {
		t.Error(err)
	}
}

func TestPrepareNilTable(t *testing.T) {
	_, err := New(Options{syscalls: &fakeSyscalls{abi: 7}}).Prepare(context.Background(), nil, Run{})
	if !errors.Is(err, ErrRulesetBuild) {
		t.Errorf("nil table: %v", err)
	}
}

// TestPrepareWriteEntries covers write masks per ABI, the /dev IOCTL_DEV rule, file entries, a
// missing write directory created by Prepare, and ask/watch/implicit identity entries.
//
// Spec: docs/p0/enforce-landlock.md R20.
func TestPrepareWriteEntries(t *testing.T) {
	root := tempDir(t)
	mkTree(t, root, "out/", "note.txt", "watch/", "ask/")
	rt := &agent.RuleTable{
		Contract: contractWith(true, true),
		FS: []agent.FSRule{
			fsRule(agent.FSWrite, filepath.Join(root, "out")),
			fsRule(agent.FSWrite, filepath.Join(root, "note.txt")),
			{Path: filepath.Join(root, "new"), Kind: agent.FSWrite, Access: agent.AccessWriteSet, Missing: true},
			fsRule(agent.FSWatch, filepath.Join(root, "watch")),
			fsRule(agent.FSAsk, filepath.Join(root, "ask")),
			fsRule(agent.FSImplicit, "/sys/fs/cgroup"),
			fsRule(agent.FSImplicit, filepath.Join(root, "absent-ledger-root")),
			fsRule(agent.FSImplicit, "/"),
		},
	}
	for _, abi := range []int{1, 3, 7, 9} {
		t.Run("abi"+string(rune('0'+abi)), func(t *testing.T) {
			h, fake := prepare(t, abi, rt)
			p := profileFor(abi)
			dir, _ := h.entry(filepath.Join(root, "out"))
			want := p.mask(accessFS(agent.AccessWriteSet)|readSet) &^ accessIoctlDev
			if abi >= 9 {
				want |= accessResolveUnix
			}
			if dir.Kind != kindWrite || dir.Access != want || !dir.IsDir {
				t.Errorf("write dir = %+v, want access %#x", dir, want)
			}
			file, _ := h.entry(filepath.Join(root, "note.txt"))
			if file.Access != want&fileRights || file.Access&accessReadDir != 0 {
				t.Errorf("write file = %+v, want %#x", file, want&fileRights)
			}
			created, ok := h.entry(filepath.Join(root, "new"))
			if !ok || created.Access != want {
				t.Errorf("missing write dir = %+v, %v", created, ok)
			}
			for _, id := range []string{filepath.Join(root, "watch"), filepath.Join(root, "ask"), "/sys/fs/cgroup"} {
				e, ok := h.entry(id)
				if !ok || e.Access != 0 {
					t.Errorf("identity entry %s = %+v, %v", id, e, ok)
				}
			}
			if _, ok := h.entry(filepath.Join(root, "absent-ledger-root")); ok {
				t.Error("a missing implicit entry was held")
			}
			// "/" is both the fs: {} implicit entry and the read root: one inode, one union grant.
			rootE, _ := h.entry("/")
			if rootE.Access != readSet {
				t.Errorf("root = %+v", rootE)
			}
			// I3: one add_rule per entry with rights, none for identity-only entries.
			withRights := 0
			for _, e := range h.fds.open {
				if e.Access != 0 {
					withRights++
				}
			}
			if len(fake.paths) != withRights {
				t.Errorf("%d add_rule calls for %d entries with rights", len(fake.paths), withRights)
			}
			for _, c := range fake.paths {
				if c.Flags != 0 {
					t.Errorf("add_rule flags = %d (R20)", c.Flags)
				}
			}
		})
	}
	t.Run("dev keeps ioctl", func(t *testing.T) {
		rt := &agent.RuleTable{Contract: contractWith(true, true), FS: []agent.FSRule{fsRule(agent.FSWrite, "/dev/null")}}
		h, _ := prepare(t, 7, rt)
		e, _ := h.entry("/dev/null")
		if e.Access&accessIoctlDev == 0 || e.Access&accessWriteFile == 0 {
			t.Errorf("/dev/null = %+v", e)
		}
	})
	t.Run("exec unrestricted adds EXECUTE", func(t *testing.T) {
		rt := &agent.RuleTable{Contract: contractWith(false, true), FS: []agent.FSRule{fsRule(agent.FSWrite, filepath.Join(root, "out"))}}
		h, _ := prepare(t, 7, rt)
		e, _ := h.entry(filepath.Join(root, "out"))
		r, _ := h.entry("/")
		if e.Access&accessExecute == 0 || r.Access != readSet|accessExecute {
			t.Errorf("write = %+v root = %+v", e, r)
		}
	})
}

func TestPrepareVanishedAndKinds(t *testing.T) {
	root := tempDir(t)
	cases := []struct {
		name string
		rule agent.FSRule
		want error
	}{
		{"write missing without Missing", fsRule(agent.FSWrite, filepath.Join(root, "gone")), ErrPathVanished},
		{"watch missing", fsRule(agent.FSWatch, filepath.Join(root, "gone")), ErrPathVanished},
		{"ask missing", fsRule(agent.FSAsk, filepath.Join(root, "gone")), ErrPathVanished},
		{"unknown kind", agent.FSRule{Path: root, Kind: "bogus"}, ErrRulesetBuild},
		{"missing write under a missing parent", agent.FSRule{Path: filepath.Join(root, "a/b"), Kind: agent.FSWrite, Missing: true}, ErrPathVanished},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := openFDs(t)
			err := prepareErr(t, 7, &agent.RuleTable{FS: []agent.FSRule{tc.rule}}, nil)
			if !errors.Is(err, tc.want) {
				t.Errorf("error %v, want %v", err, tc.want)
			}
			if after := openFDs(t); after != before {
				t.Errorf("fd leak: %d -> %d", before, after)
			}
		})
	}
}

// TestPrepareSaysAWriteEntryItCouldNotCreate: a directory the run may not create in is not a path that vanished since
// compile, which is what a missing `out/` under a read-only project was told. It stays a refusal.
func TestPrepareSaysAWriteEntryItCouldNotCreate(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory write permission, which this test relies on")
	}
	root := tempDir(t)
	if err := os.Chmod(root, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(root, 0o755) })
	err := prepareErr(t, 7, &agent.RuleTable{FS: []agent.FSRule{{Path: filepath.Join(root, "out"), Kind: agent.FSWrite, Missing: true}}}, nil)
	if errors.Is(err, ErrPathVanished) || !errors.Is(err, os.ErrPermission) || !strings.Contains(err.Error(), "creating write entry") {
		t.Errorf("error %v: want the failed create, and no vanished path", err)
	}
}

// TestPrepareRulesetErrors asserts docs/p0/enforce-landlock.md I1.
func TestPrepareRulesetErrors(t *testing.T) {
	root := tempDir(t)
	mkTree(t, root, "out/")
	rt := &agent.RuleTable{Contract: contractWith(true, true), FS: []agent.FSRule{fsRule(agent.FSWrite, filepath.Join(root, "out"))}}
	before := openFDs(t)
	err := prepareErr(t, 7, rt, &fakeSyscalls{createErr: unix.EINVAL})
	if !errors.Is(err, ErrRulesetBuild) || !errors.Is(err, unix.EINVAL) {
		t.Errorf("create: %v", err)
	}
	err = prepareErr(t, 7, rt, &fakeSyscalls{addErr: unix.EINVAL})
	if !errors.Is(err, ErrRulesetBuild) || !errors.Is(err, unix.EINVAL) {
		t.Errorf("add: %v", err)
	}
	if after := openFDs(t); after != before {
		t.Errorf("fd leak on ruleset failure: %d -> %d", before, after)
	}
}

// TestPrepareCancelled is LL-E20 and LL-I1: a cancelled context returns no Handle and holds nothing, whether
// it is seen before the first open or inside the walk.
//
// Spec: docs/p0/enforce-landlock.md E20, I1.
func TestPrepareCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	before := openFDs(t)
	h, err := New(Options{syscalls: &fakeSyscalls{abi: 7}}).Prepare(ctx, &agent.RuleTable{}, Run{})
	if !errors.Is(err, context.Canceled) || h != nil {
		t.Errorf("error %v", err)
	}
	if after := openFDs(t); after != before {
		t.Errorf("fd leak: %d -> %d", before, after)
	}
	// Cancellation between entries: a deny_read with more siblings than ctxCheckEvery.
	root := tempDir(t)
	names := make([]string, 0, ctxCheckEvery+10)
	for i := 0; i < ctxCheckEvery+10; i++ {
		names = append(names, filepath.Join("many", "f"+string(rune('a'+i%26))+string(rune('a'+(i/26)%26))+string(rune('a'+(i/676)%26))))
	}
	mkTree(t, root, append(names, "many/secret")...)
	// The context reads live at Prepare's first check (E20's "stop before the first open") and cancelled at
	// every later one, so the cancellation is seen inside the walk, at the ctxCheckEvery-th entry, and not
	// at the door: a context cancelled before Prepare would pass this test without the walk ever checking.
	ctx2 := &cancelAfterFirstCheck{Context: context.Background()}
	fake := &fakeSyscalls{abi: 7}
	b := New(Options{syscalls: fake})
	rt := &agent.RuleTable{FS: []agent.FSRule{fsRule(agent.FSDenyRead, filepath.Join(root, "many", "secret"))}}
	_, err = b.Prepare(ctx2, rt, Run{})
	if !errors.Is(err, context.Canceled) {
		t.Errorf("mid-walk cancel: %v", err)
	}
	if want := fmt.Sprintf("cancelled after %d entries", ctxCheckEvery); err == nil || !strings.Contains(err.Error(), want) {
		t.Errorf("mid-walk cancel: %v, want it seen inside the walk (%q)", err, want)
	}
	if len(fake.created) != 0 {
		t.Errorf("a cancelled Prepare created %d rulesets, want none (I1: all or nothing)", len(fake.created))
	}
	if after := openFDs(t); after != before {
		t.Errorf("fd leak after mid-walk cancel: %d -> %d", before, after)
	}
}

// TestPrepareFDExhaustion is E11: a plan over the launcher's descriptor budget is refused naming the cap, before the
// open that would meet EMFILE, and every fd opened so far is closed exactly once.
//
// Spec: docs/p0/enforce-landlock.md E11, I1.
func TestPrepareFDExhaustion(t *testing.T) {
	root := tempDir(t)
	names := make([]string, 0, 64)
	for i := 0; i < 64; i++ {
		names = append(names, filepath.Join("d", "s"+string(rune('a'+i%26))+string(rune('a'+i/26))))
	}
	mkTree(t, root, append(names, "d/secret")...)
	var lim unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &lim); err != nil {
		t.Fatal(err)
	}
	before := openFDs(t)
	low := lim
	low.Cur = uint64(before) + 16
	if err := unix.Setrlimit(unix.RLIMIT_NOFILE, &low); err != nil {
		t.Skipf("setrlimit: %v", err)
	}
	t.Cleanup(func() { _ = unix.Setrlimit(unix.RLIMIT_NOFILE, &lim) })
	// The limit as lowered here: ReadFDBudget would raise it back to the hard limit first.
	prev := readFDBudget
	readFDBudget = currentFDBudget
	t.Cleanup(func() { readFDBudget = prev })
	rt := &agent.RuleTable{FS: []agent.FSRule{fsRule(agent.FSDenyRead, filepath.Join(root, "d", "secret"))}}
	err := prepareErr(t, 7, rt, nil)
	var capErr *FDCapError
	if !errors.Is(err, ErrFDExhausted) || !errors.As(err, &capErr) || errors.Is(err, unix.EMFILE) {
		t.Errorf("error %v, want the budget's refusal, not EMFILE", err)
	}
	// §7: exit 125 with the count and the cap named, before any open meets the limit.
	if err == nil || !strings.Contains(err.Error(), "its cap on this launcher") || !strings.Contains(err.Error(), "RLIMIT_NOFILE") {
		t.Errorf("error %v, want the cap named", err)
	}
	if after := openFDs(t); after != before {
		t.Errorf("fd leak: %d -> %d", before, after)
	}
}

// TestListDirFDExhaustionNamesTheCount is E11 where the descriptors run out on the reopen a listing makes
// (E27's enumeration), which as root in the KVM guest is where TestPrepareFDExhaustion runs out: the error is
// ErrFDExhausted and names the count held, as the §7 row says, like an entry's own open.
//
// Spec: docs/p0/enforce-landlock.md E11, E27.
func TestListDirFDExhaustionNamesTheCount(t *testing.T) {
	pathFD, err := unix.Open(tempDir(t), unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(pathFD) //nolint:errcheck // test cleanup
	// The number the next open would get: a limit at it makes that open fail with EMFILE.
	next, err := unix.Dup(pathFD)
	if err != nil {
		t.Fatal(err)
	}
	_ = unix.Close(next)
	var lim unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &lim); err != nil {
		t.Fatal(err)
	}
	low := lim
	low.Cur = uint64(next)
	if err := unix.Setrlimit(unix.RLIMIT_NOFILE, &low); err != nil {
		t.Skipf("setrlimit: %v", err)
	}
	_, err = listDir(pathFD, "/held/dir", 7)
	_ = unix.Setrlimit(unix.RLIMIT_NOFILE, &lim)
	if !errors.Is(err, ErrFDExhausted) || !errors.Is(err, unix.EMFILE) || err == nil ||
		!strings.Contains(err.Error(), "7 fds held when listing \"/held/dir\"") {
		t.Errorf("error %v, want fd exhaustion naming the 7 fds held", err)
	}
}

// TestCloseIdempotent is I7 on a live handle, a double close and a zero value.
//
// Spec: docs/p0/enforce-landlock.md I7.
func TestCloseIdempotent(t *testing.T) {
	root := tempDir(t)
	mkTree(t, root, "out/")
	before := openFDs(t)
	h, _ := prepare(t, 7, &agent.RuleTable{FS: []agent.FSRule{fsRule(agent.FSWrite, filepath.Join(root, "out"))}})
	if openFDs(t) <= before {
		t.Fatal("nothing was held")
	}
	if err := h.Close(); err != nil {
		t.Errorf("first Close: %v", err)
	}
	if after := openFDs(t); after != before {
		t.Errorf("fds after Close: %d, before %d", after, before)
	}
	if err := h.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
	if fd, ok := h.LandlockRuleset(); fd != -1 || !ok {
		t.Errorf("after Close: fd %d ok %v", fd, ok)
	}
	var zero Handle
	if err := zero.Close(); err != nil {
		t.Errorf("zero Close: %v", err)
	}
	if _, ok := zero.SeccompFilter(); ok {
		t.Error("zero handle has a filter")
	}
}

func TestHandleCapabilitiesUnenforced(t *testing.T) {
	root := tempDir(t)
	mkTree(t, root, "work/.env", "work/x")
	rt := &agent.RuleTable{
		Contract: contractWith(true, true),
		FS: []agent.FSRule{
			fsRule(agent.FSWrite, filepath.Join(root, "work")),
			{Path: filepath.Join(root, "work", ".env"), Kind: agent.FSDenyRead, Unenforced: true},
		},
	}
	h, fake := prepare(t, 7, rt)
	if !h.Capabilities().Has(backend.CapFileWriteDeny) || h.Capabilities().Has(backend.CapReadDeny) {
		t.Errorf("caps = %v", h.Capabilities())
	}
	if got := h.unenforced; len(got) != 1 || got[0] != filepath.Join(root, "work", ".env") {
		t.Errorf("Unenforced = %v", got)
	}
	// The held-object plan read the target's name from a descriptor (TestHeldPlanDetectsChangedContainment), and,
	// the target being left out of the ruleset, keeps none of it for the run (TestLeftOutDenyReadTargetsHoldNoDescriptor).
	if e, ok := h.entry(filepath.Join(root, "work", ".env")); ok {
		t.Errorf("an unenforced target is held for the run (%+v); R4 leaves it out of the ruleset", e)
	}
	for _, c := range fake.paths {
		if c.Access == 0 {
			t.Error("an identity-only entry got a rule")
		}
	}
	h.Capabilities()[backend.CapReadDeny] = true
	if h.Capabilities().Has(backend.CapReadDeny) {
		t.Error("Capabilities returned shared state")
	}
}

// TestRunDirImplicit asserts docs/p0/enforce-landlock.md R8.
func TestRunDirImplicit(t *testing.T) {
	root := tempDir(t)
	mkTree(t, root, "run/")
	fake := &fakeSyscalls{abi: 7}
	h, err := New(Options{syscalls: fake}).Prepare(context.Background(), &agent.RuleTable{}, Run{Dir: filepath.Join(root, "run")})
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	e, ok := h.entry(filepath.Join(root, "run"))
	if !ok || e.Kind != kindImplicitDeny || e.Access != 0 {
		t.Errorf("run dir = %+v, %v", e, ok)
	}
}

func TestKindNames(t *testing.T) {
	seen := map[string]bool{}
	for k := kindWrite; k <= kindImplicitDeny; k++ {
		n := kindName(k)
		if n == "" || seen[n] || strings.HasPrefix(n, "kind") {
			t.Errorf("kind %d: name %q", k, n)
		}
		seen[n] = true
	}
	if kindName(entryKind(200)) != "kind(200)" {
		t.Error("unknown kind name")
	}
}

func BenchmarkPrepare(b *testing.B) {
	root := b.TempDir()
	names := make([]string, 0, 200)
	for i := 0; i < 200; i++ {
		names = append(names, filepath.Join("home", "f"+string(rune('a'+i%26))+string(rune('a'+i/26))))
	}
	for _, p := range append(names, "home/.ssh/id", "out/") {
		full := filepath.Join(root, p)
		if p[len(p)-1] == '/' {
			_ = mkdirAll(full)
			continue
		}
		_ = mkdirAll(filepath.Dir(full))
		_ = writeFile(full)
	}
	rt := &agent.RuleTable{
		Contract: contractWith(true, true),
		FS: []agent.FSRule{
			fsRule(agent.FSWrite, filepath.Join(root, "out")),
			fsRule(agent.FSDenyRead, filepath.Join(root, "home", ".ssh")),
		},
		Exec: []agent.ExecRule{{Path: "/bin/sh", Basename: "sh", Source: agent.ExecSourceCommand}},
	}
	be := New(Options{syscalls: &fakeSyscalls{abi: 7}})
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h, err := be.Prepare(context.Background(), rt, Run{})
		if err != nil {
			b.Fatal(err)
		}
		_ = h.Close()
	}
}

// cancelAfterFirstCheck is a context that is live at its first Err() and cancelled at every later one.
type cancelAfterFirstCheck struct {
	context.Context
	checks int
}

func (c *cancelAfterFirstCheck) Err() error {
	c.checks++
	if c.checks == 1 {
		return nil
	}
	return context.Canceled
}
