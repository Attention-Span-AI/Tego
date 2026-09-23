// SPDX-License-Identifier: Apache-2.0

package landlock

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// The tests in this file are E32: a deny node (a deny_read target or an enumerated ancestor) that is
// the same inode as some other entry, reached by another name. Landlock keys rules by inode, so what
// decides is the inode, whichever name each stage used to reach it.

// procAlias names dir through /proc/<pid>/root, a magic link to "/" that openat follows: the same
// inode under a second path, which is what a bind mount gives a directory. It is the only such alias
// an unprivileged test can make, and resolveTarget (EvalSymlinks) collapses it where a bind mount
// would survive, so the tests that use it enter after resolution — a hand-built table whose Resolved
// is empty, or walk itself — which is where a bind-mounted path enters. The pid, not "self": walk
// would otherwise also enumerate /proc/self, itself a second name for /proc/<pid>, and a test about
// one alias would be decided by another.
func procAlias(t *testing.T, dir string) string {
	t.Helper()
	alias := fmt.Sprintf("/proc/%d/root%s", os.Getpid(), dir)
	var a, b unix.Stat_t
	if unix.Stat(dir, &a) != nil || unix.Stat(alias, &b) != nil || a.Dev != b.Dev || a.Ino != b.Ino {
		t.Skipf("%s does not alias %s here", alias, dir)
	}
	return alias
}

func link(t *testing.T, oldname, newname string) {
	t.Helper()
	if err := os.Link(oldname, newname); err != nil {
		t.Skipf("hardlink unsupported here: %v", err)
	}
}

// TestDenyNodeIsAWriteEntryInode: a deny node whose inode an fs.write entry already holds under
// another name. fsEntries runs first, so the entry hold finds carries the write set, and the rule on
// that inode reads the target through every name. compile compares paths and cannot see it, so this is
// R4 decided by identity with nothing to cross-check against (I5): the build fails closed.
func TestDenyNodeIsAWriteEntryInode(t *testing.T) {
	root := tempDir(t)
	mkTree(t, root, "work/notes.txt", "vault/", "home/.ssh/id", "home/pub")
	notes := filepath.Join(root, "work", "notes.txt")
	secret := filepath.Join(root, "vault", "secret")
	link(t, notes, secret)
	cases := []struct {
		name, deny, write string
	}{
		{"target is a hardlink of a write file", secret, notes},
		{"ancestor is a write directory under another name", filepath.Join(root, "home", ".ssh", "id"), procAlias(t, filepath.Join(root, "home"))},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := prepareErr(t, 7, denyTable([]string{tc.deny}, tc.write), nil)
			if !errors.Is(err, ErrRulesetBuild) || !strings.Contains(err.Error(), tc.write) {
				t.Errorf("error %v, want %v naming the write entry %q", err, ErrRulesetBuild, tc.write)
			}
		})
	}
}

// TestDenyTargetHeldFirstForIdentity: a deny_read target that is also an fs.watch or implicit entry.
// Those are held first, with no rights, under their own kind — and add's guard reads the kind. Unless
// the target's entry is re-marked, a hardlink of it enumerated as a sibling unions READ_FILE onto the
// secret's inode, and a PT_INTERP naming that hardlink passes holdLoader's inode check (I11).
func TestDenyTargetHeldFirstForIdentity(t *testing.T) {
	for _, kind := range []agent.FSKind{agent.FSWatch, agent.FSImplicit} {
		t.Run(string(kind), func(t *testing.T) {
			root := tempDir(t)
			mkTree(t, root, "secrets/id", "pub/note", "bin/")
			target := filepath.Join(root, "secrets", "id")
			alias := filepath.Join(root, "alias")
			link(t, target, alias)
			fs := []agent.FSRule{fsRule(kind, target), fsRule(agent.FSDenyRead, target)}

			h, _ := prepare(t, 7, &agent.RuleTable{Contract: contractWith(true, true), FS: fs})
			if e, ok := h.entry(target); !ok || e.Kind != kindDenyTarget || e.Access != 0 {
				t.Errorf("target %s = %+v (held %v), want kind deny_read with access 0", target, e, ok)
			}
			if !h.Capabilities().Has(backend.CapReadDeny) || len(h.unenforced) != 0 {
				t.Fatalf("the fixture must be an enforced deny: caps %v, unenforced %v", h.Capabilities(), h.unenforced)
			}

			bin := filepath.Join(root, "bin", "tool")
			dynamicELF(t, bin, alias)
			rt := &agent.RuleTable{Contract: contractWith(true, true), FS: fs, Exec: []agent.ExecRule{execRule(bin, agent.ExecSourceAllow)}}
			if err := prepareErr(t, 7, rt, nil); !errors.Is(err, ErrLoaderRefused) {
				t.Errorf("PT_INTERP naming a hardlink of the target: error %v, want %v", err, ErrLoaderRefused)
			}
		})
	}
}

// TestCompileWatchedDenyReadTarget is the same shape through agent.Compile: watching a credential
// file that deny_read also covers is a natural contract, and compile accepts it with no diagnostic.
func TestCompileWatchedDenyReadTarget(t *testing.T) {
	root, err := filepath.EvalSymlinks(tempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	mkTree(t, root, "work/src", "secrets/id", "ledger/")
	target := filepath.Join(root, "secrets", "id")
	alias := filepath.Join(root, "alias")
	link(t, target, alias)
	contract := filepath.Join(root, "agent.yaml")
	yaml := "version: 0\nname: watched\ncommand: [\"/bin/sh\", \"-c\", \"true\"]\n" +
		"fs:\n  write: [\"" + filepath.Join(root, "work") + "\"]\n" +
		"  watch: [\"" + target + "\"]\n" +
		"  deny_read: [\"" + target + "\"]\n" +
		"exec:\n  allow: [\"sh\"]\ntier: landlock\n"
	if err := os.WriteFile(contract, []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}
	c, ds, err := agent.LoadBytes(contract, []byte(yaml), nil)
	if err != nil {
		t.Fatalf("Load: %v\n%v", err, ds)
	}
	m := config.Builtin()
	m.LedgerRoot.Value = filepath.Join(root, "ledger")
	rt, ds, err := agent.Compile(c, m, agent.WithPATH("/usr/bin:/bin"), agent.WithCwd(root), agent.WithHome(root), agent.WithMountInfo(""), agent.Offline())
	if err != nil {
		t.Fatalf("Compile: %v\n%v", err, ds)
	}
	h, _ := prepare(t, 7, rt)
	if e, ok := h.entry(target); !ok || e.Kind != kindDenyTarget || e.Access != 0 {
		t.Errorf("target %s = %+v (held %v), want kind deny_read with access 0", target, e, ok)
	}
	if !h.Capabilities().Has(backend.CapReadDeny) {
		t.Error("fs.deny_read not reported: the fixture must be an enforced deny")
	}
}

// TestDeclaredGrantOnADenyNode: an exec or unix: grant, built after denyRead, whose inode is a
// deny_read target. add refuses the union (I11), so the grant would be lost without a word and the run
// would meet EACCES at execve or connect behind a compile --test row that says allow: the build fails
// naming both instead, and says why. An exec grant would read the target, and says so. RESOLVE_UNIX
// would not: the reason is the dropped backstop. The backstop exists only from ABI 9, so below it the
// same contract prepares with the supervisor alone deciding (R21). A grant *beneath* a target is a
// different inode and keeps its rights.
func TestDeclaredGrantOnADenyNode(t *testing.T) {
	root := tempDir(t)
	mkTree(t, root, "secrets/", "bin/", "pub/note")
	tool := filepath.Join(root, "secrets", "tool")
	staticELF(t, tool)
	alias := filepath.Join(root, "bin", "tool")
	link(t, tool, alias)
	// Its own short directory: sun_path holds 108 bytes, and t.TempDir's names are long.
	sockDir, err := os.MkdirTemp("", "ey")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(sockDir) })
	if sockDir, err = filepath.EvalSymlinks(sockDir); err != nil { // as tempDir, for the entry it is held under
		t.Fatal(err)
	}
	sock := filepath.Join(sockDir, "agent.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()

	withExec := func(deny string, rules ...agent.ExecRule) *agent.RuleTable {
		return &agent.RuleTable{Contract: contractWith(true, true), FS: []agent.FSRule{fsRule(agent.FSDenyRead, deny)}, Exec: rules}
	}
	unixOnTarget := func() *agent.RuleTable {
		return &agent.RuleTable{
			Contract: contractWith(true, true),
			FS:       []agent.FSRule{fsRule(agent.FSDenyRead, sock)},
			Net:      []agent.NetRule{{Raw: "unix:" + sock, Proto: agent.ProtoUnix, UnixPath: sock}},
		}
	}
	const readsIt, dropsIt = "without granting what deny_read denies", "backstop would be dropped"
	cases := []struct {
		name        string
		abi         int
		rt          *agent.RuleTable
		why, notWhy string
	}{
		{"exec.allow names the target", 7, withExec(tool, execRule(tool, agent.ExecSourceAllow)), readsIt, dropsIt},
		{"exec.allow names a hardlink of the target", 7, withExec(tool, execRule(alias, agent.ExecSourceAllow)), readsIt, dropsIt},
		{"the agent command is a hardlink of the target", 7, withExec(tool, execRule(alias, agent.ExecSourceCommand)), readsIt, dropsIt},
		{"unix: names the target", 9, unixOnTarget(), dropsIt, readsIt},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := prepareErr(t, tc.abi, tc.rt, nil)
			if !errors.Is(err, ErrRulesetBuild) || !strings.Contains(err.Error(), "deny_read") {
				t.Errorf("error %v, want %v naming the deny_read entry", err, ErrRulesetBuild)
			}
			if err != nil && (!strings.Contains(err.Error(), tc.why) || strings.Contains(err.Error(), tc.notWhy)) {
				t.Errorf("error %q: want the reason %q, not %q", err, tc.why, tc.notWhy)
			}
		})
	}

	t.Run("unix: names the target below ABI 9", func(t *testing.T) {
		h, _ := prepare(t, 8, unixOnTarget())
		if e, ok := h.entry(sock); !ok || e.Kind != kindDenyTarget || e.Access != 0 {
			t.Errorf("%s = %+v (held %v), want kind deny_read with access 0", sock, e, ok)
		}
	})

	t.Run("a binary beneath a target keeps its grant", func(t *testing.T) {
		h, _ := prepare(t, 7, withExec(filepath.Join(root, "secrets"), execRule(tool, agent.ExecSourceAllow)))
		if e, ok := h.entry(tool); !ok || e.Kind != kindExecBinary || e.Access != execAccess {
			t.Errorf("%s = %+v (held %v), want kind exec binary access %#x", tool, e, ok, execAccess)
		}
	})
}

// walkBuilder is a builder for driving walk directly with paths that are already "resolved": the
// only way to hand it two names for one directory, which is what a bind mount does after resolution.
func walkBuilder(t *testing.T) *builder {
	t.Helper()
	bd := newBuilder(context.Background(), &agent.RuleTable{Contract: contractWith(true, true)}, Run{}, profileFor(7), &fakeSyscalls{abi: 7})
	t.Cleanup(func() { _ = bd.fds.closeAll() })
	return bd
}

// entryFor finds the entry holding path's inode, whatever name held it first.
func entryFor(t *testing.T, bd *builder, path string) openPath {
	t.Helper()
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		t.Fatal(err)
	}
	i, ok := bd.fds.ids[devIno{dev: st.Dev, ino: st.Ino}]
	if !ok {
		t.Fatalf("%s is not held", path)
	}
	return bd.fds.open[i]
}

// TestWalkLevelIsATargetInode is E32 (d): target T, and a second target whose path runs through a bind
// mount of the whole of T. Their strings are unrelated, so outermost keeps both. The second target's
// walk reaches a level that is T's own inode, and when that target lies deeper, levels inside T that
// are not T's inode at all. Listing any of them grants T's contents as siblings, and the grant is keyed
// by inode, so the content becomes readable under every name, T's own path included. Each case puts a
// sibling that is not on the path at the deepest level. The check runs over T's real subtree by inode,
// so no name for that content can hold rights unnoticed.
func TestWalkLevelIsATargetInode(t *testing.T) {
	for _, second := range []string{"x", "prod/app.key", "prod/eu/app.key"} {
		t.Run(second, func(t *testing.T) {
			root := tempDir(t)
			mkTree(t, root, "secrets/x", "secrets/aws.json", "secrets/prod/app.key", "secrets/prod/other.key",
				"secrets/prod/eu/app.key", "secrets/prod/eu/other.key", "pub")
			target := filepath.Join(root, "secrets")
			alias := procAlias(t, target)
			bd := walkBuilder(t)
			if err := bd.walk([]string{target, filepath.Join(alias, second)}); err != nil {
				t.Fatal(err)
			}
			if e := entryFor(t, bd, target); e.Kind != kindDenyTarget || e.Access != 0 {
				t.Errorf("target %s = %+v, want kind deny_read with access 0", target, e)
			}
			err := filepath.Walk(target, func(p string, _ os.FileInfo, err error) error {
				if err != nil {
					return err
				}
				var st unix.Stat_t
				if err := unix.Lstat(p, &st); err != nil {
					return err
				}
				if i, ok := bd.fds.ids[devIno{dev: st.Dev, ino: st.Ino}]; ok && bd.fds.open[i].Access != 0 {
					e := bd.fds.open[i]
					t.Errorf("%s lies inside the deny_read target yet its inode is held as %s %q with %#x", p, kindName(e.Kind), e.Path, e.Access)
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			// The walk outside T still happened: the sibling beside it is granted.
			if e := entryFor(t, bd, filepath.Join(root, "pub")); e.Kind != kindDenySibling || e.Access != accessReadFile {
				t.Errorf("sibling pub = %+v, want READ_FILE", e)
			}
		})
	}
}

// TestWalkAliasedLevels: two targets whose ancestors are one directory reached by two paths. Each
// name's level has its own on-path child, so whichever of the two is listed first sees the other's
// on-path child as a sibling. Every deny node is sealed before any listing, so that sibling grant meets
// a sealed ancestor and the secret beneath it stays denied — in both orders.
func TestWalkAliasedLevels(t *testing.T) {
	root := tempDir(t)
	mkTree(t, root, "X/a/secret", "X/b/secret", "X/pub")
	aliasRoot := procAlias(t, root)
	a, b := filepath.Join(root, "X", "a", "secret"), filepath.Join(root, "X", "b", "secret")
	aliasOf := func(p string) string { return aliasRoot + strings.TrimPrefix(p, root) }
	for _, tc := range []struct {
		name    string
		targets []string
	}{{"second target aliased", []string{a, aliasOf(b)}}, {"first target aliased", []string{aliasOf(a), b}}} {
		t.Run(tc.name, func(t *testing.T) {
			bd := walkBuilder(t)
			if err := bd.walk(tc.targets); err != nil {
				t.Fatal(err)
			}
			for _, dir := range []string{filepath.Dir(a), filepath.Dir(b), filepath.Join(root, "X")} {
				if e := entryFor(t, bd, dir); e.Kind != kindDenyAncestor || e.Access != accessReadDir {
					t.Errorf("ancestor %s = %+v, want READ_DIR only", dir, e)
				}
			}
			for _, s := range []string{a, b} {
				if e := entryFor(t, bd, s); e.Kind != kindDenyTarget || e.Access != 0 {
					t.Errorf("target %s = %+v, want access 0", s, e)
				}
			}
			if e := entryFor(t, bd, filepath.Join(root, "X", "pub")); e.Kind != kindDenySibling || e.Access != accessReadFile {
				t.Errorf("sibling X/pub = %+v, want READ_FILE", e)
			}
		})
	}
}
