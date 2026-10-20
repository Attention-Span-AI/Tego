// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"errors"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/policy/decide"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// compileLanders are compile --test's Landers over Land and LandUnix (internal/cli's landers without their stderr note).
var compileLanders = agent.Landers{Path: Land, Unix: LandUnix}

// landCase is one TestResolveActionFollowsAsTheKernel case: an action, and the action and resolved paths it lands as.
type landCase struct {
	name string
	a    agent.Action
	want agent.Action
	rp   agent.ResolvedPaths
}

// unixCase is a landCase of a connect's or a datagram's unix name p: its name kept, landed at at, the walk having met
// walk.
func unixCase(name string, kind agent.ActionKind, p, at string, walk agent.UnixWalk) landCase {
	c := landCase{name: name, a: agent.Action{Kind: kind, Path: "unix:" + p},
		want: agent.Action{Kind: kind, Path: "unix:" + p, Landed: at, Walk: walk}}
	if at != "" && at != filepath.Clean(p) {
		c.rp.Path = at
	}
	return c
}

// noSocket is a unixCase whose name lands on no socket (Action.NoSocket): a directory, or a file that is not one.
func noSocket(c landCase) landCase {
	c.want.NoSocket = true
	return c
}

// TestResolveActionFollowsAsTheKernel pins compile --test's landing of a row's paths (ADR 0019's 2026-10-17 design
// note): the run's own walk (Land), asked with each syscall's own lookup (agent.ActionKind.Lookups). An open or an exec
// is evaluated on the file a symlink reaches, an unlink, a mkdir or a rename on the link itself in its walked
// directory, a hard link stays itself (its old name looked up whole, unfollowed, so a final "." or ".." is walked),
// and the part of a path that does not exist yet lies where the walk lands once it is made: beneath the
// deepest existing directory, through a dangling symlink to its target (intermediate, or final where the syscall
// follows it), and with ".." after a symlink taken physically. The last three were answered at the link's own
// spelling, or on the lexically cleaned path, where the kernel's walk goes elsewhere (R6-C1 and R6-C2 of both lenses).
//
// Spec: docs/p0/agent-contract.md R15.
func TestResolveActionFollowsAsTheKernel(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	j := func(p ...string) string { return filepath.Join(append([]string{dir}, p...)...) }
	must(os.MkdirAll(j("real", "sub"), 0o755))
	must(os.MkdirAll(j("ro"), 0o755))
	must(os.WriteFile(j("real", "f"), nil, 0o755))
	must(os.Symlink(j("real", "f"), j("lnk")))
	must(os.Symlink(j("real"), j("dl")))
	must(os.Link(j("real", "f"), j("hl")))
	must(os.Symlink("real/later", j("dang")))  // a dangling link to a directory the agent makes later
	must(os.Symlink("../made", j("ro", "dl"))) // a dangling final link an O_CREAT open follows
	must(os.Symlink("real/sub", j("lk")))      // lk/.. is real, physically; dir, lexically
	must(os.Symlink(j("nowhere", "deep"), j("adang")))
	must(os.Symlink("/proc/self/cwd", j("cw")))              // a magic link
	must(os.Symlink("/proc/self/root"+dir+"/real", j("rt"))) // another, to a directory of this tree
	must(os.Symlink("/proc/self", j("pself")))               // no magic link, but it ends on procfs
	must(os.Symlink("loop", j("loop")))
	must(os.Symlink("real/s.sock", j("dsock")))                       // a dangling final link to a socket made later
	must(os.Symlink("/proc/self/fd", j("fdl")))                       // no magic link: its entries are
	must(os.Symlink("real/gone.sock/", j("tsl")))                     // a dangling final link whose body ends in a slash
	must(unix.Mknod(j("real", "bound.sock"), unix.S_IFSOCK|0o600, 0)) // a socket already there, as a bound one is

	type c = landCase
	read := func(p string) agent.Action { return agent.Action{Kind: agent.ActionFSRead, Path: p} }
	write := func(p string) agent.Action { return agent.Action{Kind: agent.ActionFSWrite, Path: p} }
	rename := func(p, d string) agent.Action { return agent.Action{Kind: agent.ActionFSRename, Path: p, DestPath: d} }
	link := func(p, d string) agent.Action { return agent.Action{Kind: agent.ActionFSLink, Path: p, DestPath: d} }
	cases := []c{
		{"read through a symlink", read(j("lnk")), read(j("real", "f")), agent.ResolvedPaths{Path: j("real", "f")}},
		{"exec through a symlink", agent.Action{Kind: agent.ActionExec, Path: j("lnk")},
			agent.Action{Kind: agent.ActionExec, Path: j("real", "f")}, agent.ResolvedPaths{Path: j("real", "f")}},
		{"exec of a hard link", agent.Action{Kind: agent.ActionExec, Path: j("hl")}, agent.Action{Kind: agent.ActionExec, Path: j("hl")}, agent.ResolvedPaths{}},
		{"delete through a symlinked directory", agent.Action{Kind: agent.ActionFSDelete, Path: j("dl", "f")},
			agent.Action{Kind: agent.ActionFSDelete, Path: j("real", "f")}, agent.ResolvedPaths{Path: j("real", "f")}},
		{"delete of the link itself", agent.Action{Kind: agent.ActionFSDelete, Path: j("lnk")}, agent.Action{Kind: agent.ActionFSDelete, Path: j("lnk")}, agent.ResolvedPaths{}},
		// The part that does not exist yet lies beneath the deepest existing
		// directory as the walk reaches it, a link included.
		{"a missing name in a symlinked directory", write(j("dl", "new")), write(j("real", "new")), agent.ResolvedPaths{Path: j("real", "new")}},
		{"a rename's missing new name in a symlinked directory", rename(j("real", "f"), j("dl", "new")),
			rename(j("real", "f"), j("real", "new")), agent.ResolvedPaths{Dest: j("real", "new")}},
		{"a link's new name two missing levels beneath a symlinked directory", link(j("real", "f"), j("dl", "a", "b", "new")),
			link(j("real", "f"), j("real", "a", "b", "new")), agent.ResolvedPaths{Dest: j("real", "a", "b", "new")}},
		{"a missing path beneath no symlink stays as written", write(j("no", "new")), write(j("no", "new")), agent.ResolvedPaths{}},
		// A dangling intermediate link is followed to the directory the agent makes later.
		{"a rename into a dangling link's target", rename(j("real", "f"), j("dang", "x")),
			rename(j("real", "f"), j("real", "later", "x")), agent.ResolvedPaths{Dest: j("real", "later", "x")}},
		{"a link into a dangling link's target", link(j("real", "f"), j("dang", "y")),
			link(j("real", "f"), j("real", "later", "y")), agent.ResolvedPaths{Dest: j("real", "later", "y")}},
		{"an absolute dangling link", write(j("adang", "x")), write(j("nowhere", "deep", "x")), agent.ResolvedPaths{Path: j("nowhere", "deep", "x")}},
		// R6-C2 (correctness, low): an O_CREAT open follows a dangling final link and creates its target; a rename of
		// the link, or its unlink, acts on the link.
		{"a write through a dangling final link", write(j("ro", "dl")), write(j("made")), agent.ResolvedPaths{Path: j("made")}},
		{"a read through it", read(j("ro", "dl")), read(j("made")), agent.ResolvedPaths{Path: j("made")}},
		{"a delete of the dangling link", agent.Action{Kind: agent.ActionFSDelete, Path: j("ro", "dl")},
			agent.Action{Kind: agent.ActionFSDelete, Path: j("ro", "dl")}, agent.ResolvedPaths{}},
		// R6-C2 (security) and R6-S1: ".." after a symlink is physical, whatever the spelling cleans to.
		{"a rename's new name with .. after a symlink", rename(j("real", "f"), dir+"/lk/../x2"),
			rename(j("real", "f"), j("real", "x2")), agent.ResolvedPaths{Dest: j("real", "x2")}},
		{"a link's new name that cleans to its source", link(j("x"), dir+"/lk/../x"),
			link(j("x"), j("real", "x")), agent.ResolvedPaths{Dest: j("real", "x")}},
		// Design (-3c4-2): a link's source is looked up whole,
		// unfollowed (linkat(2) without AT_SYMLINK_FOLLOW: filename_lookup, not filename_parentat), so a final "." or
		// ".." is where the walk lands; only a name-making end (an unlink, a mkdir, a rename's ends, a link's new name)
		// is refused before a lookup and evaluated as written. compile asked the source as a name-making end and
		// evaluated lk (the symlink itself) and dir (the clean), where the run and the kernel act on real/sub and real.
		{"a link's source ending in /. after a symlink", link(dir+"/lk/.", j("n1")), link(j("real", "sub"), j("n1")),
			agent.ResolvedPaths{Path: j("real", "sub")}},
		{"a link's source ending in /.. after a symlink", link(dir+"/lk/..", j("n2")), link(j("real"), j("n2")),
			agent.ResolvedPaths{Path: j("real")}},
		{"a link's source that is a symlink is the link itself", link(j("lnk"), j("n3")), link(j("lnk"), j("n3")), agent.ResolvedPaths{}},
		{"an attribute change of lk/.. acts where the walk lands", agent.Action{Kind: agent.ActionFSAttr, Path: dir + "/lk/.."},
			agent.Action{Kind: agent.ActionFSAttr, Path: j("real")}, agent.ResolvedPaths{Path: j("real")}},
		{"a delete of lk/. is refused before a lookup, evaluated as written", agent.Action{Kind: agent.ActionFSDelete, Path: dir + "/lk/."},
			agent.Action{Kind: agent.ActionFSDelete, Path: j("lk")}, agent.ResolvedPaths{}},
		{"a name beneath a file", rename(j("real", "f"), j("real", "f", "x")), rename(j("real", "f"), j("real", "f", "x")), agent.ResolvedPaths{}},
		{"a missing directory climbed back out of", write(dir + "/real/new/../../lk/w"), write(j("real", "sub", "w")), agent.ResolvedPaths{Path: j("real", "sub", "w")}},
		{"a missing name under a link, then ..", write(dir + "/dang/../f"), write(j("real", "f")), agent.ResolvedPaths{Path: j("real", "f")}},
		// A name-making end ending in "/" is the name in its
		// directory, never followed (mkdir is EEXIST, rmdir, unlink and a rename onto it ENOTDIR, and Landlock's hooks
		// are asked there). compile took the whole walk, followed the final link, and evaluated where it leads; an
		// open's end with a slash still follows it.
		{"a mkdir of a dangling final link spelled with a slash", agent.Action{Kind: agent.ActionFSMkdir, Path: j("ro", "dl") + "/"},
			agent.Action{Kind: agent.ActionFSMkdir, Path: j("ro", "dl")}, agent.ResolvedPaths{}},
		{"a delete of a directory link spelled with a slash", agent.Action{Kind: agent.ActionFSDelete, Path: dir + "/lk/"},
			agent.Action{Kind: agent.ActionFSDelete, Path: j("lk")}, agent.ResolvedPaths{}},
		{"a rename onto a directory link spelled with a slash", rename(j("real", "sub"), dir+"/lk/"), rename(j("real", "sub"), j("lk")),
			agent.ResolvedPaths{}},
		{"a link's new name through a dangling link spelled with a slash", link(j("real", "f"), dir+"/dang/"), link(j("real", "f"), j("dang")),
			agent.ResolvedPaths{}},
		{"a mkdir of a symlink loop spelled with a slash", agent.Action{Kind: agent.ActionFSMkdir, Path: dir + "/loop/"},
			agent.Action{Kind: agent.ActionFSMkdir, Path: j("loop")}, agent.ResolvedPaths{}},
		{"control, a write through a directory link spelled with a slash follows it", write(dir + "/lk/"), write(j("real", "sub")),
			agent.ResolvedPaths{Path: j("real", "sub")}},
		{"bare command", agent.Action{Kind: agent.ActionExec, Path: "rg"}, agent.Action{Kind: agent.ActionExec, Path: "rg"}, agent.ResolvedPaths{}},
		// A unix connect or datagram keeps the name it passes, the
		// run's first decision, and lands where connect(2) and sendto(2) walk it, the second.
		{"a unix connect through a symlink, to a file that is no socket", agent.Action{Kind: agent.ActionNetConnect, Path: "unix:" + j("lnk")},
			agent.Action{Kind: agent.ActionNetConnect, Path: "unix:" + j("lnk"), Landed: j("real", "f"), NoSocket: true}, agent.ResolvedPaths{Path: j("real", "f")}},
		{"a unix datagram with .. after a symlink", agent.Action{Kind: agent.ActionNetSend, Path: "unix:" + dir + "/lk/../s.sock"},
			agent.Action{Kind: agent.ActionNetSend, Path: "unix:" + dir + "/lk/../s.sock", Landed: j("real", "s.sock")}, agent.ResolvedPaths{Path: j("real", "s.sock")}},
		{"a unix connect to a plain name", agent.Action{Kind: agent.ActionNetConnect, Path: j("real", "s.sock")},
			agent.Action{Kind: agent.ActionNetConnect, Path: j("real", "s.sock"), Landed: j("real", "s.sock")}, agent.ResolvedPaths{}},
		{"an abstract name untouched", agent.Action{Kind: agent.ActionNetConnect, Path: "unix:@" + j("lnk")},
			agent.Action{Kind: agent.ActionNetConnect, Path: "unix:@" + j("lnk")}, agent.ResolvedPaths{}},
		// A unix name is walked as the run's unixWalk walks it,
		// every magic link refused and a landing on procfs refused (path-unreliable), and what that walk met rides on
		// the action. A socket made later is taken as there, through a dangling final link too; a name beneath a file
		// names nothing (ENOTDIR), and a symlink loop is one the run cannot place (ELOOP).
		unixCase("a datagram through a link to /proc/self/cwd", agent.ActionNetSend, j("cw", "s.sock"), "", agent.UnixWalkUnreliable),
		unixCase("a connect through a link to /proc/self/root", agent.ActionNetConnect, j("rt", "s.sock"), "", agent.UnixWalkUnreliable),
		unixCase("a datagram to a procfs file through /proc/self", agent.ActionNetSend, j("pself", "status"), "", agent.UnixWalkUnreliable),
		// What appears on procfs while the agent runs (/proc/<pid>/fd/N, /proc/<pid>,
		// task/<tid>) is a magic link or a procfs directory, and this process's own entries are not the agent's, so a
		// missing part on procfs is refused as a landing there, a climb back out of it too; it was answered as naming
		// nothing, and a name through /proc/self/fd/N read as compile itself held N or not.
		unixCase("a datagram to a missing name beneath /proc/self", agent.ActionNetSend, j("pself", "s.sock"), "", agent.UnixWalkUnreliable),
		unixCase("a connect climbing out of a missing procfs directory", agent.ActionNetConnect, dir+"/pself/x/../../.."+dir+"/real/s.sock",
			"", agent.UnixWalkUnreliable),
		unixCase("a connect to a descriptor the agent opens later", agent.ActionNetConnect, j("fdl", "987"), "", agent.UnixWalkUnreliable),
		unixCase("a datagram to it", agent.ActionNetSend, j("fdl", "987"), "", agent.UnixWalkUnreliable),
		unixCase("a datagram to a descriptor this process holds", agent.ActionNetSend, j("fdl", "0"), "", agent.UnixWalkUnreliable),
		// Design: the agent makes every directory a name's walk needs, a
		// missing name ending in "/" or "/." (in its spelling or a final link's body) and a part the walk goes beneath
		// included, and binds the socket only at a final name nothing needs as a directory. A name that ends on a
		// directory, made or already there, or on a file there that is no socket, lands there with NoSocket, which the
		// run's implicit admit refuses unix-foreign; round 3 answered the first three as naming nothing (ENOTDIR) and the
		// rest as the socket.
		noSocket(unixCase("a datagram to a missing name ending in a slash", agent.ActionNetSend, j("real")+"/new.sock/",
			j("real", "new.sock"), agent.UnixWalkLookup)),
		noSocket(unixCase("a connect to a missing name in a missing directory ending in /.", agent.ActionNetConnect,
			j("real")+"/sub2/new.sock/.", j("real", "sub2", "new.sock"), agent.UnixWalkLookup)),
		noSocket(unixCase("a datagram through a dangling link whose body ends in a slash", agent.ActionNetSend, j("tsl"),
			j("real", "gone.sock"), agent.UnixWalkLookup)),
		noSocket(unixCase("a datagram to a missing directory climbed into and out of", agent.ActionNetSend, j("real")+"/a/b/../",
			j("real", "a"), agent.UnixWalkLookup)),
		noSocket(unixCase("a datagram to a made part the walk went beneath, by its plain name", agent.ActionNetSend,
			j("real")+"/x/y/../../x", j("real", "x"), agent.UnixWalkLookup)),
		noSocket(unixCase("a datagram to a directory already there", agent.ActionNetSend, j("real", "sub"), j("real", "sub"),
			agent.UnixWalkLookup)),
		noSocket(unixCase("a connect to it named with a slash", agent.ActionNetConnect, j("real", "sub")+"/", j("real", "sub"),
			agent.UnixWalkLookup)),
		noSocket(unixCase("a datagram climbing out of a missing part back to it", agent.ActionNetSend, j("real")+"/sub/z/..",
			j("real", "sub"), agent.UnixWalkLookup)),
		noSocket(unixCase("a datagram to a regular file already there", agent.ActionNetSend, j("real", "f"), j("real", "f"),
			agent.UnixWalkLookup)),
		unixCase("control, a socket already there", agent.ActionNetSend, j("real", "bound.sock"), j("real", "bound.sock"),
			agent.UnixWalkLookup),
		unixCase("control, that socket named with a slash names nothing", agent.ActionNetSend, j("real", "bound.sock")+"/", "",
			agent.UnixWalkAbsent),
		unixCase("control, a missing name with no slash", agent.ActionNetSend, j("real")+"/new.sock", j("real", "new.sock"), agent.UnixWalkLookup),
		unixCase("a connect through a symlink loop", agent.ActionNetConnect, j("loop", "s.sock"), "", agent.UnixWalkUnreliable),
		unixCase("a datagram beneath a file", agent.ActionNetSend, j("real", "f", "s.sock"), "", agent.UnixWalkAbsent),
		unixCase("a connect to a dangling final link", agent.ActionNetConnect, j("dsock"), j("real", "s.sock"), agent.UnixWalkLookup),
		unixCase("a datagram to a socket beneath a dangling link", agent.ActionNetSend, j("dang", "s.sock"), j("real", "later", "s.sock"),
			agent.UnixWalkLookup),
		// A bind is walked as the run's bindUnix walks it (FSTarget); one whose walk fails is refused path-unreliable.
		{"a bind beneath a file", agent.Action{Kind: agent.ActionNetBind, Proto: agent.ProtoUnix, Path: "unix:" + j("real", "f", "s.sock")},
			agent.Action{Kind: agent.ActionNetBind, Proto: agent.ProtoUnix, Path: j("real", "f", "s.sock"), Walk: agent.UnixWalkUnreliable},
			agent.ResolvedPaths{}},
		{"a bind through a symlinked directory", agent.Action{Kind: agent.ActionNetBind, Proto: agent.ProtoUnix, Path: "unix:" + j("dl", "s.sock")},
			agent.Action{Kind: agent.ActionNetBind, Proto: agent.ProtoUnix, Path: j("real", "s.sock")}, agent.ResolvedPaths{Path: j("real", "s.sock")}},
	}
	for _, tc := range cases {
		got, rp := agent.ResolveAction(tc.a, compileLanders)
		if got.Path != tc.want.Path || got.DestPath != tc.want.DestPath || got.Landed != tc.want.Landed || got.Walk != tc.want.Walk ||
			got.NoSocket != tc.want.NoSocket || rp != tc.rp {
			t.Errorf("%s: got %q %q landed %q (no socket %v) walk %d %+v, want %q %q landed %q (no socket %v) walk %d %+v", tc.name,
				got.Path, got.DestPath, got.Landed, got.NoSocket, got.Walk, rp, tc.want.Path, tc.want.DestPath, tc.want.Landed,
				tc.want.NoSocket, tc.want.Walk, tc.rp)
		}
	}
}

// TestLandUnixStepwise: a unix name through a final link fs.protected_symlinks refuses to follow (in a sticky
// world-writable directory, owned by neither the follower nor that directory's owner) lands where the run's unixWalk
// lands it only by its own walk a component at a time, so LandUnix answers UnixWalkStepwise, and compile then refuses
// a connect path-unreliable (the relay's errWalkedOnly) and decides a datagram on the socket (no test made LandUnix
// answer Stepwise, so dropping it, or predictUnix's walked, passed every suite). Unprivileged, the follower is
// another uid in predictUnix's facts (landFollowFacts), and
// a socket missing at compile is asked; as root, the link is given another owner and the kernel's own lookup refuses
// it, so a bound socket is asked too, through unixWalk's fallback walk, with the run's own walk held to the same answer.
// The link lies in /tmp, a sticky world-writable directory root owns (TestDeputyWalkFollowsLinksAsTheKernelDoes).
//
// Spec: docs/p0/limits-check-doctor-cli.md R28; docs/p0/supervisor.md R11.
func TestLandUnixStepwise(t *testing.T) {
	var tmp unix.Stat_t
	if err := unix.Stat("/tmp", &tmp); err != nil || tmp.Uid != 0 || tmp.Mode&(unix.S_ISVTX|0o002) != unix.S_ISVTX|0o002 {
		t.Skip("needs a root-owned, sticky, world-writable /tmp")
	}
	// A short directory: the bound socket's name must fit sun_path.
	dir, err := os.MkdirTemp("", "ls")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if dir, err = filepath.EvalSymlinks(dir); err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(dir, "s.sock")
	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	if err := unix.Bind(fd, &unix.SockaddrUnix{Name: sock}); err != nil {
		t.Fatal(err)
	}
	root := os.Geteuid() == 0
	if root {
		// The kernel's refusal this branch asks for is fs.protected_symlinks', which a host or guest may have off (the
		// kernel's own default): turned on for the test, as TestHeldOpenDifferentialAcrossMounts turns it on.
		old, err := os.ReadFile("/proc/sys/fs/protected_symlinks")
		if err != nil {
			t.Skipf("no fs.protected_symlinks: %v", err)
		}
		if err := os.WriteFile("/proc/sys/fs/protected_symlinks", []byte("1"), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.WriteFile("/proc/sys/fs/protected_symlinks", old, 0o644) })
	}
	links := map[string]string{"bound": sock, "missing": filepath.Join(dir, "missing.sock")}
	for name, target := range links {
		link := filepath.Join("/tmp", "tego-land-unix-"+name+"-"+strconv.Itoa(os.Getpid())+"-"+filepath.Base(dir))
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Remove(link) })
		if root {
			// Root's link would be owned by /tmp's owner, which may_follow_link lets anyone follow: give it another owner.
			if err := os.Lchown(link, 65534, 65534); err != nil {
				t.Fatal(err)
			}
		}
		links[name] = link
	}
	var lst unix.Stat_t
	if err := unix.Lstat(links["missing"], &lst); err != nil {
		t.Fatal(err)
	}
	// The kernel's lookup refuses root the link; unprivileged, this process owns it, so its walk is held to another
	// follower's facts: the answer the kernel gives that follower.
	if !root {
		other := lst.Uid + 4242
		landFollowFacts = func() *followFacts { return &followFacts{fsuid: other, protected: true} }
		t.Cleanup(func() { landFollowFacts = currentFollowFacts })
	}
	rt := &agent.RuleTable{Tier: backend.TierLandlock, FS: []agent.FSRule{{Kind: agent.FSWrite, Path: "/", Raw: "/", Resolved: "/",
		Access: agent.AccessWriteSet}}}
	cases := []struct{ link, at string }{{links["missing"], filepath.Join(dir, "missing.sock")}}
	if root {
		cases = append(cases, struct{ link, at string }{links["bound"], sock})
		if at, walked, err := runUnixWalk(links["bound"]); err != nil || at != sock || !walked {
			t.Errorf("the run's unix walk of the bound socket's link: %q walked %t, %v; want %q walked", at, walked, err, sock)
		}
	}
	for _, c := range cases {
		if l, err := LandUnix(c.link); err != nil || l.At != c.at || l.Walk != agent.UnixWalkStepwise {
			t.Errorf("LandUnix(%s) = %+v, %v; want %q, walk %d (Stepwise)", c.link, l, err, c.at, agent.UnixWalkStepwise)
		}
		for kind, want := range map[agent.ActionKind]string{agent.ActionNetConnect: "refused " + rulePathUnreliable,
			agent.ActionNetSend: "allow fs.write[/]"} {
			a, _ := agent.ResolveAction(agent.Action{Kind: kind, Path: "unix:" + c.link}, compileLanders)
			if res := decide.Evaluate(rt, a, backend.TierLandlock); string(res.Verdict)+" "+res.Rule != want {
				t.Errorf("%s %s: %s %s, want %s", kind, c.link, res.Verdict, res.Rule, want)
			}
		}
	}
	// Control: followed by its owner, the link is the kernel's to follow, and the landing a lookup's.
	if !root {
		landFollowFacts = currentFollowFacts
		if l, err := LandUnix(links["missing"]); err != nil || l.Walk != agent.UnixWalkLookup || l.At != filepath.Join(dir, "missing.sock") {
			t.Errorf("control, its owner follows: LandUnix = %+v, %v; want a lookup", l, err)
		}
	}
}

// TestLandRefusesAsTheKernel: a walk that fails as the task's own lookup fails answers its errno, the kernel's limit of
// 40 symlinks included, and a relative path is not a question Land takes.
//
// Spec: docs/p0/agent-contract.md R15.
func TestLandRefusesAsTheKernel(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "f"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	for _, l := range [][2]string{{"loop1", "loop2"}, {"loop2", "loop1"}} {
		if err := os.Symlink(l[1], filepath.Join(dir, l[0])); err != nil {
			t.Fatal(err)
		}
	}
	// c0 -> c1 -> ... -> c40 -> f: 41 links to follow from c0, 40 from c1.
	for i := 0; i <= 40; i++ {
		target := "c" + strconv.Itoa(i+1)
		if i == 40 {
			target = "f"
		}
		if err := os.Symlink(target, filepath.Join(dir, "c"+strconv.Itoa(i))); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		p    string
		how  agent.Lookup
		want error
		at   string
	}{
		{dir + "/f/x", agent.LookupParent, unix.ENOTDIR, ""},
		{dir + "/f/x", agent.LookupNoFollow, unix.ENOTDIR, ""},
		{dir + "/loop1/x", agent.LookupParent, unix.ELOOP, ""},
		{dir + "/loop1", agent.LookupFollow, unix.ELOOP, ""},
		{dir + "/loop1", agent.LookupCreate, unix.ELOOP, ""},
		{dir + "/loop1", agent.LookupParent, nil, dir + "/loop1"},
		{dir + "/loop1", agent.LookupNoFollow, nil, dir + "/loop1"},
		{dir + "/c0", agent.LookupFollow, unix.ELOOP, ""},
		{dir + "/c1", agent.LookupFollow, nil, dir + "/f"},
		// A name-making end refuses a final ".." before a lookup; an unfollowed whole lookup walks it, and c1 leads to
		// the file f, above which nothing lies.
		{dir + "/c1/..", agent.LookupParent, unix.EINVAL, ""},
		{dir + "/c1/..", agent.LookupNoFollow, unix.ENOTDIR, ""},
		{"rel/x", agent.LookupFollow, unix.EINVAL, ""},
	} {
		at, err := Land(tc.p, tc.how)
		if !errors.Is(err, tc.want) || (tc.want == nil && err != nil) || at != tc.at {
			t.Errorf("Land(%q, %v) = %q, %v; want %q, %v", tc.p, tc.how, at, err, tc.at, tc.want)
		}
	}
}

// landTree is a generated tree: directories, files and symlinks beneath a root, each link's target as written (an
// absolute one relative to the root, prefixed with it when built).
type landTree struct {
	dirs, files []string
	links       [][3]string // name, target, "abs" when the target is the root's
	// sock is a socket already there in a unix row's tree, at a name the others may have taken (then none is made).
	sock string
}

// buildSocket makes tr's socket beneath root: a socket inode, as a bind leaves one (mknod(2) makes it unprivileged).
func (tr landTree) buildSocket(root string) {
	_ = unix.Mknod(filepath.Join(root, tr.sock), unix.S_IFSOCK|0o600, 0)
}

func (tr landTree) build(t *testing.T, root string) {
	t.Helper()
	for _, d := range tr.dirs {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range tr.files {
		_ = os.WriteFile(filepath.Join(root, f), nil, 0o644) // a name under a file fails, as generated
	}
	for _, l := range tr.links {
		target := l[1]
		if l[2] == "abs" {
			target = root + "/" + target
		}
		_ = os.Symlink(target, filepath.Join(root, l[0]))
	}
}

// genLandTree makes a small tree over the names a, b and c, with links whose targets climb, dangle and loop.
func genLandTree(r *rand.Rand) landTree {
	names := []string{"a", "b", "c"}
	tr := landTree{dirs: []string{"a"}}
	parents := []string{"", "a"}
	for i := 0; i < 7; i++ {
		parent := parents[r.Intn(len(parents))]
		name := filepath.Join(parent, names[r.Intn(len(names))])
		switch k := r.Intn(10); {
		case k < 3:
			tr.dirs = append(tr.dirs, name)
			parents = append(parents, name)
		case k < 5:
			tr.files = append(tr.files, name)
		default:
			n := 1 + r.Intn(3)
			comps := make([]string, n)
			for i := range comps {
				comps[i] = []string{"a", "b", "c", "m", "..", "."}[r.Intn(6)]
			}
			abs := ""
			if r.Intn(5) == 0 {
				abs = "abs"
			}
			body := strings.Join(comps, "/")
			if r.Intn(4) == 0 {
				body += "/" // a final link's body ending in "/" is the name's own trailing slash
			}
			tr.links = append(tr.links, [3]string{name, body, abs})
		}
	}
	tr.sock = filepath.Join(parents[r.Intn(len(parents))], names[r.Intn(len(names))])
	return tr
}

// materialize makes, through the kernel, every directory the walk of the spelled path p passes through that does not
// exist yet, a dangling link's target included, as an agent would make them later: each prefix of p is looked up by the
// kernel as written and made with mkdir(2) when missing, so ".." and every link are the kernel's.
func materialize(p string, depth int, jail string) error {
	if depth > 40 {
		return unix.ELOOP
	}
	comps := strings.Split(strings.TrimPrefix(p, "/"), "/")
	for i := 1; i <= len(comps); i++ {
		pre := "/" + strings.Join(comps[:i], "/")
		fd, err := unix.Open(pre, unix.O_PATH|unix.O_CLOEXEC, 0)
		if err == nil {
			_ = unix.Close(fd)
			continue
		}
		if !errors.Is(err, unix.ENOENT) {
			return err
		}
		var st unix.Stat_t
		if unix.Lstat(pre, &st) == nil && st.Mode&unix.S_IFMT == unix.S_IFLNK {
			target, err := os.Readlink(pre)
			if err != nil || target == "" {
				return unix.ENOENT
			}
			if !strings.HasPrefix(target, "/") {
				target = "/" + strings.Join(comps[:i-1], "/") + "/" + target
			}
			if err := materialize(target, depth+1, jail); err != nil {
				return err
			}
			continue
		}
		// The directory pre is made in, as the kernel walks it: path.Dir would clean "lk/.." away lexically.
		if !inJail("/"+strings.Join(comps[:i-1], "/"), jail) {
			return errUnmakeable
		}
		if err := unix.Mkdir(pre, 0o755); err != nil && !errors.Is(err, unix.EEXIST) {
			return fmt.Errorf("%w: %w", errUnmakeable, err)
		}
	}
	return nil
}

// errUnmakeable is materialize's answer for a directory it would make outside the test's own tree, or one it cannot
// make there; every other error it returns is a lookup the kernel's walk fails at, before anything is to be made.
var errUnmakeable = errors.New("the walk leaves the test's tree, or what it needs cannot be made there")

// inJail reports whether the directory dir, as the kernel's walk reaches it, lies inside jail: materialize makes
// nothing elsewhere, whatever a generated link or a magic one leads to.
func inJail(dir, jail string) bool {
	fd, err := unix.Open(dir, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return false
	}
	defer unix.Close(fd) //nolint:errcheck // an O_PATH descriptor this test opened
	at, err := os.Readlink("/proc/self/fd/" + strconv.Itoa(fd))
	return err == nil && (at == jail || strings.HasPrefix(at, jail+"/"))
}

// kernelLanding is where the kernel itself lands p for kind: for an fs.write the file an O_CREAT open makes or opens,
// for an fs.read what an O_PATH open reaches, for a link's old name (nofollow) what an O_PATH|O_NOFOLLOW open reaches
// (path_lookupat without LOOKUP_FOLLOW: a final "." or ".." physical, a final symlink itself, a missing final name in
// its directory), for an end a syscall makes or removes (end) its parent opened as a directory, with the final name.
// Each answer is the descriptor's /proc link.
func kernelLanding(p, kind string) (string, error) {
	link := func(fd int) (string, error) {
		defer unix.Close(fd) //nolint:errcheck // an O_PATH descriptor this test opened
		return os.Readlink("/proc/self/fd/" + strconv.Itoa(fd))
	}
	switch kind {
	case "write":
		fd, err := unix.Open(p, unix.O_WRONLY|unix.O_CREAT|unix.O_CLOEXEC, 0o644)
		if errors.Is(err, unix.EISDIR) {
			fd, err = unix.Open(p, unix.O_PATH|unix.O_CLOEXEC, 0)
		}
		if err != nil {
			return "", err
		}
		return link(fd)
	case "read":
		fd, err := unix.Open(p, unix.O_PATH|unix.O_CLOEXEC, 0)
		if err != nil {
			return "", err
		}
		return link(fd)
	}
	dir, base := splitFinal(p)
	if kind == "nofollow" && (base == "." || base == ".." || strings.HasSuffix(p, "/")) {
		// path_lookupat walks a final "." or ".." physically, and a trailing slash has it follow a final symlink and
		// need a directory, O_NOFOLLOW or not.
		fd, err := unix.Open(p, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return "", err
		}
		return link(fd)
	}
	if base == "." || base == ".." {
		return "", unix.EINVAL
	}
	// An end a syscall makes or removes is the name in its directory, a trailing slash or not: filename_parentat strips
	// it, and the name is looked up there unfollowed.
	fd, err := unix.Open(dir, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return "", err
	}
	at, err := link(fd)
	return filepath.Join(at, base), err
}

// TestCompileLandsWhereTheRunLands is the property: over generated trees, the place compile
// --test evaluates a row's path on (RunResolved with Land, asked of the tree before the agent runs) is the place the
// kernel lands the agent's own syscall once the directories the path passes through exist (materialize), and the
// supervisor's walk of that syscall's query lands it there too. A row the kernel refuses to walk (ENOTDIR, ELOOP,
// EINVAL) is one compile could not land either, so compile and the run's line both answer its spelling. A connect's or
// a datagram's unix name is held to the run's verdict, not only its landing (unixRowHeld; design, where a name that
// can only end on a directory read allow because the landing alone was compared): every row, landed or not, on a
// socket or not, gets the verdict the run's own decision code gives
// once the tree is the one compile answers for. Each row gets a fresh copy of its tree, built beneath a jail of
// directories, so what one row makes no other row sees.
//
// Spec: docs/p0/agent-contract.md R15; docs/p0/limits-check-doctor-cli.md R28.
func TestCompileLandsWhereTheRunLands(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	r := rand.New(rand.NewSource(20261017))
	// slashes draws which filesystem rows end in "/" from a stream of its own, so the trees and rows r draws stay the ones
	// the rows without a slash were held to.
	slashes := rand.New(rand.NewSource(20261019))
	// Each filesystem row's end is asked of compile and of the run's walk with the one Lookup the row's kind gives it
	// (agent.ActionKind.Lookups, pathQuery.as; TestEveryRowEndIsWalkedAsItsSyscall holds the run's handlers to it), and
	// the kernel's own landing for that lookup is the truth (kernelLanding). The rows cover every lookup: the run's
	// queries were written out here by hand and drifted from the handlers', and fs.link's old name, the one end looked up
	// whole and unfollowed, was not asked at all (design).
	truthOf := map[agent.Lookup]string{agent.LookupFollow: "read", agent.LookupCreate: "write", agent.LookupNoFollow: "nofollow",
		agent.LookupParent: "end"}
	type rowKind struct {
		kind, action string
		how          agent.Lookup // the lookup of the end the row asks: its path's, or a rename's new name's
	}
	var kinds []rowKind
	for _, k := range []struct {
		action string
		ak     agent.ActionKind
	}{
		{"fs.read", agent.ActionFSRead}, {"fs.write", agent.ActionFSWrite}, {"fs.delete", agent.ActionFSDelete},
		{"fs.rename", agent.ActionFSRename}, {"fs.link", agent.ActionFSLink}, {"fs.attr", agent.ActionFSAttr},
		{"fs.mkdir", agent.ActionFSMkdir},
	} {
		how, dest := k.ak.Lookups()
		if k.ak == agent.ActionFSRename {
			how = dest
		}
		kinds = append(kinds, rowKind{truthOf[how], k.action, how})
	}
	// A datagram's and a connect's name: compile lands it with LandUnix in
	// Action.Landed and Action.Walk, and the run walks it with unixWalk, not FSTarget (decideLanded, the relay's
	// connectUnixAs). They are asked as often as the filesystem rows together.
	for range 3 {
		kinds = append(kinds, rowKind{kind: "unix", action: "net.send"}, rowKind{kind: "unix", action: "net.connect"})
	}
	rows, landed, unixHeld, unixNoSocket, unixRefused, slashLinks := 0, 0, 0, 0, 0, 0
	for tree := 0; tree < 120; tree++ {
		tr := genLandTree(r)
		for row := 0; row < 8; row++ {
			n := 1 + r.Intn(5)
			comps := make([]string, n)
			for i := range comps {
				comps[i] = []string{"a", "b", "c", "m", "n", "..", "."}[r.Intn(7)]
			}
			spell := strings.Join(comps, "/")
			k := kinds[r.Intn(len(kinds))]
			if k.kind != "unix" && slashes.Intn(5) == 0 {
				// A fifth of the filesystem rows end in "/": path_lookupat then follows a final symlink and needs a
				// directory, while an end a syscall makes or removes is still the name in its directory, unfollowed
				// (no fs row had one, and compile followed it).
				// Half of them name one of the tree's links, live, dangling or looping, with ".." before it now and then.
				if len(tr.links) > 0 && slashes.Intn(2) == 0 {
					spell = tr.links[slashes.Intn(len(tr.links))][0]
					if slashes.Intn(3) == 0 {
						spell = "a/../" + spell
					}
				}
				spell += "/"
			}
			root := fmt.Sprintf("%s/t%d-%d/j1/j2/j3/j4/j5/j6/j7/j8/w", base, tree, row)
			if err := os.MkdirAll(root, 0o755); err != nil {
				t.Fatal(err)
			}
			tr.build(t, root)
			p := root + "/" + spell
			src := "version: 0\ntests:\n  - {action: " + k.action + ", path: " + strconv.Quote(spell) + ", expect: allow}\n"
			switch k.action {
			case "fs.rename":
				// The row's path is its new name; its source is a file that exists.
				if err := os.WriteFile(root+"/src", nil, 0o644); err != nil {
					t.Fatal(err)
				}
				src = "version: 0\ntests:\n  - {action: fs.rename, path: src, dest: " + strconv.Quote(spell) + ", expect: allow}\n"
			case "fs.link":
				// The row's path is the link's old name; its new name is one that names nothing.
				src = "version: 0\ntests:\n  - {action: fs.link, path: " + strconv.Quote(spell) + ", dest: newname, expect: allow}\n"
			}
			if k.kind == "unix" {
				// A quarter of the unix names end in "/", which only a directory takes.
				if r.Intn(4) == 0 {
					spell += "/"
					p += "/"
				}
				// A relative name, which the row joins to cwd as the run joins a sun_path to the agent's.
				src = "version: 0\ntests:\n  - {action: " + k.action + ", path: " + strconv.Quote("unix:"+spell) + ", expect: allow}\n"
				tr.buildSocket(root)
				// Half the unix rows' trees also hold a link whose walk the run cannot place in its own view: a magic link
				// back into this tree, and procfs's own "self".
				if r.Intn(2) == 0 {
					_ = os.Symlink("/proc/self/root"+root+"/a", root+"/m")
					_ = os.Symlink("/proc/self", root+"/n")
				}
			}
			table, ds, err := agent.LoadTestTableBytes("t.yaml", []byte(src))
			if err != nil {
				t.Fatalf("%s: %v %v", spell, err, ds)
			}
			var compiled agent.Action
			eval := func(_ *agent.RuleTable, a agent.Action, _ backend.Tier) agent.EvalResult {
				compiled = a
				return agent.EvalResult{Verdict: agent.VerdictAllow}
			}
			table.RunResolved(eval, &agent.RuleTable{Tier: backend.TierLandlock}, root, compileLanders, backend.TierLandlock)
			rows++
			if k.kind == "unix" {
				// The name stays the row's, spelled as the agent passes it; what its walk met rides beside it.
				if compiled.Path != "unix:"+p {
					t.Errorf("%s %q: the name was evaluated as %q, want %q", k.action, spell, compiled.Path, "unix:"+p)
					continue
				}
				if land, err := LandUnix(p); err != nil || land.At != compiled.Landed || land.Walk != compiled.Walk ||
					land.NoSocket != compiled.NoSocket {
					t.Errorf("%s %q: compile landed %q (walk %d, no socket %v), LandUnix %+v, %v", k.action, spell, compiled.Landed,
						compiled.Walk, compiled.NoSocket, land, err)
					continue
				}
				switch held := unixRowHeld(t, k.action, spell, p, base, root, compiled); {
				case !held:
				case compiled.Landed == "":
					unixRefused++
				case compiled.NoSocket:
					unixNoSocket++
				default:
					unixHeld++
				}
				continue
			}
			got, spelled := compiled.Path, filepath.Clean(p)
			if k.action == "fs.rename" {
				got = compiled.DestPath
			}
			walk := k.kind
			_, landErr := Land(p, k.how)
			if landErr != nil {
				// Not landed: compile evaluates the spelling, as the run's line does when its walk fails as the task's
				// lookup fails; the kernel refuses the syscall's walk too.
				if got != spelled {
					t.Errorf("%s %q: Land failed (%v) but compile evaluated %q", k.action, spell, landErr, got)
				}
				if _, err := kernelLanding(p, walk); err == nil && !errors.Is(landErr, unix.EINVAL) {
					t.Errorf("%s %q: Land failed (%v) where the kernel lands it", k.action, spell, landErr)
				}
				continue
			}
			if !strings.HasPrefix(got, root+"/") && got != root {
				continue // the walk climbed out of this row's jail: nothing is made there
			}
			mat := p
			if d, base := splitFinal(p); k.kind == "end" || (k.kind == "nofollow" && base != "." && base != ".." && !strings.HasSuffix(p, "/")) {
				mat = d // the final name is made or linked in its directory; what is missing there names nothing yet
			}
			if err := materialize(mat, 0, base); err != nil {
				t.Errorf("%s %q: compile landed %q, but the path cannot be made: %v", k.action, spell, got, err)
				continue
			}
			if walk == "read" || walk == "write" {
				// A dangling final link: the kernel's O_CREAT open makes its target if the target's directory exists.
				if target, err := os.Readlink(p); err == nil {
					if !strings.HasPrefix(target, "/") {
						d, _ := splitFinal(p)
						target = d + "/" + target
					}
					d, _ := splitFinal(target)
					if err := materialize(d, 1, base); err != nil {
						continue
					}
				}
			}
			kind := walk
			if kind == "read" {
				kind = "write" // a file the agent reads exists by then: make it as an O_CREAT open would
			}
			truth, err := kernelLanding(p, kind)
			if err != nil {
				t.Errorf("%s %q: compile landed %q, the kernel then refuses the walk: %v", k.action, spell, got, err)
				continue
			}
			landed++
			if st, err := os.Lstat(truth); k.kind == "end" && strings.HasSuffix(p, "/") && err == nil && st.Mode()&os.ModeSymlink != 0 {
				slashLinks++ // a name-making end with a slash on a symlink: the case compile followed
			}
			if got != truth {
				t.Errorf("%s %q in %+v: compile landed %q, the kernel lands %q", k.action, spell, tr, got, truth)
			}
			q := pathQuery{tid: os.Getpid(), dirfd: atFDCWD, path: p, joined: cleanPath(p)}.as(k.how)
			if at, err := (sysKernel{}).FSTarget(q); err != nil || at.at != truth {
				t.Errorf("%s %q: the run's walk lands %q, %v; the kernel %q", k.action, spell, at.at, err, truth)
			}
		}
	}
	if landed < rows/3 {
		t.Errorf("only %d of %d rows landed: the generator is not exercising the walk", landed, rows)
	}
	if slashLinks < rows/100 {
		t.Errorf("only %d of %d rows were name-making ends ending in a slash that landed on a symlink: the generator is not "+
			"exercising that case", slashLinks, rows)
	}
	if unixHeld < rows/20 || unixNoSocket < rows/40 || unixRefused < rows/40 {
		t.Errorf("of %d rows only %d unix names on a socket, %d on no socket and %d the walk fails at were held to the run",
			rows, unixHeld, unixNoSocket, unixRefused)
	}
	t.Logf("%d rows, %d filesystem paths landed and held to the kernel (%d name-making ends with a slash on a symlink); "+
		"unix names held to the run's verdict: %d on a socket, %d on no socket, %d its walk fails at", rows, landed, slashLinks,
		unixHeld, unixNoSocket, unixRefused)
}

// runUnixWalk is the run's own walk of the absolute unix name p, as UnixTarget and connectUnixAs make it for a task of
// this process: unixWalk, then unixPlaceOf.
func runUnixWalk(p string) (at string, walked bool, err error) {
	task, err := openTaskView(os.Getpid(), false)
	if err != nil {
		return "", false, err
	}
	defer unix.Close(task.root) //nolint:errcheck // an O_PATH descriptor openTaskView opened
	fd, walked, err := unixWalk(task, unixQuery{tid: task.tid, path: p})
	if err != nil {
		return "", false, err
	}
	defer unix.Close(fd) //nolint:errcheck // an O_PATH descriptor unixWalk opened
	place, err := unixPlaceOf(fd)
	return place.at, walked, err
}

// unixRowHeld holds a connect's or a datagram's row to the run (ADR 0019's design note): compile's verdict,
// decide.Evaluate of the action compile landed before the
// agent ran, is the verdict the run's own decision code gives once the tree is the one compile answers for
// (materializeUnix: every directory the name's walk needs made, and the socket the agent binds at a final name that
// names nothing yet and that nothing needs as a directory), over one contract (unixOracleTable), with R11a's question
// (boundByRun) answered as compile's premise answers it: a socket there is the run's, anything else is not. The run's
// code is decideUnix's name decision, then for a datagram decideLanded's walk and decision (UnixTarget, landedVerdict)
// and for a connect the relay's (connectUnixAs, unixAdmit, unixConnectLine). Where compile landed the name, the kernel's
// own lookup lands it there too, on a socket exactly when compile said it would. It reports whether the row was held: a
// name whose tree cannot be made (on procfs, outside the test's tree) is not.
func unixRowHeld(t *testing.T, action, spell, p, base, root string, compiled agent.Action) bool {
	t.Helper()
	rt := unixOracleTable(root)
	res := decide.Evaluate(rt, compiled, backend.TierLandlock)
	if err := materializeUnix(p, 0, base); err != nil {
		return false
	}
	c := compile(&Policy{Rules: rt})
	for i := range c.unix {
		c.unix[i].resolved = rt.Net[i].UnixResolved // resolved at the run's start, before the agent made anything
	}
	sockets := socketsIn(root)
	bound := func(f unixFile, dec verdictOf) verdictOf {
		if sockets[f.id()] {
			return dec
		}
		return refuse(ruleUnixForeign)
	}
	named := c.decideUnixName(cleanPath(p), nil) // unixOracleTable declares no net.ask unix: scope
	run := named
	switch {
	case !named.allowed:
	case action == "net.send":
		place, err := sysKernel{}.UnixTarget(unixQuery{tid: os.Getpid(), path: p})
		run = c.landedVerdict(place, err, bound)
	default:
		run = runConnect(t, c, named, p, bound)
	}
	line := "refused " + run.rule
	if run.allowed {
		line = "allow " + run.rule
	}
	if got := string(res.Verdict) + " " + res.Rule; got != line {
		t.Errorf("%s %q: compile answers %s (landed %q, walk %d, no socket %v), the run %s", action, spell, got, compiled.Landed,
			compiled.Walk, compiled.NoSocket, line)
	}
	if compiled.Landed == "" {
		return true
	}
	fd, err := unix.Open(p, unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Errorf("%s %q: compile landed %q, the kernel's lookup then fails: %v", action, spell, compiled.Landed, err)
		return true
	}
	defer unix.Close(fd) //nolint:errcheck // an O_PATH descriptor this test opened
	truth, _ := os.Readlink("/proc/self/fd/" + strconv.Itoa(fd))
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || truth != compiled.Landed || (st.Mode&unix.S_IFMT == unix.S_IFSOCK) == compiled.NoSocket {
		t.Errorf("%s %q: compile landed %q (no socket %v), the kernel %q (mode %o)", action, spell, compiled.Landed,
			compiled.NoSocket, truth, st.Mode&unix.S_IFMT)
	}
	if at, walked, err := runUnixWalk(p); err != nil || at != truth || walked != (compiled.Walk == agent.UnixWalkStepwise) {
		t.Errorf("%s %q: the run's unix walk lands %q (walked %t), %v; the kernel %q, compile's walk %d", action, spell, at,
			walked, err, truth, compiled.Walk)
	}
	return true
}

// unixOracleTable is the contract unixRowHeld decides a unix row of root's tree against, compile's decision core and the
// run's alike: a write entry at root, a deny_read entry at its b, which leaves the names beneath it to no write entry,
// and a unix: entry declared at its a/b, each resolved as compile and the run resolve them at start (resolveDeclared).
func unixOracleTable(root string) *agent.RuleTable {
	deny, declared := root+"/b", root+"/a/b"
	placed, _ := resolveUnixDeclared(sysKernel{}, declared) // the run's own placement of a unix: entry (R11)
	return &agent.RuleTable{Tier: backend.TierLandlock,
		FS: []agent.FSRule{
			{Kind: agent.FSWrite, Path: root, Raw: root, Resolved: root, Access: agent.AccessWriteSet},
			{Kind: agent.FSDenyRead, Path: deny, Raw: deny, Resolved: resolveDeclared(sysKernel{}, deny)},
		},
		Net: []agent.NetRule{{Proto: agent.ProtoUnix, Raw: "unix:" + declared, UnixPath: declared,
			UnixResolved: placed, Verdict: agent.VerdictAllow}},
	}
}

// materializeUnix makes the tree compile answers a unix name p for: every directory its walk needs that does not exist
// yet (materialize: one the name passes through, its final part when the name ends in "/", "." or ".."), and, where its
// final name names nothing yet, the socket the agent binds there (a socket inode, as bind(2) leaves one). A dangling
// final link is followed to its target, as connect(2) and sendto(2) follow it. A walk that fails as the agent's own
// lookup fails (beneath a file, a symlink loop) makes nothing more: the run's walk fails there too. err is
// errUnmakeable, wrapped, for a tree it cannot make.
func materializeUnix(p string, depth int, jail string) error {
	if depth > 40 {
		return nil // the kernel's limit: the run's walk fails ELOOP, with nothing to make
	}
	if strings.HasSuffix(p, "/") || finalDot(p) || strings.HasSuffix(p, "/..") || p == ".." {
		return lookupFails(materialize(p, 0, jail))
	}
	dir, _ := splitFinal(p)
	if err := lookupFails(materialize(dir, 0, jail)); err != nil {
		return err
	}
	fd, err := unix.Open(p, unix.O_PATH|unix.O_CLOEXEC, 0)
	if err == nil {
		_ = unix.Close(fd)
		return nil
	}
	if !errors.Is(err, unix.ENOENT) {
		return nil
	}
	var st unix.Stat_t
	switch err := unix.Lstat(p, &st); {
	case err != nil:
	case st.Mode&unix.S_IFMT == unix.S_IFLNK:
		target, err := os.Readlink(p)
		if err != nil || target == "" {
			return nil
		}
		if !strings.HasPrefix(target, "/") {
			target = dir + "/" + target
		}
		return materializeUnix(target, depth+1, jail)
	default:
		return nil // a part of the name is a file whose lookup fails ENOENT: nothing to make
	}
	if !inJail(dir, jail) {
		return errUnmakeable
	}
	if err := unix.Mknod(p, unix.S_IFSOCK|0o600, 0); err != nil {
		return fmt.Errorf("%w: %w", errUnmakeable, err)
	}
	return nil
}

// lookupFails is materialize's answer with a lookup the kernel's walk fails at taken as nothing to make.
func lookupFails(err error) error {
	if errors.Is(err, errUnmakeable) {
		return err
	}
	return nil
}

// socketsIn is the identity of every socket inode beneath root: what compile's premise takes as the run's own.
func socketsIn(root string) map[fileID]bool {
	ids := map[fileID]bool{}
	_ = filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		var st unix.Stat_t
		if err == nil && d.Type()&os.ModeSocket != 0 && unix.Lstat(p, &st) == nil {
			ids[fileID{dev: st.Dev, ino: st.Ino}] = true
		}
		return nil // an entry the walk cannot read holds no socket of the test's
	})
	return ids
}

// runConnect is the line a relayed connect to the absolute unix name p gets, from the relay's own code for a task of
// this process: connectUnixAs's walk and connect, decided by unixAdmit with bound, the line by unixConnectLine.
func runConnect(t *testing.T, c *compiled, named verdictOf, p string, bound func(unixFile, verdictOf) verdictOf) verdictOf {
	t.Helper()
	task, err := openTaskView(os.Getpid(), false)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(task.root) //nolint:errcheck // an O_PATH descriptor openTaskView opened
	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd) //nolint:errcheck // a socket this test made
	var decided verdictOf
	o, _ := unixAs(task, nil, p, func(resolved string, file unixFile) bool {
		decided = c.unixAdmit(named, resolved, file, bound)
		return decided.allowed
	}, func(to []byte) error { return connectRaw(fd, to) })
	return unixConnectLine(o, named, decided)
}
