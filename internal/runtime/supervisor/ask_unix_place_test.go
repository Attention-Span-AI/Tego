// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"context"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/runtime/ask"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// placeLoop builds a loop over f, once the test has filled the fake's view of the filesystem as it stands when the
// loop is built, with the write entry write (/work when nil) and a net.ask unix: scope declared at each of scopes,
// whose asks a person answers with answer; the requests asked are kept in asked.
func placeLoop(t *testing.T, f *fakeKernel, write []agent.FSRule, answer ask.Decision, scopes ...string) (*Loop, *testSink, *[]ask.Request) {
	t.Helper()
	if write == nil {
		write = []agent.FSRule{{Path: "/work", Raw: "/work/", Kind: agent.FSWrite, Resolved: "/work"}}
	}
	pol := testPolicy(nil, write, nil)
	for _, s := range scopes {
		r := unixRuleOf("unix:"+s, s, false)
		r.Verdict = agent.VerdictAsk
		pol.Rules.NetAsk = append(pol.Rules.NetAsk, r)
	}
	pol.Rules.AskConfig = &agent.AskConfig{Hold: agent.AskHoldConnect, Timeout: agent.Duration(time.Second), MaxPending: 4}
	l, sink := newTestLoop(t, f, pol)
	asked := new([]ask.Request)
	l.ask = func(_ context.Context, r ask.Request) (ask.Decision, error) {
		*asked = append(*asked, r)
		return answer, nil
	}
	return l, sink, asked
}

// placeConnect is one stream connect of the run to p, the answer it got and the line it wrote.
func placeConnect(t *testing.T, f *fakeKernel, l *Loop, sink *testSink, p string) (sysResp, *record.Event) {
	t.Helper()
	sa := sockaddrUn(p)
	before := len(sink.all())
	at := 0x40000 + uint64(before)*0x200 // the fake reads the first region mapped at an address: one per connect
	f.put(at, sa)
	l.handle(notifFor(connectNR(), 4242, 5, at, uint64(len(sa))))
	r, _ := f.lastResp()
	evs := sink.all()
	if len(evs) != before+1 {
		t.Fatalf("connect to %s wrote %d lines, want one", p, len(evs)-before)
	}
	return r, evs[before]
}

func newPlaceFake() *fakeKernel {
	f := newFake()
	f.sockDomain = unix.AF_UNIX
	f.sockType = unix.SOCK_STREAM
	return f
}

// TestAskUnixScopeIsThePlaceTheNameReaches is R11c's model (ADR 0008's note of 2026-10-19): a net.ask unix: scope is
// the place its path resolved to, and a connect is the scope's when the name it
// passes reaches that place in the task's view — by the scope's own spelling, a relative one, a symlink or a symlinked
// directory — whoever bound the socket there, the run included: it is asked, never admitted by the write entry around
// it. A name that reaches another place is decided as every unix connect is (R11, R11a), on the socket it reaches
// there: the run's own socket, also one it bound at the scope's place and then linked or renamed elsewhere, is admitted
// by the write entry, as a fresh socket it bound there would be; a socket outside the run, one at a scope's place
// included, is refused unix-foreign under every other name. A datagram, which nobody is asked about (ASK-UDP), is
// refused unix-ask-scope at a scope's place and decided the same way elsewhere. Before, the scope was matched by the
// spelling the task passed, a relative name in a project reached through a symlink was refused with nobody asked,
// and the run's own socket was tracked across its renames and links, which only a trap on every rename and link
// could do.
func TestAskUnixScopeIsThePlaceTheNameReaches(t *testing.T) {
	const scope, ext, other = "/work/app.sock", "/work/ext.sock", "/work/other.sock"
	const writeRule = "fs.write[/work/]"
	for _, tc := range []struct {
		name      string
		path      string
		dgram     bool
		symlinks  map[string]string // where a name resolves, planted after the run bound its sockets
		hardlinks map[string]string // a name of the same inode as another
		renames   map[string]string // a new name of the inode another name had, which names nothing now
		asked     string            // the scope a person is asked about; "" for none
		rule      string            // the line's rule when nobody is asked
		reached   string            // the socket file connected to, "" for none
	}{
		{name: "the scope's own name", path: scope, asked: scope},
		{name: "a relative name", path: "app.sock", asked: scope},
		{name: "a symlink to the scope's place", path: "/work/alias.sock",
			symlinks: map[string]string{"/work/alias.sock": scope}, asked: scope},
		{name: "a symlinked directory on the way", path: "/work/d/app.sock",
			symlinks: map[string]string{"/work/d/app.sock": scope}, asked: scope},
		{name: "a socket outside the run at a scope's place", path: ext, asked: ext},
		{name: "a symlink to a socket outside the run at a scope's place", path: "/work/extlink",
			symlinks: map[string]string{"/work/extlink": ext}, asked: ext},
		{name: "the run's socket at the scope, through a hard link", path: "/work/hard",
			hardlinks: map[string]string{"/work/hard": scope}, rule: writeRule, reached: "/work/hard"},
		{name: "the run's socket renamed away from the scope", path: "/work/moved",
			renames: map[string]string{"/work/moved": scope}, rule: writeRule, reached: "/work/moved"},
		{name: "a socket outside the run at a scope, through a hard link", path: "/work/exthard",
			hardlinks: map[string]string{"/work/exthard": ext}, rule: ruleUnixForeign},
		{name: "a socket outside the run renamed away from a scope", path: "/work/extmoved",
			renames: map[string]string{"/work/extmoved": ext}, rule: ruleUnixForeign},
		{name: "the run's socket beside the scope", path: other, rule: writeRule, reached: other},
		{name: "a datagram to the scope's name", path: scope, dgram: true, rule: ruleUnixAskScope},
		{name: "a datagram through a symlink to the scope's place", path: "/work/alias.sock", dgram: true,
			symlinks: map[string]string{"/work/alias.sock": scope}, rule: ruleUnixAskScope},
		{name: "a datagram to the run's socket renamed away from the scope", path: "/work/moved", dgram: true,
			renames: map[string]string{"/work/moved": scope}, rule: writeRule},
		{name: "a datagram through a hard link to a socket outside the run at a scope", path: "/work/exthard", dgram: true,
			hardlinks: map[string]string{"/work/exthard": ext}, rule: ruleUnixForeign},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newPlaceFake()
			if tc.dgram {
				f.sockType = unix.SOCK_DGRAM
			}
			f.links["/proc/4242/cwd"] = "/work"
			l, sink, asked := placeLoop(t, f, nil, ask.Decision{Reason: ask.ReasonDenied}, scope, ext)
			f.bindsSocket(t, l, sockID{ino: 9700, cookie: 1}, scope)
			f.bindsSocket(t, l, sockID{ino: 9701, cookie: 2}, other)
			for k, v := range tc.symlinks {
				f.symlinks[k] = v
			}
			for k, v := range tc.hardlinks {
				f.statIDs[k] = fakeID(v)
			}
			for k, v := range tc.renames {
				f.statIDs[k] = fakeID(v)
				f.statErrs[v] = unix.ENOENT
			}
			var r sysResp
			var ev *record.Event
			if tc.dgram {
				r, ev = sendUnixDgram(t, f, l, sink, tc.path)
			} else {
				r, ev = placeConnect(t, f, l, sink, tc.path)
				switch {
				case tc.reached == "" && len(f.unixConnects) != 0:
					t.Errorf("reached %q, want no connect", f.unixConnects)
				case tc.reached != "" && (len(f.unixConnects) != 1 || f.unixConnects[0] != tc.reached):
					t.Errorf("reached %q, want %s", f.unixConnects, tc.reached)
				}
			}
			if tc.asked != "" {
				if len(*asked) != 1 || (*asked)[0].Target != "unix:"+tc.asked || (*asked)[0].Rule != "net[unix:"+tc.asked+"]" {
					t.Fatalf("asked %+v, want one ask about unix:%s", *asked, tc.asked)
				}
				if ev.Verdict != record.VerdictRefused || ev.Rule != "net[unix:"+tc.asked+"]" || string(ev.Reason) != ask.ReasonDenied {
					t.Errorf("denied connect's line %s/%s/%s, want refused/net[unix:%s]/%s", ev.Verdict, ev.Rule, ev.Reason, tc.asked, ask.ReasonDenied)
				}
				if r.Error != -int32(refusalErrno) {
					t.Errorf("answer %+v, want error %d", r, -int32(refusalErrno))
				}
				return
			}
			if len(*asked) != 0 {
				t.Errorf("asked %+v, want nobody: the name reaches no scope's place", *asked)
			}
			allow := tc.rule == writeRule
			if wantV := map[bool]record.Verdict{true: record.VerdictAllow, false: record.VerdictRefused}[allow]; ev.Verdict != wantV || ev.Rule != tc.rule {
				t.Errorf("line %s/%s, want %s/%s", ev.Verdict, ev.Rule, wantV, tc.rule)
			}
			if !allow && (r.Error != -int32(refusalErrno) || r.Flags != 0) {
				t.Errorf("answer %+v, want error %d", r, -int32(refusalErrno))
			}
			if f.fdBalance() != 0 {
				t.Errorf("%d descriptors left open (E28)", f.fdBalance())
			}
		})
	}
}

// TestAskUnixScopeSpelledThroughASymlinkIsAskedByEveryName: a scope declared
// in a project reached through a symlink, in a directory the run makes after the loop is built, is asked and approved
// by every name that reaches its place — the declared spelling, a relative name from the task's cwd (which the kernel
// reports canonical), and the canonical spelling getcwd gives — and relayed to the socket the run bound there.
// Before, only the declared spelling was asked, and the others were refused unix-ask-scope with nobody asked.
func TestAskUnixScopeSpelledThroughASymlinkIsAskedByEveryName(t *testing.T) {
	const declared, real = "/link/out/sub/app.sock", "/real/out/sub/app.sock"
	write := []agent.FSRule{{Path: "/link/out", Raw: "./out/", Kind: agent.FSWrite, Resolved: "/real/out"}}
	for _, name := range []string{declared, "out/sub/app.sock", real} {
		t.Run(name, func(t *testing.T) {
			f := newPlaceFake()
			f.links["/link/out"] = "/real/out" // out/sub, and its socket, are made by the run later
			f.links["/proc/4242/cwd"] = "/real"
			l, sink, asked := placeLoop(t, f, write, ask.Decision{Approved: true}, declared)
			f.symlinks[declared] = real
			f.bindsSocket(t, l, sockID{ino: 9820, cookie: 1}, real)
			r, ev := placeConnect(t, f, l, sink, name)
			if len(*asked) != 1 || (*asked)[0].Target != "unix:"+declared {
				t.Fatalf("asked %+v, want one ask about unix:%s", *asked, declared)
			}
			if r.Error != 0 || ev.Verdict != record.VerdictAllow || ev.Rule != "net[unix:"+declared+"]" || ev.Authority != record.AuthorityHuman {
				t.Errorf("approved connect: answer %+v line %s/%s by %q, want allow/net[unix:%s] by a person", r, ev.Verdict, ev.Rule, ev.Authority, declared)
			}
			if len(f.unixConnects) != 1 || f.unixConnects[0] != real {
				t.Errorf("reached %q, want %s", f.unixConnects, real)
			}
		})
	}
}

// TestAskUnixScopeThroughALinkThatDanglesAtStart: a scope declared through a symlink whose target
// directory does not exist when the loop is built is the place that symlink points at, as the kernel's lookup lands
// there once the run makes the directory: a connect by the scope's name is asked, and an approval is relayed to the
// socket the run bound there. Before, the scope stayed at the symlink's spelling and the approved connect was refused
// unmatched.
func TestAskUnixScopeThroughALinkThatDanglesAtStart(t *testing.T) {
	const scope, real = "/work/out/dl/app.sock", "/work/out/sub/app.sock"
	f := newPlaceFake()
	f.links["/work/out/dl"] = "sub" // sub is made by the run later
	l, sink, asked := placeLoop(t, f, nil, ask.Decision{Approved: true}, scope)
	f.symlinks[scope] = real
	f.bindsSocket(t, l, sockID{ino: 9830, cookie: 1}, real)
	r, ev := placeConnect(t, f, l, sink, scope)
	if len(*asked) != 1 {
		t.Fatalf("asked %+v, want one ask", *asked)
	}
	if r.Error != 0 || ev.Verdict != record.VerdictAllow || ev.Rule != "net[unix:"+scope+"]" || ev.Authority != record.AuthorityHuman {
		t.Errorf("approved connect: answer %+v line %s/%s by %q, want allow/net[unix:%s] by a person", r, ev.Verdict, ev.Rule, ev.Authority, scope)
	}
	if len(f.unixConnects) != 1 || f.unixConnects[0] != real {
		t.Errorf("reached %q, want %s", f.unixConnects, real)
	}
}

// TestAskUnixPlacementEndsWhereTheAgentRacedADirectory: the loop places a
// connect's name with the kernel's PlaceLink (agent.ReadPlaceLink), which follows no symlink before the name it reads,
// never with Readlink, which would follow one. A connect by the scope's own spelling, its socket not there yet, is
// asked when its names read as the loop read them; when an agent's thread made a directory the walk passed a symlink
// meanwhile, the read below it fails ELOOP and the name is not placed: no scope's, nobody is asked, and it is decided
// at its place as any connect is (the write entry, ENOENT). A placement read through Readlink followed every link
// before the name again (1.17 s for one placement); in the fake it reads no link outside
// /proc, so this test and every placement test that follows a link fail with it.
func TestAskUnixPlacementEndsWhereTheAgentRacedADirectory(t *testing.T) {
	const scope, place = "/work/out/dl/app.sock", "/work/out/sub/app.sock"
	for _, raced := range []bool{false, true} {
		t.Run(map[bool]string{false: "names as the loop read them", true: "a directory raced into a link"}[raced], func(t *testing.T) {
			f := newPlaceFake()
			f.links["/work/out/dl"] = "sub" // sub is made by the run later
			l, sink, asked := placeLoop(t, f, nil, ask.Decision{Approved: true}, scope)
			if l.table.Load().unixAskAt(place) == nil {
				t.Fatalf("scope %s not placed at %s when the loop was built", scope, place)
			}
			f.mu.Lock()
			f.finalErrs = map[string]error{scope: unix.ENOENT} // the socket is not there yet
			f.placeLinks = 0
			if raced {
				f.racedDirs = map[string]bool{"/work/out": true}
			}
			f.mu.Unlock()
			r, ev := placeConnect(t, f, l, sink, scope)
			f.mu.Lock()
			reads := f.placeLinks
			f.mu.Unlock()
			if reads == 0 {
				t.Errorf("placing the connect's name read no name through PlaceLink")
			}
			want, n := "fs.write[/work/]", 0
			if !raced {
				want, n = "net[unix:"+scope+"]", 1
			}
			if len(*asked) != n || r.Error != -int32(unix.ENOENT) || ev.Rule != want || len(f.unixConnects) != 0 {
				t.Errorf("asked %d, answer %+v line %s/%s reached %q; want %d asked, ENOENT under %s, no connect",
					len(*asked), r, ev.Verdict, ev.Rule, f.unixConnects, n, want)
			}
		})
	}
}

// TestAskUnixScopeThroughALinkWithDotDot: a scope declared at a symlink that leads nowhere yet
// and whose target holds a ".." after a symlinked directory (/p/s -> sub/../x.sock, /p/sub -> real/deep) is the place
// the kernel's lookup lands at, /p/real/x.sock, the ".." applied after sub is followed. A connect there is asked and
// approved; a connect to /p/x.sock, where a socket outside the run listens and no entry names, is nobody's to ask and is
// refused. Before, the link's target was cleaned lexically, the scope was placed at /p/x.sock, and the approval
// connected the outside listener there.
func TestAskUnixScopeThroughALinkWithDotDot(t *testing.T) {
	const scope, place, outside = "/p/s", "/p/real/x.sock", "/p/x.sock"
	for _, tc := range []struct {
		name  string
		path  string
		asked bool
	}{
		{name: "the place the link leads to", path: place, asked: true},
		{name: "the place a lexical clean of the link gives", path: outside},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newPlaceFake()
			f.links["/p/sub"] = "real/deep"
			f.links[scope] = "sub/../x.sock"
			l, sink, asked := placeLoop(t, f, nil, ask.Decision{Approved: true}, scope)
			if tc.path == place {
				f.finalErrs = map[string]error{place: unix.ENOENT} // the socket is not there yet
			}
			r, ev := placeConnect(t, f, l, sink, tc.path)
			if got := len(*asked); got != map[bool]int{true: 1, false: 0}[tc.asked] {
				t.Fatalf("asked %+v, want asked %v", *asked, tc.asked)
			}
			if tc.asked {
				if (*asked)[0].Target != "unix:"+scope || r.Error != -int32(unix.ENOENT) || ev.Rule != "net[unix:"+scope+"]" {
					t.Errorf("asked %+v answer %+v line %s/%s; want unix:%s asked, ENOENT under net[unix:%s]", *asked, r, ev.Verdict, ev.Rule, scope, scope)
				}
				return
			}
			if ev.Verdict != record.VerdictRefused || r.Error != -int32(refusalErrno) || len(f.unixConnects) != 0 {
				t.Errorf("answer %+v line %s/%s reached %q; want refused, no connect", r, ev.Verdict, ev.Rule, f.unixConnects)
			}
		})
	}
}

// TestAskUnixScopeNamedByALinkThatLeadsNowhere: a scope whose own name is a symlink that leads
// nowhere yet (/work/out/f.sock -> real/y.sock, out/real missing) is the place the link points at. A connect by that
// name, or by another symlink the agent made to the same place, reaches no socket (the walk of the whole name fails
// ENOENT) but leads to the scope's place, and is asked, as a connect to a socket the run has not bound yet is: an
// approval is relayed and meets ENOENT. A link that leads elsewhere is decided as any name is, by the write entry
// around it. Before, the name was placed at the link itself, and the write entry admitted the connect with nobody
// asked.
func TestAskUnixScopeNamedByALinkThatLeadsNowhere(t *testing.T) {
	const scope = "/work/out/f.sock"
	for _, tc := range []struct {
		name, path, link string // link is the target of path when the agent made path a symlink
		asked            bool
	}{
		{name: "the scope's own name", path: scope, asked: true},
		{name: "a link the agent made to the same place", path: "/work/out/alias", link: "real/y.sock", asked: true},
		{name: "a link the agent made elsewhere", path: "/work/out/other", link: "real/z.sock"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newPlaceFake()
			f.links[scope] = "real/y.sock"
			l, sink, asked := placeLoop(t, f, nil, ask.Decision{Approved: true}, scope)
			if tc.link != "" {
				f.links[tc.path] = tc.link
			}
			f.finalErrs = map[string]error{tc.path: unix.ENOENT}
			r, ev := placeConnect(t, f, l, sink, tc.path)
			if got := len(*asked); got != map[bool]int{true: 1, false: 0}[tc.asked] {
				t.Fatalf("asked %+v, want asked %v", *asked, tc.asked)
			}
			want := "fs.write[/work/]"
			if tc.asked {
				want = "net[unix:" + scope + "]"
				if (*asked)[0].Target != "unix:"+scope {
					t.Errorf("asked %+v, want unix:%s", *asked, scope)
				}
			}
			if r.Error != -int32(unix.ENOENT) || ev.Rule != want || len(f.unixConnects) != 0 {
				t.Errorf("answer %+v line %s/%s reached %q; want ENOENT under %s, no connect", r, ev.Verdict, ev.Rule, f.unixConnects, want)
			}
		})
	}
}

// TestAskUnixScopeWhoseSocketIsNotThereYet: a name whose last component names nothing yet reaches the place the
// directory its walk lands in gives it, and is asked when that is the scope's place; a name whose directory does not
// exist yet reaches no place and is the scope's when it spells it, from the task's cwd too. An approval is then
// relayed, and the relay's own lookup meets what the task's would, ENOENT: that is the answer, as for any relayed
// connect whose lookup failed. A name the loop's walk cannot place (a magic link) is no scope's: nobody is asked,
// and the relay refuses it path-unreliable.
func TestAskUnixScopeWhoseSocketIsNotThereYet(t *testing.T) {
	const scope = "/work/sub/app.sock"
	for _, tc := range []struct {
		name       string
		path       string
		finalErr   error             // the walk of the whole name fails so at its last component; its directory's lands
		resolveErr error             // the walk of the whole name and of its directory fails so
		cwd        string            // the task's cwd, /work when ""
		links      map[string]string // symlinks the agent made after the loop was built, by their targets
		asked      bool
		errno      int32
		rule       string
	}{
		{name: "the scope's socket not bound yet", path: scope, finalErr: unix.ENOENT, asked: true,
			errno: -int32(unix.ENOENT), rule: "net[unix:" + scope + "]"},
		{name: "a magic link at the scope's place", path: scope, finalErr: unix.ELOOP,
			errno: -int32(refusalErrno), rule: rulePathUnreliable},
		{name: "the scope's directory not made yet", path: scope, resolveErr: unix.ENOENT, asked: true,
			errno: -int32(unix.ENOENT), rule: "net[unix:" + scope + "]"},
		{name: "a relative name, the scope's directory not made yet", path: "sub/app.sock", resolveErr: unix.ENOENT, asked: true,
			errno: -int32(unix.ENOENT), rule: "net[unix:" + scope + "]"},
		{name: "a name beside the scope, its directory not made yet", path: "/work/none/x.sock", resolveErr: unix.ENOENT,
			errno: -int32(unix.ENOENT), rule: "fs.write[/work/]"},
		{name: "the scope's name through a magic link", path: scope, resolveErr: unix.ELOOP,
			errno: -int32(refusalErrno), rule: rulePathUnreliable},
		// Placed as the scope is, the symlinked directory before the missing one
		// followed. Before, only the spelling was compared, and the write entry admitted it with nobody asked.
		{name: "a symlinked directory before the scope's missing one", path: "/work/lnk/sub/app.sock",
			links: map[string]string{"/work/lnk": "/work"}, resolveErr: unix.ENOENT, asked: true,
			errno: -int32(unix.ENOENT), rule: "net[unix:" + scope + "]"},
		// A ".." after a symlinked directory, before the missing one, is
		// applied after that link is followed, a relative name's as an absolute one's. Before, a relative name was
		// placed from R6's lexically cleaned spelling (/work/c/sub/app.sock here), and the write entry admitted it.
		{name: "a relative name with a .. after a symlinked directory", cwd: "/work/c", path: "d/../sub/app.sock",
			links: map[string]string{"/work/c/d": "/work/z"}, resolveErr: unix.ENOENT, asked: true,
			errno: -int32(unix.ENOENT), rule: "net[unix:" + scope + "]"},
		{name: "an absolute name with a .. after a symlinked directory", cwd: "/work/c", path: "/work/c/d/../sub/app.sock",
			links: map[string]string{"/work/c/d": "/work/z"}, resolveErr: unix.ENOENT, asked: true,
			errno: -int32(unix.ENOENT), rule: "net[unix:" + scope + "]"},
		{name: "a relative name with two .. after a deeper symlinked directory", path: "x/y/lnk/../../sub/app.sock",
			links: map[string]string{"/work/x/y/lnk": "/work/e/f"}, resolveErr: unix.ENOENT, asked: true,
			errno: -int32(unix.ENOENT), rule: "net[unix:" + scope + "]"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newPlaceFake()
			f.links["/proc/4242/cwd"] = "/work"
			if tc.cwd != "" {
				f.links["/proc/4242/cwd"] = tc.cwd
			}
			l, sink, asked := placeLoop(t, f, nil, ask.Decision{Approved: true}, scope)
			for k, v := range tc.links {
				f.links[k] = v
			}
			if tc.finalErr != nil {
				f.finalErrs = map[string]error{tc.path: tc.finalErr}
			}
			if tc.resolveErr != nil {
				f.resolveErrs[tc.path] = tc.resolveErr
			}
			r, ev := placeConnect(t, f, l, sink, tc.path)
			if got := len(*asked) == 1; got != tc.asked || len(*asked) > 1 {
				t.Fatalf("asked %+v, want asked %v", *asked, tc.asked)
			}
			if r.Error != tc.errno || ev.Rule != tc.rule || len(f.unixConnects) != 0 {
				t.Errorf("answer %+v line %s/%s reached %q; want error %d, rule %s, no connect", r, ev.Verdict, ev.Rule, f.unixConnects, tc.errno, tc.rule)
			}
		})
	}
}

// TestAskUnixPlacementOfAConnectsNameIsBounded: placing a connect's name the
// agent made — a chain of symlinks that lead nowhere yet, each through a thousand directories and back — costs a
// number of reads linear in the names it walks and stops at a fixed number of them, where the kernel's walk would
// still be going: the name is then no scope's, decided at its place as any connect is (the write entry admits it,
// and it meets ENOENT; nothing connects). Before, each link was placed by resolving every prefix of its target from
// the deepest down, one whole-path EvalSymlinks each, so one connect stalled a supervisor worker for tens of seconds.
func TestAskUnixPlacementOfAConnectsNameIsBounded(t *testing.T) {
	const scope = "/work/sub/app.sock"
	const maxReads = 1100 // the walk's 1024 names, and the loop's own reads
	f := newPlaceFake()
	f.links["/proc/4242/cwd"] = "/work"
	l, sink, asked := placeLoop(t, f, nil, ask.Decision{Approved: true}, scope)
	down, up := strings.Repeat("m/", 1000), strings.Repeat("../", 1000)
	for i := 0; i < 5; i++ {
		f.links["/work/out/l"+strconv.Itoa(i)] = "/work/out/" + down + up + "l" + strconv.Itoa(i+1)
	}
	f.links["/work/out/l5"] = scope
	f.finalErrs = map[string]error{"/work/out/l0": unix.ENOENT}
	f.mu.Lock()
	f.readlinks, f.evals, f.placeLinks = 0, 0, 0
	f.mu.Unlock()
	r, ev := placeConnect(t, f, l, sink, "/work/out/l0")
	f.mu.Lock()
	reads := f.readlinks + f.evals + f.placeLinks
	f.mu.Unlock()
	if reads > maxReads {
		t.Errorf("placing one connect's name made %d reads, want at most %d", reads, maxReads)
	}
	if len(*asked) != 0 || r.Error != -int32(unix.ENOENT) || ev.Rule != "fs.write[/work/]" || len(f.unixConnects) != 0 {
		t.Errorf("asked %d, answer %+v line %s/%s reached %q; want nobody asked, ENOENT under fs.write[/work/], no connect",
			len(*asked), r, ev.Verdict, ev.Rule, f.unixConnects)
	}
}

// TestAskUnixApprovalConnectsOnlyTheScopesPlace: a person's approval admits the scope's place and nothing else. A name
// the agent repoints while the person decides reaches another place by the relay, and that connect is decided as any
// unix connect is, on the socket it reaches there, with no person's authority: the run's own socket is the write
// entry's, a socket outside the run is refused unix-foreign, and a place no entry names is refused unmatched.
func TestAskUnixApprovalConnectsOnlyTheScopesPlace(t *testing.T) {
	const scope, own, daemon = "/work/app.sock", "/work/own.sock", "/work/daemon.sock"
	for _, tc := range []struct {
		name, to, rule string
		allow          bool
	}{
		{name: "the run's own socket elsewhere", to: own, rule: "fs.write[/work/]", allow: true},
		{name: "a socket outside the run", to: daemon, rule: ruleUnixForeign},
		{name: "a place no entry names", to: "/run/docker.sock", rule: ruleUnmatched},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newPlaceFake()
			l, sink, asked := placeLoop(t, f, nil, ask.Decision{}, scope)
			f.bindsSocket(t, l, sockID{ino: 9840, cookie: 1}, own)
			l.ask = func(_ context.Context, r ask.Request) (ask.Decision, error) {
				*asked = append(*asked, r)
				f.mu.Lock()
				f.symlinks[scope] = tc.to
				f.mu.Unlock()
				return ask.Decision{Approved: true}, nil
			}
			r, ev := placeConnect(t, f, l, sink, scope)
			if len(*asked) != 1 {
				t.Fatalf("asked %+v, want one ask", *asked)
			}
			if ev.Rule != tc.rule || ev.Authority == record.AuthorityHuman {
				t.Errorf("line %s/%s by %q, want rule %s and no person's authority", ev.Verdict, ev.Rule, ev.Authority, tc.rule)
			}
			if tc.allow {
				if ev.Verdict != record.VerdictAllow || len(f.unixConnects) != 1 || f.unixConnects[0] != tc.to {
					t.Errorf("line %s, reached %q; want allow and %s", ev.Verdict, f.unixConnects, tc.to)
				}
				return
			}
			if ev.Verdict != record.VerdictRefused || r.Error != -int32(refusalErrno) || len(f.unixConnects) != 0 {
				t.Errorf("line %s answer %+v reached %q; want refused, error %d, no connect", ev.Verdict, r, f.unixConnects, -int32(refusalErrno))
			}
		})
	}
}

// TestAskUnixScopesPlaceReachedOnlyByTheRelayIsRefused: a name whose walk reaches another place when the loop decides
// whether to ask, and the scope's place by the relay's own walk (the agent repointed it in between), is refused
// unix-ask-scope: the scope's place is admitted by a person or a declared entry, never by the write entry the name's
// first place lay under.
func TestAskUnixScopesPlaceReachedOnlyByTheRelayIsRefused(t *testing.T) {
	const scope, own, name = "/work/app.sock", "/work/own.sock", "/work/x.sock"
	f := newPlaceFake()
	l, sink, asked := placeLoop(t, f, nil, ask.Decision{Approved: true}, scope)
	f.bindsSocket(t, l, sockID{ino: 9850, cookie: 1}, own)
	f.bindsSocket(t, l, sockID{ino: 9851, cookie: 2}, scope)
	f.symlinks[name] = own
	f.walkDone = func(unixQuery) {
		f.mu.Lock()
		f.symlinks[name] = scope
		f.mu.Unlock()
	}
	r, ev := placeConnect(t, f, l, sink, name)
	if len(*asked) != 0 {
		t.Errorf("asked %+v, want nobody", *asked)
	}
	if ev.Verdict != record.VerdictRefused || ev.Rule != ruleUnixAskScope || r.Error != -int32(refusalErrno) || len(f.unixConnects) != 0 {
		t.Errorf("line %s/%s answer %+v reached %q; want refused/%s, error %d, no connect", ev.Verdict, ev.Rule, r, f.unixConnects, ruleUnixAskScope, -int32(refusalErrno))
	}
}
