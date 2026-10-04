// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"gopkg.in/yaml.v3"
)

func TestAskConfigStrictShapeDefaultsAndExplicitZero(t *testing.T) {
	base := "version: 0\nname: a\ncommand: [x]\n"
	for _, extra := range []string{"ask: {hold: other}", "ask: {timeout: 0s}", "ask: {timeout: 2h}", "ask: {timeout: 3}", "ask: {max_pending: 0}", "ask: {max_pending: 65}", "ask: {max_pending: '2'}", "ask: {hold: connect, hold: request}", "ask: {unknown: true}", "ask: {timeout: null}", "ask: null", "ask: []", "ask: {hold: null}"} {
		if _, ds, e := LoadBytes("ask.yaml", []byte(base+extra+"\n"), nil); e == nil || !hasCode(ds, CodeSchema) {
			t.Fatalf("accepted %q: %v %v", extra, ds, e)
		}
		var node yaml.Node
		_ = yaml.Unmarshal([]byte(strings.TrimPrefix(extra, "ask: ")), &node)
		if len(node.Content) > 0 {
			c := &Contract{Ask: *node.Content[0]}
			if _, e := CompileAskConfig(c); e == nil {
				t.Fatalf("typed boundary accepted %q", extra)
			}
		}
	}
	for _, tc := range []struct {
		src     string
		hold    AskHold
		timeout time.Duration
		pending int
	}{{"fs: {ask: [/work]}\n", AskHoldConnect, 5 * time.Minute, 64}, {"net: {ask: ['tcp://192.0.2.1:443']}\nask: {hold: first_write, timeout: 3m, max_pending: 2}\n", AskHoldFirstWrite, 3 * time.Minute, 2}} {
		c, ds, e := LoadBytes("ask.yaml", []byte(base+tc.src), nil)
		if e != nil {
			t.Fatalf("load %v %v", ds, e)
		}
		p, e := CompileAskConfig(c)
		if e != nil || p == nil || p.Hold != tc.hold || time.Duration(p.Timeout) != tc.timeout || p.MaxPending != tc.pending {
			t.Fatalf("config %+v %v", p, e)
		}
	}
}

func TestAskScopeShapeAndUnsafeModesAreRejected(t *testing.T) {
	base := "version: 0\nname: a\ncommand: [x]\n"
	for _, s := range []string{"net: {ask: ['192.0.2.1:0']}", "net: {ask: ['192.0.2.1']}", "net: {ask: ['10.0.0.0/8:0']}", "fs: {ask: [/work/*]}", "fs: {ask: [/work]}\nsetuid: true", "fs: {ask: [/work]}\nio_uring: true", "fs: {ask: ['" + strings.Repeat("x", 4097) + "']}", "fs:\n  ask: [" + strings.Repeat("/work,", 256) + "/work]"} {
		if _, ds, e := LoadBytes("ask.yaml", []byte(base+s+"\n"), nil); e == nil {
			t.Fatalf("accepted unsafe scope %q %v", s, ds)
		}
	}
	request := "ask: {hold: request}\nnet: {ask: ['tcp://api.example:443']}\n"
	if _, _, e := LoadBytes("ask.yaml", []byte(base+request), nil); e == nil {
		t.Fatal("opaque request hold accepted")
	}
	full := "ask: {hold: request}\ncapture: forwarder\nmodels: [{provider: anthropic, host: api.example, port: 443}]\nnet:\n  ask: ['tcp://api.example:443']\n  http: [{host: api.example, allow: [/v1]}]\n"
	c, ds, e := LoadBytes("ask.yaml", []byte(base+full), nil)
	if e != nil {
		t.Fatalf("request load %v %v", ds, e)
	}
	p, e := CompileAskConfig(c)
	if e != nil || p.Hold != AskHoldRequest || time.Duration(p.Timeout) != 4*time.Minute {
		t.Fatalf("request defaults %+v %v", p, e)
	}
	if _, _, e = LoadBytes("ask.yaml", []byte(base+strings.Replace(full, "tcp://api.example:443", "tcp://other.example:443", 1)), nil); e == nil {
		t.Fatal("unbound request authority accepted")
	}
}

// A udp:// approval scope, and a bare host:port, which names TCP and UDP (SEMANTICS §5; the contract writes
// `ask: ["queue.internal:5672"]`), compile into NetAsk rules: a datagram or a UDP connect to one is held while a person
// decides (supervisor R13d, ASK-UDP). UDP is held at the syscall, so such a scope needs ask.hold: connect: first_write
// holds TCP bytes and request an HTTP request, which a datagram is neither. A destination without a port is no ask
// scope: port 0 is ICMP's, and an approval names one port.
func TestAskUDPScopesAreHeldAtTheDatagram(t *testing.T) {
	f := newFixture(t)
	c := f.load("version: 0\nname: a\ncommand: [static-tool]\nnet: {ask: ['udp://192.0.2.1:53', '192.0.2.2:5672', '10.0.0.0/8:443']}\n")
	rt, _ := f.compile(c)
	if rt.AskConfig == nil || rt.AskConfig.Hold != AskHoldConnect || len(rt.NetAsk) != 3 {
		t.Fatalf("compiled udp asks %+v %+v", rt.AskConfig, rt.NetAsk)
	}
	if r := rt.NetAsk[0]; r.Proto != ProtoUDP || r.Port != 53 || r.Verdict != VerdictAsk {
		t.Fatalf("udp scope %+v", r)
	}
	if r := rt.NetAsk[1]; r.Proto != ProtoInet || r.Port != 5672 || r.Verdict != VerdictAsk {
		t.Fatalf("bare scope %+v", r)
	}
	if r := rt.NetAsk[2]; r.Proto != ProtoInet || r.CIDR == nil || r.Port != 443 {
		t.Fatalf("bare cidr scope %+v", r)
	}
	base := "version: 0\nname: a\ncommand: [x]\n"
	for _, hold := range []string{"first_write", "request"} {
		for _, scope := range []string{"udp://192.0.2.1:53", "192.0.2.2:5672"} {
			src := base + "ask: {hold: " + hold + "}\nnet: {ask: ['" + scope + "']}\n"
			if _, ds, e := LoadBytes("ask.yaml", []byte(src), nil); e == nil || !hasCode(ds, CodeSchema) {
				t.Fatalf("hold %s accepted %s: %v %v", hold, scope, ds, e)
			}
		}
	}
	if _, ds, e := LoadBytes("ask.yaml", []byte(base+"ask: {hold: first_write}\nnet: {ask: ['tcp://192.0.2.1:443']}\n"), nil); e != nil {
		t.Fatalf("first_write refused a tcp:// scope: %v %v", ds, e)
	}
}

// A unix: approval scope names a socket the way a net.allow unix: entry does, pathname or abstract, and is held at the
// connect: the supervisor relays it as the task once a person approves (supervisor R11, ADR 0008). first_write and
// request holds are for a TCP byte stream and an inspected HTTP request, which a unix connect is neither.
func TestAskUnixScopesAreHeldAtTheConnect(t *testing.T) {
	f := newFixture(t)
	c := f.load("version: 0\nname: a\ncommand: [static-tool]\nnet: {ask: ['unix:/run/x.sock', 'unix:@bus']}\n")
	rt, _ := f.compile(c)
	if rt.AskConfig == nil || rt.AskConfig.Hold != AskHoldConnect || len(rt.NetAsk) != 2 {
		t.Fatalf("compiled unix asks %+v %+v", rt.AskConfig, rt.NetAsk)
	}
	if r := rt.NetAsk[0]; r.Proto != ProtoUnix || r.Abstract || r.UnixPath != "/run/x.sock" || r.Verdict != VerdictAsk {
		t.Fatalf("pathname scope %+v", r)
	}
	if r := rt.NetAsk[1]; r.Proto != ProtoUnix || !r.Abstract || r.UnixPath != "bus" {
		t.Fatalf("abstract scope %+v", r)
	}
	base := "version: 0\nname: a\ncommand: [x]\n"
	for _, hold := range []string{"first_write", "request"} {
		src := base + "ask: {hold: " + hold + "}\nnet: {ask: ['unix:/run/x.sock']}\n"
		if _, ds, e := LoadBytes("ask.yaml", []byte(src), nil); e == nil || !hasCode(ds, CodeSchema) {
			t.Fatalf("hold %s accepted a unix scope: %v %v", hold, ds, e)
		}
	}
}

// A pathname unix: scope keeps the place it resolves to at compile, as an fs entry does (NetRule.UnixResolved), and
// Evaluate refuses a connect there under the scope's rule, inside the write entry around it, as P0 compiles an ask: the
// run asks a person about a connect that reaches that place (supervisor R11c), where compile --test answered allow.
func TestAskUnixScopeIsMatchedByItsResolvedSpelling(t *testing.T) {
	f := newFixture(t)
	// Not under the fixture's root: a socket path there is past sun_path's 107 bytes.
	out, err := os.MkdirTemp("", "eyas")
	if err == nil {
		t.Cleanup(func() { _ = os.RemoveAll(out) })
		out, err = filepath.EvalSymlinks(out)
	}
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(out, "real"), 0o755); err != nil {
		t.Fatal(err)
	}
	// link leads to real; dl, dlabs and dl2 lead to directories the run makes later: a relative
	// target, an absolute one, and a link to a link that leads nowhere yet.
	for name, target := range map[string]string{"link": "real", "dl": "made", "dlabs": filepath.Join(out, "made2"), "dl2": "dl"} {
		if err := os.Symlink(target, filepath.Join(out, name)); err != nil {
			t.Fatal(err)
		}
	}
	// The scope's own directory, or several below the symlink, may be made by the run later:
	// the spelling is resolved from the deepest ancestor that exists, and a symlink there whose target does not exist
	// yet is followed to where it points, where the kernel's lookup lands once the run makes it.
	for _, c := range [][2]string{
		{"link/app.sock", "real/app.sock"}, {"link/sub/app.sock", "real/sub/app.sock"},
		{"link/sub/deep/app.sock", "real/sub/deep/app.sock"},
		{"dl/app.sock", "made/app.sock"}, {"dl/sub/app.sock", "made/sub/app.sock"},
		{"dlabs/app.sock", "made2/app.sock"}, {"dl2/app.sock", "made/app.sock"},
	} {
		declared, real := filepath.Join(out, c[0]), filepath.Join(out, c[1])
		c := f.load("version: 0\nname: a\ncommand: [static-tool]\nfs: {write: ['" + out + "/']}\nnet: {ask: ['unix:" + declared + "']}\n")
		rt, _ := f.compile(c)
		if len(rt.NetAsk) != 1 || rt.NetAsk[0].UnixPath != declared || rt.NetAsk[0].UnixResolved != real {
			t.Fatalf("compiled unix scope %+v, want UnixPath %s UnixResolved %s", rt.NetAsk, declared, real)
		}
		for _, tier := range []backend.Tier{backend.TierLandlock, backend.TierCgroup, backend.TierBPFLSM} {
			for _, p := range []string{declared, real} {
				if got := rt.Evaluate(Action{Kind: ActionNetConnect, Path: p}, tier); got.Verdict != VerdictRefused || got.Rule != rt.NetAsk[0].RuleName() {
					t.Errorf("tier %s connect %s = %+v, want refused %s", tier, p, got, rt.NetAsk[0].RuleName())
				}
			}
		}
	}
}

// ResolveUnixPlace over a view where only some of the path exists: a symlink is followed whether or not its target
// exists, a symlinked directory on the way included, and a chain past the kernel's 40 links, a relative path, or a
// place past PATH_MAX is the path as given, not placed.
func TestResolveUnixPlace(t *testing.T) {
	links := map[string]string{"/link": "/w", "/w/dl": "made", "/w/abs": "/w/made2", "/w/dl2": "dl", "/w/loop": "loop2",
		"/w/loop2": "loop", "/w/long": "/" + strings.Repeat("d/", 2100) + "x"}
	readlink := func(p string) (string, error) {
		if v, ok := links[p]; ok {
			return v, nil
		}
		return "", unix.EINVAL
	}
	for p, want := range map[string]string{
		"/w/sock":              "/w/sock",
		"/link/sock":           "/w/sock",
		"/link/sub/deep/a.s":   "/w/sub/deep/a.s",
		"/w/dl/a.s":            "/w/made/a.s",
		"/w/dl/sub/a.s":        "/w/made/sub/a.s",
		"/w/abs/a.s":           "/w/made2/a.s",
		"/w/dl2/a.s":           "/w/made/a.s",
		"/w/dl":                "/w/made",
		"/link/../w/./dl//a.s": "/w/made/a.s",
		"/..":                  "/",
	} {
		if got, ok := ResolveUnixPlace(p, readlink); got != want || !ok {
			t.Errorf("ResolveUnixPlace(%q) = %q %v, want %q true", p, got, ok, want)
		}
	}
	for _, p := range []string{"/w/loop/a.s", "rel/a.s", "/w/long/a.s"} {
		if got, ok := ResolveUnixPlace(p, readlink); got != p || ok {
			t.Errorf("ResolveUnixPlace(%q) = %q %v, want it as given, not placed", p, got, ok)
		}
	}
	// A read still interrupted after ReadPlaceLink's retries (EINTR) says nothing about the name: the name may be
	// a link, so keeping it as a plain directory would place the path where the kernel's lookup does not land.
	interrupted := func(p string) (string, error) {
		if p == "/link" {
			return "", unix.EINTR
		}
		return readlink(p)
	}
	if got, ok := ResolveUnixPlace("/link/sock", interrupted); got != "/link/sock" || ok {
		t.Errorf("ResolveUnixPlace(/link/sock), its link's read interrupted = %q %v, want it as given, not placed", got, ok)
	}
	// Only a read that says what the name is keeps it as a plain name: EINVAL (it is no symlink), ENOENT or ENOTDIR
	// (nothing is there yet, as the kernel's own lookup finds). Any other failure — the supervisor's descriptor table
	// full (EMFILE, ENFILE: ReadPlaceLink's openat2 takes a descriptor), no memory, an I/O error, no search permission
	// for this process — leaves the name's kind unknown, so the placement ends, not placed, as for EINTR (an
	// fd-exhausted read kept /link as a plain directory and placed /link/sock at itself, ok).
	failing := func(with error) func(string) (string, error) {
		return func(p string) (string, error) {
			if p == "/link" {
				return "", &fs.PathError{Op: "openat2", Path: "/", Err: with}
			}
			return readlink(p)
		}
	}
	for _, errno := range []unix.Errno{unix.EMFILE, unix.ENFILE, unix.ENOMEM, unix.EIO, unix.EACCES, unix.ENAMETOOLONG} {
		if got, ok := ResolveUnixPlace("/link/sock", failing(errno)); got != "/link/sock" || ok {
			t.Errorf("ResolveUnixPlace(/link/sock), its link's read failing %v = %q %v, want it as given, not placed", errno, got, ok)
		}
	}
	for _, errno := range []unix.Errno{unix.EINVAL, unix.ENOENT, unix.ENOTDIR} {
		if got, ok := ResolveUnixPlace("/link/sock", failing(errno)); got != "/link/sock" || !ok {
			t.Errorf("ResolveUnixPlace(/link/sock), its link's read failing %v = %q %v, want it kept as a name, placed", errno, got, ok)
		}
	}
}

// TestReadPlaceLinkRetriesEINTR: ReadPlaceLink retries an interrupted
// openat2 or readlinkat, as os.Readlink retried its readlink, up to maxEINTR times in all, and reads the link; one more
// interruption is returned, and ResolveUnixPlace then does not place the path. Without the retry, a name on a FUSE or
// network file system whose lookup a signal interrupted once ended the placement.
func TestReadPlaceLinkRetriesEINTR(t *testing.T) {
	P, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(P+"/real", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("real", P+"/link"); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Openat2(unix.AT_FDCWD, P, &unix.OpenHow{Flags: unix.O_PATH | unix.O_CLOEXEC})
	if err != nil {
		t.Skipf("openat2 refused here (%v): ReadPlaceLink reads with os.Readlink, which retries EINTR itself", err)
	}
	_ = unix.Close(fd)
	for _, c := range []struct {
		name               string
		opens, readlinks   int // interruptions of each, in turn
		wantInterruptedErr bool
	}{
		{"openat2 up to the retries", maxEINTR, 0, false},
		{"readlinkat up to the retries", 0, maxEINTR, false},
		{"both, up to the retries in all", maxEINTR / 2, maxEINTR / 2, false},
		{"openat2 past the retries", maxEINTR + 1, 0, true},
		{"readlinkat past the retries", 0, maxEINTR + 1, true},
		{"both, past the retries in all", maxEINTR / 2, maxEINTR/2 + 1, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			open, readlinkat := sysOpenat2, sysReadlinkat
			t.Cleanup(func() { sysOpenat2, sysReadlinkat = open, readlinkat })
			opens, readlinks := 0, 0
			sysOpenat2 = func(dirfd int, p string, how *unix.OpenHow) (int, error) {
				if p != P+"/" {
					return open(dirfd, p, how)
				}
				if opens++; opens <= c.opens {
					return -1, unix.EINTR
				}
				return open(dirfd, p, how)
			}
			sysReadlinkat = func(dirfd int, p string, buf []byte) (int, error) {
				if p != "link" {
					return readlinkat(dirfd, p, buf)
				}
				if readlinks++; readlinks <= c.readlinks {
					return 0, unix.EINTR
				}
				return readlinkat(dirfd, p, buf)
			}
			got, err := ReadPlaceLink(P + "/link")
			if c.wantInterruptedErr {
				if !errors.Is(err, unix.EINTR) {
					t.Fatalf("ReadPlaceLink = %q, %v; want EINTR past %d retries", got, err, maxEINTR)
				}
				opens, readlinks = 0, 0
				if at, ok := ResolveUnixPlace(P+"/link/s.sock", ReadPlaceLink); ok {
					t.Errorf("ResolveUnixPlace through the interrupted link = %q, placed; want not placed", at)
				}
				return
			}
			if got != "real" || err != nil {
				t.Errorf("ReadPlaceLink = %q, %v; want real after %d+%d interruptions", got, err, c.opens, c.readlinks)
			}
		})
	}
}

// TestResolveUnixPlaceIsBounded: on a real filesystem, placing a chain of
// symlinks that lead nowhere yet, each through hundreds of directories and back, as an agent can plant under its
// write entry, reads at most unixPlaceNames links and gives up, so a connect's name costs the supervisor a bounded
// time; a chain of links through a few directories each is still placed where realpath -m places it. Before, each
// link was placed by resolving every prefix of its target from the deepest down, one filepath.EvalSymlinks each,
// which took 38 s for five links through 500 directories.
func TestResolveUnixPlaceIsBounded(t *testing.T) {
	P, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name       string
		depth      int
		wantPlaced bool
	}{
		{"a long chain", 500, false},
		{"a short chain", 3, true},
	} {
		dir := filepath.Join(P, c.name)
		deep := filepath.Join(dir, strings.Repeat("m/", c.depth))
		if err := os.MkdirAll(deep, 0o755); err != nil {
			t.Fatal(err)
		}
		down, up := strings.Repeat("m/", c.depth), strings.Repeat("../", c.depth)
		for i := 0; i < 5; i++ {
			target := down + up + "l" + strconv.Itoa(i+1)
			if err := os.Symlink(target, filepath.Join(dir, "l"+strconv.Itoa(i))); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.Symlink("nodir/x.sock", filepath.Join(dir, "l5")); err != nil {
			t.Fatal(err)
		}
		reads := 0
		counted := func(p string) (string, error) {
			reads++
			return ReadPlaceLink(p)
		}
		start := time.Now()
		got, ok := ResolveUnixPlace(dir+"/l0", counted)
		took := time.Since(start)
		t.Logf("%s: %d readlinks, %v", c.name, reads, took)
		if reads > unixPlaceNames {
			t.Errorf("%s: %d readlinks, want at most %d", c.name, reads, unixPlaceNames)
		}
		want := dir + "/l0"
		if c.wantPlaced {
			want = dir + "/nodir/x.sock"
		}
		if got != want || ok != c.wantPlaced {
			t.Errorf("%s: place %q %v, want %q %v", c.name, got, ok, want, c.wantPlaced)
		}
	}
	// The most one placement reads through plain directories: a path 1100 directories deep,
	// each read a walk of every directory before its name, ends at unixPlaceNames reads, not placed.
	deep := P + "/plain/" + strings.Repeat("a/", 1100)
	if err := os.MkdirAll(deep, 0o755); err != nil {
		t.Fatal(err)
	}
	reads := 0
	start := time.Now()
	got, ok := ResolveUnixPlace(deep+"s.sock", func(p string) (string, error) { reads++; return ReadPlaceLink(p) })
	t.Logf("plain directories 1100 deep: %d reads, %v", reads, time.Since(start))
	if reads != unixPlaceNames || got != deep+"s.sock" || ok {
		t.Errorf("plain directories 1100 deep: %d reads, place %q %v, want %d reads, not placed", reads, got, ok, unixPlaceNames)
	}
}

// TestResolveUnixPlaceFollowsALinkBeforeItsDotDot: on a real filesystem, a ".." after a
// symlink — in a dangling link's target, in the path itself, or after a component that does not exist yet — is
// applied after that symlink is followed, as the kernel's lookup and realpath -m apply it, by compile's resolution
// (resolveDeepest) and by ResolveUnixPlace over ReadPlaceLink, the read compile and the supervisor kernel make. Before, a link's target was joined and cleaned lexically, so P/s -> sub/../x.sock
// with P/sub -> real/deep was placed at P/x.sock, where an approval for the scope then connected a socket the declared
// path never leads to.
func TestResolveUnixPlaceFollowsALinkBeforeItsDotDot(t *testing.T) {
	P, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(P, "real", "deep"), 0o755); err != nil {
		t.Fatal(err)
	}
	for link, target := range map[string]string{
		"sub":  "real/deep",
		"s":    "sub/../x.sock",
		"m":    "sub/../nodir",
		"dl":   "nodir2/../sub/w.sock",
		"abs":  P + "/sub/../a.sock",
		"two":  "m/../../b.sock",
		"loop": "loop",
	} {
		if err := os.Symlink(target, filepath.Join(P, link)); err != nil {
			t.Fatal(err)
		}
	}
	realpath, rpErr := exec.LookPath("realpath")
	for name, want := range map[string]string{
		"s":                      "real/x.sock",
		"m/z.sock":               "real/nodir/z.sock",
		"sub/../y.sock":          "real/y.sock",
		"nodir/../sub/../x.sock": "real/x.sock",
		"dl":                     "real/deep/w.sock",
		"abs":                    "real/a.sock",
		"two":                    "b.sock",
		"sub/q.sock":             "real/deep/q.sock",
		"real/deep/../../c.sock": "c.sock",
		"nodir/a/../../d.sock":   "d.sock",
	} {
		p, want := P+"/"+name, P+"/"+want
		if got := resolveDeepest(p); got != want {
			t.Errorf("compile's view: place of %s = %q, want %q", name, got, want)
		}
		if got, ok := ResolveUnixPlace(p, ReadPlaceLink); got != want || !ok {
			t.Errorf("supervisor's view: place of %s = %q, want %q", name, got, want)
		}
		if rpErr == nil {
			out, err := exec.Command(realpath, "-m", "--", p).Output()
			if got := strings.TrimSpace(string(out)); err != nil || got != want {
				t.Errorf("realpath -m %s = %q (%v), want %q: the cell's expectation is not the kernel's", name, got, err, want)
			}
		}
	}
	if got := resolveDeepest(P + "/loop/a.s"); got != P+"/loop/a.s" {
		t.Errorf("a link loop: place %q, want the path as given", got)
	}
}

func TestAskCompiledDefaultsKeepAllTiersOrdinaryDenial(t *testing.T) {
	f := newFixture(t)
	c := f.load("version: 0\nname: a\ncommand: [static-tool]\nfs: {ask: [./out]}\nnet: {ask: ['tcp://192.0.2.1:443']}\n")
	rt, _ := f.compile(c)
	if rt.AskConfig == nil || rt.AskConfig.Hold != AskHoldConnect || len(rt.FSAsk) != 1 || len(rt.NetAsk) != 1 {
		t.Fatalf("compiled asks %+v", rt.AskConfig)
	}
	for _, tier := range []backend.Tier{backend.TierLandlock, backend.TierCgroup, backend.TierBPFLSM} {
		if got := rt.Evaluate(Action{Kind: ActionNetConnect, Host: "192.0.2.1", Port: 443, Proto: ProtoTCP}, tier); got.Verdict != VerdictRefused {
			t.Fatalf("ask became ordinary grant %s %+v", tier, got)
		}
	}
}

// ask.on_timeout takes refuse (the default, also when the key is absent) or refuse_always, nothing else; the compiled
// table prints it, with what refuse_always does.
func TestAskOnTimeout(t *testing.T) {
	base := "version: 0\nname: a\ncommand: [x]\nfs: {ask: [/work]}\n"
	for _, bad := range []string{"ask: {on_timeout: allow}", "ask: {on_timeout: refuse-always}", "ask: {on_timeout: null}", "ask: {on_timeout: 1}", "ask: {on_timeout: ''}"} {
		if _, ds, e := LoadBytes("ask.yaml", []byte(base+bad+"\n"), nil); e == nil || !hasCode(ds, CodeSchema) {
			t.Fatalf("accepted %q: %v %v", bad, ds, e)
		}
	}
	for src, want := range map[string]AskOnTimeout{"": AskOnTimeoutRefuse, "ask: {on_timeout: refuse}\n": AskOnTimeoutRefuse, "ask: {on_timeout: refuse_always}\n": AskOnTimeoutRefuseAlways} {
		c, ds, e := LoadBytes("ask.yaml", []byte(base+src), nil)
		if e != nil {
			t.Fatalf("%q: %v %v", src, ds, e)
		}
		p, e := CompileAskConfig(c)
		if e != nil || p.OnTimeout != want {
			t.Fatalf("%q: %+v %v; want on_timeout %s", src, p, e, want)
		}
		var out strings.Builder
		pr := &printer{w: &out}
		pr.ask(p)
		if !strings.Contains(out.String(), "on_timeout="+string(want)) || strings.Contains(out.String(), "refused at once") != (want == AskOnTimeoutRefuseAlways) {
			t.Fatalf("%q printed %q", src, out.String())
		}
	}
}

// TestResolveUnixPlaceFollowsTheKernelsFortyLinks: on a real filesystem, a chain of 40 short
// links is placed where the kernel's lookup lands, and one of 41, which the kernel refuses ELOOP, is not placed. The
// links are short, so the bound on names never ends either walk: only the bound on links tells the two apart.
func TestResolveUnixPlaceFollowsTheKernelsFortyLinks(t *testing.T) {
	P, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(P+"/real", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(P+"/real/s.sock", nil, 0o600); err != nil {
		t.Fatal(err)
	}
	var want unix.Stat_t
	if err := unix.Stat(P+"/real/s.sock", &want); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		prefix string
		links  int
	}{{"a", 40}, {"b", 41}} {
		for i := 0; i < c.links; i++ {
			target := c.prefix + strconv.Itoa(i+1)
			if i == c.links-1 {
				target = "real"
			}
			if err := os.Symlink(target, P+"/"+c.prefix+strconv.Itoa(i)); err != nil {
				t.Fatal(err)
			}
		}
		p := P + "/" + c.prefix + "0/s.sock"
		var st unix.Stat_t
		statErr := unix.Stat(p, &st)
		got, ok := ResolveUnixPlace(p, ReadPlaceLink)
		if c.links == 40 {
			if statErr != nil || st.Ino != want.Ino {
				t.Fatalf("the kernel's stat through %d links: %v (ino %d, want %d)", c.links, statErr, st.Ino, want.Ino)
			}
			if got != P+"/real/s.sock" || !ok {
				t.Errorf("%d links: place %q %v, want %q true, where the kernel's lookup lands", c.links, got, ok, P+"/real/s.sock")
			}
			continue
		}
		if !errors.Is(statErr, unix.ELOOP) {
			t.Fatalf("the kernel's stat through %d links: %v, want ELOOP", c.links, statErr)
		}
		if got != p || ok {
			t.Errorf("%d links: place %q %v, want the path as given, not placed, as the kernel refuses it", c.links, got, ok)
		}
	}
}

// TestResolveUnixPlaceDoesNotFollowANameMadeALinkAfterItsRead: on a real filesystem, a name
// the walk read as no symlink (nothing there yet) that another thread of the agent then makes a symlink ends the
// placement, not placed, at the next read: each read (ReadPlaceLink) walks the directories before its name without
// following any symlink, so none of the walk's later names is read through a link the walk did not follow. Before,
// every later read walked the whole path from the root again and followed the new link: through a chain of 39 links
// that each go 780 directories down and back, 516 reads took 1.46 s for one placement, and through a link to a
// directory holding a dangling link, the name was placed where that link points, a place the walk never chose.
func TestResolveUnixPlaceDoesNotFollowANameMadeALinkAfterItsRead(t *testing.T) {
	P, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	const depth = 780
	for _, d := range []string{"R", "D/" + strings.Repeat("m/", depth)} {
		if err := os.MkdirAll(P+"/"+d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("/nonexistent-elsewhere", P+"/R/k"); err != nil {
		t.Fatal(err)
	}
	down, up := strings.Repeat("m/", depth), strings.Repeat("../", depth)
	for i := 1; i < 40; i++ {
		target := down + up + "c" + strconv.Itoa(i+1)
		if i == 39 {
			target = P + "/R"
		}
		if err := os.Symlink(target, P+"/D/c"+strconv.Itoa(i)); err != nil {
			t.Fatal(err)
		}
	}
	for _, c := range []struct {
		name, path, swapTo string
	}{
		{"a link to a directory holding a dangling link", "/D/N/k/s.sock", P + "/R"},
		{"a chain of 39 long links", "/D/N/" + strings.Repeat("x/../", 800) + "app.sock", "c1"},
	} {
		_ = os.Remove(P + "/D/N")
		swapped, after := false, 0
		hooked := func(p string) (string, error) {
			if swapped {
				after++
			}
			v, err := ReadPlaceLink(p)
			if p == P+"/D/N" && !swapped {
				if err == nil {
					t.Fatalf("%s: D/N is there before the swap", c.name)
				}
				if err := os.Symlink(c.swapTo, P+"/D/N"); err != nil {
					t.Fatal(err)
				}
				swapped = true
			}
			return v, err
		}
		start := time.Now()
		got, ok := ResolveUnixPlace(P+c.path, hooked)
		took := time.Since(start)
		t.Logf("%s: %d reads after the swap, %v", c.name, after, took)
		if !swapped {
			t.Fatalf("%s: the walk never read D/N", c.name)
		}
		if got != P+c.path || ok {
			t.Errorf("%s: place %q %v, want the path as given, not placed", c.name, got, ok)
		}
		if after > 1 {
			t.Errorf("%s: %d reads after D/N became a link, want the placement to end at the first", c.name, after)
		}
	}
}
