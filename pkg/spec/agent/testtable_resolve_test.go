// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// TestRunResolvedAsksTheWalkOfEachPath pins what RunResolved asks its Lander (ADR 0019's 2026-10-17 design note): each
// path of a row as the agent's syscall would spell it from the table's cwd, uncleaned, so "lk/.." is the walk's to
// take physically, and with the lookup that syscall makes of it (ActionKind.Lookups): a final symlink followed where
// the syscall follows one (an open, an exec and its #! interpreter, an attribute change, a unix connect or datagram),
// a dangling one to the name an O_CREAT open makes (a write), the whole path unfollowed for a link's old name, and the
// name made in its directory where the syscall makes, removes or renames it (an unlink, a mkdir, both ends of a rename,
// a link's new name, a unix bind); nothing asked of a bare command, an abstract name, an HTTP request or a socket. A
// link's old name was asked as a name-making end, so compile evaluated out/lk/. at the symlink out/lk where the run and
// the kernel act on where it leads. A
// landed path that differs from the spelling cleaned is reported; one the walk cannot land is evaluated cleaned. Rows
// were cleaned before they were resolved, so a row's out/lk/../x2 was answered on out/x2 while the kernel walks
// out/lk/... A unix connect or datagram keeps its name in Path, the run's first
// decision, and carries the socket the walk reaches in Landed, its second; nothing was asked of one, so a name through
// a symlink in a write entry was answered allow for a socket outside it that the run refused, and a relative name
// joins cwd as the run joins it to the agent's.
func TestRunResolvedAsksTheWalkOfEachPath(t *testing.T) {
	type ask struct {
		p   string
		how Lookup
	}
	table, ds, err := LoadTestTableBytes("t.yaml", []byte(`version: 0
tests:
  - {action: fs.rename, path: out/x, dest: out/lk/../x2, expect: allow}
  - {action: fs.link, path: out/./y, dest: /abs/lk/../y2, expect: allow}
  - {action: fs.read, path: out/lk/../r, expect: allow}
  - {action: fs.write, path: out//w, expect: allow}
  - {action: fs.delete, path: out/lk, expect: allow}
  - {action: fs.attr, path: out/lk, expect: allow}
  - {action: exec, path: ./bin/../tool, script: /usr/bin/../bin/sh, expect: allow}
  - {action: exec, argv: [rg], expect: allow}
  - {action: net.bind, host_port: "unix:/run/lk/../s.sock", expect: allow}
  - {action: net.connect, path: "unix:/run/lk/../s.sock", expect: allow}
  - {action: fs.read, path: gone/f, expect: allow}
  - {action: fs.read, path: "~/lk/../k", expect: allow}
  - {action: net.send, path: "unix:rel/lk/s.sock", expect: allow}
  - {action: net.connect, path: "unix:@abs", expect: allow}
  - {action: net.bind, host_port: "unix:/w/file/s.sock", expect: allow}
  - {action: net.bind, host_port: "unix:/w/unwalked/f", expect: allow}
  - {action: net.send, path: "unix:loop/s.sock", expect: allow}
`))
	if err != nil {
		t.Fatalf("%v %s", err, render(ds))
	}
	var asked, askedUnix []ask
	path := func(p string, how Lookup) (string, error) {
		asked = append(asked, ask{p, how})
		switch p {
		case "/w/out/lk/../x2":
			return "/w/out/realbin/x2", nil
		case "/w/gone/f", "/w/file/s.sock":
			return "", unix.ENOTDIR
		case "/w/unwalked/f":
			return "", ErrUnwalked
		}
		return "/landed" + p, nil
	}
	// A unix name is asked of the run's unix walk, which also says what it met; it follows the final link, as connect
	// and sendto do.
	unixLand := func(p string) (UnixLanding, error) {
		askedUnix = append(askedUnix, ask{p, LookupFollow})
		if p == "/w/loop/s.sock" {
			return UnixLanding{Walk: UnixWalkUnreliable}, nil
		}
		return UnixLanding{At: "/landed" + p}, nil
	}
	land := Landers{Path: path, Unix: unixLand}
	var got []Action
	eval := func(_ *RuleTable, a Action, _ backend.Tier) EvalResult {
		got = append(got, a)
		return EvalResult{Verdict: VerdictAllow}
	}
	res := table.RunResolved(eval, &RuleTable{Tier: backend.TierLandlock, Home: "/home/u"}, "/w", land, backend.TierLandlock)
	want := []ask{
		{"/w/out/x", LookupParent}, {"/w/out/lk/../x2", LookupParent}, // the rename's source, then its new name
		{"/abs/lk/../y2", LookupParent}, {"/w/out/./y", LookupNoFollow}, // a link's new name, and its old name looked up whole
		{"/w/out/lk/../r", LookupFollow},
		{"/w/out//w", LookupCreate},
		{"/w/out/lk", LookupParent},
		{"/w/out/lk", LookupFollow},
		{"/usr/bin/../bin/sh", LookupFollow}, {"/w/./bin/../tool", LookupFollow},
		{"/run/lk/../s.sock", LookupParent},
		{"/w/gone/f", LookupFollow},
		{"/home/u/lk/../k", LookupFollow},
		{"/w/file/s.sock", LookupParent}, {"/w/unwalked/f", LookupParent},
	}
	wantUnix := []ask{
		{"/run/lk/../s.sock", LookupFollow}, // the connect's name, followed
		{"/w/rel/lk/s.sock", LookupFollow},  // the datagram's relative name, joined to cwd
		{"/w/loop/s.sock", LookupFollow},
	}
	if !slices.Equal(askedUnix, wantUnix) {
		t.Errorf("asked the unix walk\n%v\nwant\n%v", askedUnix, wantUnix)
	}
	// The rename's ends are asked dest first (resolveAction lands DestPath before Path): compare as sets per row.
	byText := func(a, b ask) int { return strings.Compare(fmt.Sprint(a), fmt.Sprint(b)) }
	slices.SortFunc(asked, byText)
	slices.SortFunc(want, byText)
	if !slices.Equal(asked, want) {
		t.Errorf("asked\n%v\nwant\n%v", asked, want)
	}
	if len(got) != len(table.Rows) {
		t.Fatalf("evaluated %d rows, want %d", len(got), len(table.Rows))
	}
	for i, c := range []struct{ path, dest, script string }{
		{"/landed/w/out/x", "/w/out/realbin/x2", ""},
		{"/landed/w/out/./y", "/landed/abs/lk/../y2", ""},
		{"/landed/w/out/lk/../r", "", ""},
		{"/landed/w/out//w", "", ""},
		{"/landed/w/out/lk", "", ""},
		{"/landed/w/out/lk", "", ""},
		{"/landed/w/./bin/../tool", "", "/landed/usr/bin/../bin/sh"},
		{"", "", ""},
		{"/landed/run/lk/../s.sock", "", ""},
		{"unix:/run/lk/../s.sock", "", ""},
		{"/w/gone/f", "", ""}, // not landed: the spelling, cleaned
		{"/landed/home/u/lk/../k", "", ""},
		{"unix:/w/rel/lk/s.sock", "", ""},
		{"unix:@abs", "", ""},
		{"/w/file/s.sock", "", ""}, {"/w/unwalked/f", "", ""},
		{"unix:/w/loop/s.sock", "", ""},
	} {
		if got[i].Path != c.path || got[i].DestPath != c.dest || got[i].Script != c.script {
			t.Errorf("row %d evaluated %q %q %q, want %q %q %q", i, got[i].Path, got[i].DestPath, got[i].Script, c.path, c.dest, c.script)
		}
	}
	// A unix connect's and a datagram's names keep their spelling and carry the socket the walk reached; nothing else
	// carries one.
	for i, g := range got {
		want := map[int]string{9: "/landed/run/lk/../s.sock", 12: "/landed/w/rel/lk/s.sock"}[i]
		if g.Landed != want {
			t.Errorf("row %d landed %q, want %q", i, g.Landed, want)
		}
	}
	// What the walk met rides on the action: the unix walk's own answer for a
	// datagram through a loop, and for a bind whose walk failed as the agent's lookup fails the refusal the run's
	// bindUnix gives it, but not for one the Lander could not make (ErrUnwalked), which is evaluated as written.
	for i, g := range got {
		want := map[int]UnixWalk{14: UnixWalkUnreliable, 16: UnixWalkUnreliable}[i]
		if g.Walk != want {
			t.Errorf("row %d walk %d, want %d", i, g.Walk, want)
		}
	}
	if r := res[9].Resolved; r.Path != "/landed/run/lk/../s.sock" {
		t.Errorf("connect resolved %+v", r)
	}
	// Reported only where the landing differs from the spelling cleaned.
	if r := res[0].Resolved; r.Dest != "/w/out/realbin/x2" {
		t.Errorf("rename resolved %+v", r)
	}
	if r := res[10].Resolved; r != (ResolvedPaths{}) {
		t.Errorf("an unlanded path reported %+v", r)
	}
	// A walk that lands on the spelling cleaned reports nothing, and with no Lander every row is evaluated cleaned.
	same := Landers{
		Path: func(p string, _ Lookup) (string, error) { return filepath.Clean(p), nil },
		Unix: func(p string) (UnixLanding, error) { return UnixLanding{At: filepath.Clean(p)}, nil },
	}
	for _, r := range table.RunResolved(eval, &RuleTable{Tier: backend.TierLandlock, Home: "/home/u"}, "/w", same, backend.TierLandlock) {
		if r.Resolved != (ResolvedPaths{}) {
			t.Errorf("%s: reported %+v for a path that landed on its spelling", r.Row.Label(), r.Resolved)
		}
	}
	got = nil
	table.RunResolved(eval, &RuleTable{Tier: backend.TierLandlock, Home: "/home/u"}, "/w", Landers{}, backend.TierLandlock)
	if got[0].DestPath != "/w/out/x2" || got[1].Path != "/w/out/y" {
		t.Errorf("with no Lander: %q %q, want the spellings cleaned", got[0].DestPath, got[1].Path)
	}
}

// TestRunResolvedJoinsThePhysicalCwd: a landed table run with no cwd joins its relative rows to the working directory
// as getcwd(2) reports it, every symlink resolved, the directory the run joins an agent's relative names to
// (readlink /proc/<pid>/cwd), not $PWD, which spells it through the symlink the shell came by. The difference shows
// where the walk fails (ENOTDIR beneath a file): the row is then evaluated as written, joined to that directory. An
// earlier
// fix made run's default getcwd(2)'s, and nothing held it.
func TestRunResolvedJoinsThePhysicalCwd(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	realDir, link := filepath.Join(dir, "real"), filepath.Join(dir, "link")
	if err := os.Mkdir(realDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("real", link); err != nil {
		t.Fatal(err)
	}
	t.Chdir(link) // and $PWD with it, which os.Getwd answers
	if wd, err := os.Getwd(); err != nil || wd != link {
		t.Fatalf("os.Getwd() = %q, %v; the test needs $PWD through the symlink, %q", wd, err, link)
	}
	table, ds, err := LoadTestTableBytes("t.yaml", []byte("version: 0\ntests:\n  - {action: fs.read, path: f/x, expect: allow}\n"))
	if err != nil {
		t.Fatalf("%v %s", err, render(ds))
	}
	var got Action
	eval := func(_ *RuleTable, a Action, _ backend.Tier) EvalResult {
		got = a
		return EvalResult{Verdict: VerdictAllow}
	}
	var asked string
	enotdir := Landers{Path: func(p string, _ Lookup) (string, error) {
		asked = p
		return "", unix.ENOTDIR
	}}
	table.RunResolved(eval, &RuleTable{Tier: backend.TierLandlock}, "", enotdir, backend.TierLandlock)
	if want := filepath.Join(realDir, "f", "x"); asked != want || got.Path != want {
		t.Errorf("walked %q, evaluated %q; want both %q, the physical cwd's", asked, got.Path, want)
	}
}
