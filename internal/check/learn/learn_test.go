// SPDX-License-Identifier: Apache-2.0

package learn

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

const ws = "/work/project"

func TestNameCoverageRenameKeepsRefusalAndExplainsContractChange(t *testing.T) {
	r := newRun(t, ws)
	e := r.add(record.KindRefused, record.VerdictRefused, record.RefusedPayload{Op: record.FSRename,
		Target: ws + "/tmp/package", Reason: record.ReasonRenameOutsideContract, Rule: "fs.deny_read[" + ws + "/**/.env]"})
	e.Reason, e.Rule = record.ReasonRenameOutsideContract, "fs.deny_read["+ws+"/**/.env]"
	p := r.propose(Options{})
	if len(p.Write) != 0 || p.Refused != 1 {
		t.Fatalf("a refused rename became an allow: %+v", p)
	}
	for _, want := range []string{"protected-name coverage", `fs.write: ["./tmp/", "./target/"]`, "existing", "same exec.allow", "cd target", "Write entries alone add no name coverage", `fs.write: ["../tmp/", "./"]`} {
		if !strings.Contains(p.Contract(), want) {
			t.Errorf("proposal lacks remedy %q:\n%s", want, p.Contract())
		}
	}
}

// TestWritesStayUnderTheWorkspace: fs.write is the directories under the workspace the run wrote to, and a write
// anywhere else is reported, never allowed (C9: "never a broader directory than the workspace").
func TestWritesStayUnderTheWorkspace(t *testing.T) {
	r := newRun(t, ws)
	r.open(ws+"/out/a.txt", wronly|creat)
	r.open(ws+"/out/deep/b.txt", wronly|creat) // under out/: one entry covers it
	r.open(ws+"/cache/c.txt", rdwr)
	r.fs(record.FSUnlink, ws+"/tmp/x", "", 0)
	r.open("/etc/passwd", wronly)           // outside the workspace
	r.open("/work/project-other/x", wronly) // a sibling that shares the workspace's name as a prefix
	r.open("/home/u/.claude/state.json", wronly|creat)
	r.fs(record.FSMkdir, "/home/u/.claude/backups", "", 0)
	r.open(ws+"/read-only.txt", rdonly) // a read is not a write
	c := r.propose(Options{}).Contract()

	if got, want := entries(c, "fs"), []string{ws + "/cache/", ws + "/out/", ws + "/tmp/"}; !slices.Equal(got, want) {
		t.Errorf("fs.write = %q, want %q\n%s", got, want, c)
	}
	for _, want := range []string{
		`observed, not allowed: writes under /etc/ (seen once): outside the workspace /work/project`,
		`observed, not allowed: writes under /home/u/.claude/ (seen 2 times)`,
		`observed, not allowed: writes under /work/project-other/ (seen once)`,
	} {
		if !strings.Contains(c, want) {
			t.Errorf("the proposal lacks %q\n%s", want, c)
		}
	}
	load(t, c)
}

// TestWorkspaceFlagWidensTheWritesNotTheirReach: --workspace names the directory writes may be allowed under, so a
// state directory beside the project becomes allowed when the workspace holds both, and still nothing outside it.
func TestWorkspaceFlagWidensTheWritesNotTheirReach(t *testing.T) {
	r := newRun(t, ws)
	r.open(ws+"/out/a.txt", wronly)
	r.open("/work/state/.claude/x.json", wronly)
	r.open("/elsewhere/y", wronly)
	c := r.propose(Options{Workspace: "/work"}).Contract()
	if got, want := entries(c, "fs"), []string{"/work/project/out/", "/work/state/.claude/"}; !slices.Equal(got, want) {
		t.Errorf("fs.write = %q, want %q\n%s", got, want, c)
	}
	if !strings.Contains(c, "observed, not allowed: writes under /elsewhere/") {
		t.Errorf("a write outside the named workspace is not reported\n%s", c)
	}
}

// TestWriteOperations: every operation that changes the file system names the directory it needs, and a symlink's
// target and a read-only open are not writes.
func TestWriteOperations(t *testing.T) {
	r := newRun(t, ws)
	r.fs(record.FSMkdir, ws+"/made", "", 0)                           // the directory made, not its parent
	r.fs(record.FSRename, ws+"/a/old", ws+"/b/new", 0)                // both ends
	r.fs(record.FSLink, ws+"/c/src", ws+"/d/link", 0)                 // both ends
	r.fs(record.FSSymlink, ws+"/e/link", "/usr/share/target/file", 0) // the link made; its target is only read
	r.fs(record.FSChmod, ws+"/f/g", "", 0)
	r.open(ws+"/h/i", rdonly|creat) // creating with a read-only open still changes the directory
	r.open(ws+"/j/k", rdonly)       // a read
	c := r.propose(Options{}).Contract()
	want := []string{ws + "/a/", ws + "/b/", ws + "/c/", ws + "/d/", ws + "/e/", ws + "/f/", ws + "/h/", ws + "/made/"}
	if got := entries(c, "fs"); !slices.Equal(got, want) {
		t.Errorf("fs.write = %q, want %q\n%s", got, want, c)
	}
}

// TestDevicesWhenOpened: /dev/null and /dev/tty are proposed when the run opened them, whatever the access: a
// read-only open of /dev/tty is what bash -i is refused for without the grant.
func TestDevicesWhenOpened(t *testing.T) {
	r := newRun(t, ws)
	r.open("/dev/tty", rdonly)
	r.open("/dev/null", wronly)
	r.open("/dev/zero", rdonly)
	c := r.propose(Options{}).Contract()
	if got, want := entries(c, "fs"), []string{"/dev/null", "/dev/tty"}; !slices.Equal(got, want) {
		t.Errorf("fs.write = %q, want %q\n%s", got, want, c)
	}
	none := newRun(t, ws).propose(Options{}).Contract()
	if got := entries(none, "fs"); len(got) != 0 {
		t.Errorf("a run that opened no device got %q", got)
	}
}

// TestStateDirectoriesAreNeverWritable: an entry that is, is inside or holds tego's own state directory is never
// proposed, because tego refuses a contract that lets the agent write them.
func TestStateDirectoriesAreNeverWritable(t *testing.T) {
	r := newRun(t, ws)
	r.open(ws+"/out/a", wronly)
	r.open(ws+"/.tego/runs/r-1/events.jsonl", wronly) // inside the state directory
	r.open(ws+"/chain.log", wronly)                   // makes the workspace itself an entry, which holds it
	c := r.propose(Options{StateDirs: []string{ws + "/.tego"}}).Contract()
	if got, want := entries(c, "fs"), []string{ws + "/out/"}; !slices.Equal(got, want) {
		t.Errorf("fs.write = %q, want %q\n%s", got, want, c)
	}
	for _, want := range []string{"inside tego's own state directory " + ws + "/.tego", "it holds tego's own state directory " + ws + "/.tego"} {
		if !strings.Contains(c, want) {
			t.Errorf("the proposal does not say why: %q\n%s", want, c)
		}
	}
}

// TestWorkspaceMayNotBeRoot: / is every directory, so it is refused as a workspace, as is one that is not absolute.
func TestWorkspaceMayNotBeRoot(t *testing.T) {
	r := newRun(t, ws)
	for _, w := range []string{"/", "//", "/x/..", "relative/dir"} {
		if _, err := propose(r.events, Options{Workspace: w}); err == nil {
			t.Errorf("workspace %q was accepted", w)
		}
	}
	// A run whose own working directory is / has no workspace to allow writes under: its writes are reported and
	// none is allowed, and the proposal says to name one.
	r = newRun(t, "/")
	r.open("/var/tmp/x", wronly)
	p, err := propose(r.events, Options{})
	if err != nil {
		t.Fatal(err)
	}
	c := p.Contract()
	if got := entries(c, "fs"); len(got) != 0 || p.Workspace != "" || !strings.Contains(c, "no workspace to allow writes under: the run's working directory was /") {
		t.Errorf("a run started in /: workspace %q, fs.write %q\n%s", p.Workspace, got, c)
	}
	if p, err = propose(r.events, Options{Workspace: "/var"}); err != nil || !slices.Equal(entries(p.Contract(), "fs"), []string{"/var/tmp/"}) {
		t.Errorf("--workspace for a run started in /: %v\n%s", err, p.Contract())
	}
}

// TestManyDirectoriesAreMergedNotWidened: more than maxWriteDirs entries are merged to the first level under the
// workspace, then to the workspace itself, never above it.
func TestManyDirectoriesAreMergedNotWidened(t *testing.T) {
	r := newRun(t, ws)
	for i := range 4 * maxWriteDirs { // 128 directories under 10 first-level ones
		r.open(fmt.Sprintf("%s/t%d/s%d/f", ws, i%10, i), wronly)
	}
	p := r.propose(Options{})
	got := entries(p.Contract(), "fs")
	if len(got) != 10 || p.Collapsed != "the first level under the workspace" || got[0] != ws+"/t0/" {
		t.Fatalf("%d entries %q (collapsed %q), want the ten first-level directories", len(got), got, p.Collapsed)
	}
	if !strings.Contains(p.Contract(), "merged to the first level under the workspace") {
		t.Errorf("the merge is not said\n%s", p.Contract())
	}
	if c := p.Contract(); !strings.Contains(c, fmt.Sprintf(`%q  # seen 13 times`, ws+"/t0/")) {
		t.Errorf("the merged entry does not carry the writes under it\n%s", c)
	}

	// 64 first-level directories are still too many: the workspace itself, and nothing above it.
	r = newRun(t, ws)
	for i := range 2 * maxWriteDirs {
		r.open(fmt.Sprintf("%s/d%d/f", ws, i), wronly)
	}
	if got := entries(r.propose(Options{}).Contract(), "fs"); !slices.Equal(got, []string{ws + "/"}) {
		t.Errorf("fs.write = %q, want the workspace alone", got)
	}
}

// TestExecIsTheOtherProgramsNotTheAgent: exec.allow is the distinct programs started, not the agent's own first one,
// each once, and a PATH search's misses are not programs that started.
func TestExecIsTheOtherProgramsNotTheAgent(t *testing.T) {
	r := newRun(t, ws, "agent", "--flag")
	r.exec(10, "/opt/agent/bin/agent", "agent", "--flag")
	r.exec(11, "/usr/bin/git", "git", "status")
	r.exec(12, "/usr/bin/git", "git", "log")
	r.exec(13, "/opt/agent/bin/agent", "agent", "--child") // the agent starting itself again
	// pid 14 searches PATH for tool: three tries, the last one ran. One of the misses is listed twice.
	r.exec(14, "/home/u/bin/tool", "tool", "-x")
	r.exec(14, "/home/u/bin/tool", "tool", "-x")
	r.exec(14, "/usr/local/bin/tool", "tool", "-x")
	r.exec(14, "/usr/bin/tool", "tool", "-x")
	p := r.propose(Options{})
	c := p.Contract()
	if got, want := entries(c, "exec"), []string{"/usr/bin/git", "/usr/bin/tool"}; !slices.Equal(got, want) {
		t.Errorf("exec.allow = %q, want %q\n%s", got, want, c)
	}
	if p.SearchMisses != 3 || !strings.Contains(c, "3 exec attempts that were not a program starting") {
		t.Errorf("search misses = %d\n%s", p.SearchMisses, c)
	}
	if !strings.Contains(c, `"/usr/bin/git"  # seen 2 times`) {
		t.Errorf("git was started twice\n%s", c)
	}
}

// TestRunCommandGrantIsTheAgentToo: the program the command line after -- named is admitted by the run, so it is not
// proposed even when it is not the first thing exec'd.
func TestRunCommandGrantIsTheAgentToo(t *testing.T) {
	r := newRun(t, ws)
	r.events[0].Payload = []byte(`{"command":["agent"],"cwd":"` + ws + `","run_command_grant":"/opt/agent"}`)
	r.exec(10, "/usr/bin/env", "env", "agent")
	r.exec(10, "/opt/agent", "agent")
	if got := entries(r.propose(Options{}).Contract(), "exec"); len(got) != 0 {
		t.Errorf("exec.allow = %q, want the agent left out", got)
	}
}

// TestSandboxMakersAreNotProposed: a program that sets up a mount namespace fails inside a Landlock domain, so it is
// reported and not allowed (an agent's own sandbox probes bwrap at start-up).
func TestSandboxMakersAreNotProposed(t *testing.T) {
	r := newRun(t, ws)
	r.exec(10, "/usr/bin/agent")
	r.exec(11, "/usr/bin/bwrap", "bwrap", "--unshare-user", "/bin/true")
	r.exec(12, "/usr/bin/unshare", "unshare", "-m")
	r.exec(13, "/usr/bin/git", "git")
	c := r.propose(Options{}).Contract()
	if got := entries(c, "exec"); !slices.Equal(got, []string{"/usr/bin/git"}) {
		t.Errorf("exec.allow = %q, want git alone\n%s", got, c)
	}
	if !strings.Contains(c, "observed, not allowed: /usr/bin/bwrap (seen once): it sets up a mount namespace") {
		t.Errorf("bwrap is not reported\n%s", c)
	}
}

// TestRefusedAndFailedActionsAreNotProposed: a refused action did not happen, and neither did one that failed.
func TestRefusedAndFailedActionsAreNotProposed(t *testing.T) {
	r := newRun(t, ws)
	r.exec(10, "/usr/bin/agent")
	r.add(record.KindExec, record.VerdictRefused, record.ExecPayload{Path: "/usr/bin/curl", Argv: []string{"curl"}, ExecID: "r/11/1"})
	r.add(record.KindFS, record.VerdictRefused, record.FSPayload{Op: record.FSOpen, Path: ws + "/denied/f", Flags: wronly})
	r.add(record.KindFS, record.VerdictObserved, record.FSPayload{Op: record.FSOpen, Path: ws + "/enoent/f", Flags: wronly | creat, Errno: 2})
	r.add(record.KindNet, record.VerdictRefused, record.NetPayload{Proto: "tcp", Dst: "203.0.113.9:443"})
	r.add(record.KindNet, record.VerdictAsk, record.NetPayload{Proto: "tcp", Dst: "203.0.113.10:443"})
	r.add(record.KindRefused, "", record.RefusedPayload{})
	p := r.propose(Options{})
	c := p.Contract()
	for _, sec := range []string{"fs", "exec", "net"} {
		if got := entries(c, sec); len(got) != 0 {
			t.Errorf("%s holds %q", sec, got)
		}
	}
	if p.Refused != 5 || p.Failed != 1 {
		t.Errorf("refused %d failed %d, want 5 and 1", p.Refused, p.Failed)
	}
	if !strings.Contains(c, "5 actions the record shows refused or held") {
		t.Errorf("the header does not say so\n%s", c)
	}
}

// TestRefusedMirrorCountsOnce: the pipeline writes a refused line right after the refused action it mirrors, and the
// pair is one refusal, the count drift and measure give; a refused line standing alone is still a refusal.
func TestRefusedMirrorCountsOnce(t *testing.T) {
	r := newRun(t, ws)
	r.exec(10, "/usr/bin/agent")
	r.add(record.KindFS, record.VerdictRefused, record.FSPayload{Op: record.FSOpen, Path: ws + "/denied/f", Flags: wronly})
	r.add(record.KindRefused, "", record.RefusedPayload{})
	r.add(record.KindNet, record.VerdictRefused, record.NetPayload{Proto: "tcp", Dst: "203.0.113.9:443"})
	r.add(record.KindRefused, "", record.RefusedPayload{})
	r.add(record.KindRefused, "", record.RefusedPayload{}) // on its own: nothing before it mirrors
	p := r.propose(Options{})
	if p.Refused != 3 {
		t.Errorf("refused %d, want 3 (two mirrored pairs and one line on its own)", p.Refused)
	}
	if c := p.Contract(); !strings.Contains(c, "3 actions the record shows refused or held") {
		t.Errorf("the header does not say so\n%s", c)
	}
}

// TestNetworkEndpoints: TCP and UDP destinations become entries as addresses with the hostname hint, DNS to the
// resolver and a datagram socket disconnecting need none, and a raw socket is reported.
func TestNetworkEndpoints(t *testing.T) {
	r := newRun(t, ws)
	r.net("tcp", "160.79.104.10:443")
	r.net("tcp", "160.79.104.10:443")
	r.net("tcp", "[2607:6bc0::10]:443")
	r.net("udp", "160.79.104.10:443")
	r.net("tcp", "[::ffff:10.1.2.3]:8080")
	r.net("udp", "127.0.0.53:53") // the resolver: tego allows it itself
	r.net("tcp", "127.0.0.53:53")
	r.net("udp", "unspec")
	r.net("tcp", "127.0.0.1:0")
	r.net("raw", "family(16)")
	r.net("tcp", "not an address")
	// The forwarder's request policy is a decision about a request, not a connection the run made.
	r.add(record.KindNet, record.VerdictAllow, record.NetPayload{Op: "http_request", Proto: "http", Dst: "model.test.invalid:443", Method: "POST", Path: "/v1/messages"})
	c := r.propose(Options{}).Contract()
	if strings.Contains(c, "model.test.invalid") {
		t.Errorf("an http_request line became an entry or a left-out report\n%s", c)
	}
	want := []string{"tcp://160.79.104.10:443", "tcp://10.1.2.3:8080", "tcp://[2607:6bc0::10]:443", "udp://160.79.104.10:443"}
	slices.Sort(want)
	got := entries(c, "net")
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Errorf("net.allow = %q, want %q\n%s", got, want, c)
	}
	for _, w := range []string{
		`"tcp://160.79.104.10:443"  # seen 2 times`,
		"never the host name it asked for",
		`for example "tcp://api.example.com:443"`,
		"observed, not allowed: raw socket family(16) (seen once): a netlink socket",
		"observed, not allowed: tcp 127.0.0.1:0 (seen once): port 0",
		"observed, not allowed: tcp not an address (seen once)",
	} {
		if !strings.Contains(c, w) {
			t.Errorf("the proposal lacks %q\n%s", w, c)
		}
	}
	if strings.Contains(strings.Join(entries(c, "net"), "\n"), "127.0.0.53") {
		t.Errorf("DNS to the resolver was proposed as an endpoint\n%s", c)
	}
	load(t, c)
}

// TestDangerousSocketsAreNeverAllowed: the sockets that give an agent a way out of the run are only reported,
// whether or not the run created them.
func TestDangerousSocketsAreNeverAllowed(t *testing.T) {
	sockets := []struct{ name, sock string }{
		{"the D-Bus session bus", "/run/user/1000/bus"},
		{"the D-Bus session bus by /var/run", "/var/run/user/1000/bus"},
		{"a D-Bus bus in /tmp", "/tmp/dbus-AbCdEf"},
		{"the D-Bus system bus", "/run/dbus/system_bus_socket"},
		{"the D-Bus system bus by /var/run", "/var/run/dbus/system_bus_socket"},
		{"systemd's private socket", "/run/systemd/private"},
		{"the user manager's private socket", "/run/user/1000/systemd/private"},
		{"gpg-agent", "/run/user/1000/gnupg/S.gpg-agent"},
		{"gpg-agent's ssh socket", "/run/user/1000/gnupg/S.gpg-agent.ssh"},
		{"gpg-agent in the home directory", "/home/u/.gnupg/S.gpg-agent"},
		{"an ssh-agent in /tmp", "/tmp/ssh-XXQmLh0aBc/agent.4242"},
		{"the ssh agent in the runtime directory", "/run/user/1000/openssh_agent"},
		{"the keyring's ssh agent", "/run/user/1000/keyring/ssh"},
		{"an X11 socket", "/tmp/.X11-unix/X0"},
		{"an abstract X11 socket", "@/tmp/.X11-unix/X0"},
		{"an abstract systemd bus", "@/org/freedesktop/systemd1/notify"},
		{"docker", "/var/run/docker.sock"},
		{"docker by /run", "/run/docker.sock"},
		{"rootless docker", "/run/user/1000/docker.sock"},
		{"podman", "/run/podman/podman.sock"},
		{"containerd", "/run/containerd/containerd.sock"},
		{"docker anywhere", "/opt/engine/docker.sock"},
		// ADR 0113's built-in refusals refuse these in every enforcing run, so compile refuses an entry for one as a
		// contradiction: a socket under the runtime directory (the run's own runtime directory is a new one each run),
		// a multiplexer's or editor server's, and tego's own.
		{"an unrelated socket under the runtime directory", "/run/user/1000/some-service/sock"},
		{"a run's own runtime directory", "/run/user/1000/tego/r-1/codex/app.sock"},
		{"tmux", "/tmp/tmux-1000/default"},
		{"tmux under TMUX_TMPDIR", "/home/u/.cache/tmux/tmux-1000/default"},
		{"screen", "/run/screen/S-u/1234.pts-0.host"},
		{"screen in the home directory", "/home/u/.screen/1234.pts-0.host"},
		{"emacs", "/tmp/emacs1000/server"},
		{"neovim", "/tmp/nvim.u/0/nvim.1234.0"},
		{"tego's home", "/home/u/.tego/api.sock"},
		{"the ledger's ask socket", "/srv/ledger/ask.sock"},
	}
	for _, created := range []bool{false, true} {
		for _, tc := range sockets {
			t.Run(fmt.Sprintf("%s/created=%v", tc.name, created), func(t *testing.T) {
				r := newRun(t, ws)
				if created {
					r.fs(record.FSChmod, strings.TrimPrefix(tc.sock, "@"), "", 0) // the run made it, as far as the record shows
				}
				r.net("unix", "unix:"+tc.sock)
				p := r.propose(Options{StateDirs: []string{"/srv/ledger"}})
				c := p.Contract()
				if got := entries(c, "net"); len(got) != 0 {
					t.Errorf("net.allow = %q, want nothing\n%s", got, c)
				}
				if !strings.Contains(c, "observed, not allowed: unix:"+tc.sock+" (seen once)") {
					t.Errorf("the socket is not reported\n%s", c)
				}
			})
		}
	}
}

// TestOrdinarySocketsAreAllowed: a unix socket outside the runtime directory that is no dangerous daemon is an
// entry, and one the run created is marked so.
func TestOrdinarySocketsAreAllowed(t *testing.T) {
	r := newRun(t, ws)
	r.net("unix", "unix:/var/run/nscd/socket")
	r.net("unix", "unix:"+ws+"/mcp.sock")
	r.fs(record.FSChmod, ws+"/mcp.sock", "", 0)
	r.net("unix", "unix:@my-service")
	c := r.propose(Options{}).Contract()
	want := []string{"unix:/var/run/nscd/socket", "unix:" + ws + "/mcp.sock", "unix:@my-service"}
	if got := entries(c, "net"); !slices.Equal(got, want) {
		t.Errorf("net.allow = %q, want %q\n%s", got, want, c)
	}
	if !strings.Contains(c, "a socket the run created") {
		t.Errorf("a socket the run created is not marked\n%s", c)
	}
	load(t, c)
}

// TestHostileNamesNeverReachTheContract: the record is the agent's own doing, so a path or a socket name with a
// newline, a quote, a control character or a pattern in it can never become a line of the proposal, a second entry or
// an escape that hides one. A plain name (a quote or a backslash only) is written escaped and loads back unchanged;
// every other is left out and reported.
func TestHostileNamesNeverReachTheContract(t *testing.T) {
	plainNames := map[string]bool{"evil\"quote": true, "back\\slash": true}
	hostile := []string{
		"evil\n    - \"/etc\"", "evil\"quote", "back\\slash", "ctl\x1b[2Jchar", "glob*star", "bidi\u202eexe", "nul\x00byte",
		"bad\xffutf8", "q?mark", "br[acket",
	}
	for _, h := range hostile {
		r := newRun(t, ws)
		r.open(ws+"/"+h+"/f", wronly)
		r.exec(10, "/usr/bin/agent")
		r.exec(11, "/opt/"+h+"/tool")
		r.net("unix", "unix:/tmp/"+h+"/sock")
		r.fs(record.FSChmod, "/etc/"+h, "", 0)
		c := r.propose(Options{}).Contract()
		ct := load(t, c)
		for _, l := range strings.Split(c, "\n") {
			if strings.ContainsAny(l, "\x1b\x00\u202e") {
				t.Errorf("%q reached the file as a raw control or format character: %q", h, l)
			}
		}
		// What loaded is exactly the plain names, written under their own directories, and no "/etc" entry.
		var wantFS, wantExec, wantNet []string
		if plainNames[h] {
			wantFS = []string{ws + "/" + h + "/"}
			wantExec = []string{"/opt/" + h + "/tool"}
			wantNet = []string{"unix:/tmp/" + h + "/sock"}
		}
		if !slices.Equal(ct.FS.Write, wantFS) || !slices.Equal(ct.Exec.Allow, wantExec) || !slices.Equal(ct.Net.Allow, wantNet) {
			t.Errorf("%q loaded as fs %q exec %q net %q, want %q %q %q", h, ct.FS.Write, ct.Exec.Allow, ct.Net.Allow, wantFS, wantExec, wantNet)
		}
	}
}

// TestAnEmptyRunProposesAllowingNothing: a run that did nothing yields a contract that allows nothing, with every
// section present and empty, since an absent section would mean no restriction at all.
func TestAnEmptyRunProposesAllowingNothing(t *testing.T) {
	c := newRun(t, ws).propose(Options{}).Contract()
	ct := load(t, c)
	if ct.FS == nil || ct.Net == nil || ct.Exec == nil {
		t.Fatalf("a section is absent, which would mean no restriction: fs=%v net=%v exec=%v\n%s", ct.FS, ct.Net, ct.Exec, c)
	}
	if len(ct.FS.Write) != 0 || len(ct.Net.Allow) != 0 || len(ct.Exec.Allow) != 0 {
		t.Errorf("an empty run was given entries: %+v %+v %+v", ct.FS, ct.Net, ct.Exec)
	}
	if ct.FS.DenyRead != nil {
		t.Errorf("fs.deny_read = %q, want unset so the built-in list applies", ct.FS.DenyRead)
	}
	for _, w := range []string{"reads: none were recorded", "no run_end", "no resource peaks"} {
		if !strings.Contains(c, w) {
			t.Errorf("the proposal lacks %q\n%s", w, c)
		}
	}
}

// TestNoRunStartIsAnError: with no run_start there is no run to learn from.
func TestNoRunStartIsAnError(t *testing.T) {
	r := newRun(t, ws)
	if _, err := propose(r.events[1:], Options{}); !errors.Is(err, ErrNoRunStart) {
		t.Errorf("err = %v, want ErrNoRunStart", err)
	}
}

// TestUndecodablePayloadIsAnError: a line this reader cannot read must not become a proposal that looks complete.
func TestUndecodablePayloadIsAnError(t *testing.T) {
	r := newRun(t, ws)
	r.add(record.KindFS, record.VerdictObserved, record.FSPayload{Op: "open", Path: ws + "/x"})
	r.events[1].Payload = []byte(`{"op":"open","path":7}`)
	if _, err := propose(r.events, Options{}); err == nil {
		t.Error("an fs payload with a numeric path was accepted")
	}
}

// TestLimitsAreSuggestionsInComments: the peaks give a suggestion, never an active limit, and every number parses as
// the contract reads it (memory about twice, pids four times, wall three times).
func TestLimitsAreSuggestionsInComments(t *testing.T) {
	r := newRun(t, ws)
	r.end(158_736_384, 18, 22300*time.Millisecond)
	p := r.propose(Options{})
	c := p.Contract()
	ct := load(t, c)
	if ct.Limits.Memory != nil || ct.Limits.Pids != nil || ct.Limits.Wall != nil {
		t.Errorf("a limit is active: %+v", ct.Limits)
	}
	l := p.Limits
	if l == nil || l.Memory != "320MiB" || l.Pids != "72" || l.Wall != "2m" {
		t.Fatalf("limits = %+v, want 320MiB, 72 and 2m", l)
	}
	if _, err := agent.ParseByteSize(l.Memory); err != nil {
		t.Error(err)
	}
	if _, err := agent.ParseDuration(l.Wall); err != nil {
		t.Error(err)
	}
	// Uncommented, the suggestion is a contract the loader accepts.
	head, tail, ok := strings.Cut(c, "\n# limits:\n")
	if !ok {
		t.Fatalf("no limits block\n%s", c)
	}
	var on []string
	for _, line := range strings.Split("# limits:\n"+tail, "\n") {
		on = append(on, strings.TrimPrefix(line, "# "))
	}
	ct = load(t, head+"\n"+strings.Join(on, "\n"))
	if ct.Limits.Memory == nil || ct.Limits.Pids == nil || ct.Limits.Wall == nil {
		t.Errorf("the suggested limits did not load as limits: %+v", ct.Limits)
	}
}

// TestLimitRounding: memory rounds up to 64 MiB and shows GiB when whole, pids have a floor of 16, wall rounds up to
// whole minutes and shows hours when whole.
func TestLimitRounding(t *testing.T) {
	for _, tc := range []struct {
		mem, pids uint64
		ran       time.Duration
		memory    string
		pidsWant  string
		wall      string
	}{
		{1 << 20, 1, time.Second, "64MiB", "16", "1m"},
		{(1 << 30) / 2, 100, 20 * time.Minute, "1GiB", "400", "1h"},
		{1<<30 + 1, 5, 21 * time.Minute, "2112MiB", "20", "63m"},
	} {
		r := newRun(t, ws)
		r.end(tc.mem, tc.pids, tc.ran)
		l := r.propose(Options{}).Limits
		if l.Memory != tc.memory || l.Pids != tc.pidsWant || l.Wall != tc.wall {
			t.Errorf("peaks %d/%d over %v: got %s %s %s, want %s %s %s", tc.mem, tc.pids, tc.ran, l.Memory, l.Pids, l.Wall, tc.memory, tc.pidsWant, tc.wall)
		}
	}
}

// TestProposalIsDeterministic: the same record gives the same bytes, whatever order a map happens to be walked in.
func TestProposalIsDeterministic(t *testing.T) {
	r := newRun(t, ws)
	for i := range 40 {
		r.open(fmt.Sprintf("%s/d%d/f", ws, i%7), wronly)
		r.exec(10+i, fmt.Sprintf("/usr/bin/tool%d", i%9))
		r.net("tcp", fmt.Sprintf("203.0.113.%d:443", i%11))
	}
	first := r.propose(Options{}).Contract()
	for range 20 {
		if again := r.propose(Options{}).Contract(); again != first {
			t.Fatalf("two proposals of one record differ:\n%s\n---\n%s", first, again)
		}
	}
}

// TestContractNames: the contract name is the agent's within [a-z0-9-]{1,40}.
func TestContractNames(t *testing.T) {
	for in, want := range map[string]string{
		"watch-claude":          "learned-claude",
		"reviewer":              "learned-reviewer",
		"watch-":                "learned",
		strings.Repeat("a", 60): "learned-" + strings.Repeat("a", 32),
		"UPPER":                 "learned",
	} {
		if got := contractName(in); got != want {
			t.Errorf("contractName(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestBoundedMemory: a run that touches more distinct paths than the learner keeps says so and does not grow
// without bound.
func TestBoundedMemory(t *testing.T) {
	l := New(Options{})
	if err := l.Add(newRun(t, ws).events[0]); err != nil {
		t.Fatal(err)
	}
	r := newRun(t, ws)
	for i := range maxDistinct + 10 {
		r.net("tcp", fmt.Sprintf("10.%d.%d.%d:80", i>>16&255, i>>8&255, i&255))
	}
	for _, e := range r.events[1:] {
		if err := l.Add(e); err != nil {
			t.Fatal(err)
		}
	}
	p, err := l.Proposal()
	if err != nil {
		t.Fatal(err)
	}
	if !p.Truncated || len(l.nets) != maxDistinct || !strings.Contains(p.Contract(), "exceeded learn's bounds") {
		t.Errorf("truncated=%v, %d nets kept", p.Truncated, len(l.nets))
	}
}

// ADR 0057 D1: an open a person answered with another file is not the agent's own reach: nothing is proposed from
// it, for the file asked for or the file given, and the header says how many there were.
func TestAlternatesAreNotProposed(t *testing.T) {
	r := newRun(t, ws)
	r.exec(10, "/usr/bin/agent")
	r.add(record.KindFS, record.VerdictAllow, record.FSPayload{Op: record.FSOpen, Path: ws + "/stand-in/config", Flags: wronly, AlternateFor: ws + "/held/config"})
	p := r.propose(Options{})
	c := p.Contract()
	if got := entries(c, "fs"); len(got) != 0 {
		t.Errorf("fs holds %q", got)
	}
	if p.Alternates != 1 || p.Refused != 0 || !strings.Contains(c, "1 file opens a person answered with another file") {
		t.Errorf("alternates %d refused %d\n%s", p.Alternates, p.Refused, c)
	}
}

// TestRanIsOnTheMonotonicClock: the wall clock can step during a run, and how long the run lasted is not the wall
// clock's to say: a step back of an hour made the proposal's header read "lasted -1h0m0s" and dropped its wall limit,
// and a step forward of a day suggested a limit of three days.
func TestRanIsOnTheMonotonicClock(t *testing.T) {
	for _, step := range []time.Duration{-time.Hour, 24 * time.Hour} {
		r := newRun(t, "/w")
		r.events[0].MonoNS = 1_000_000_000
		r.end(1<<20, 4, step)
		r.events[len(r.events)-1].MonoNS = 6_000_000_000
		p := r.propose(Options{})
		if p.Ran != 5*time.Second {
			t.Errorf("wall clock stepped %s: ran %s, want 5s on the monotonic clock", step, p.Ran)
		}
		if p.Limits == nil || p.Limits.Wall != "1m" {
			t.Errorf("wall clock stepped %s: limits %+v, want a wall of 1m", step, p.Limits)
		}
	}
}
