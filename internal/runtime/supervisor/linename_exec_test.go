// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/proc"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestExecLineNamesWhereADotDotSpellingLands: an exec's line, and the naming a kernel recorder's line takes, name what
// the pathname reaches, as fs lines name it (lineName): the physical walk of its directory, with its final component as
// spelled. R6 cleans "/usr/bin/link/../python3" to the granted /usr/bin/python3, while the kernel resolves it through
// link, a symlink the agent made, into /tmp/evil; the line read a refusal of /usr/bin/python3, a binary the agent never
// asked for. The final component is not followed for the name:
// "/usr/lib/../bin/py", whose py is a link to python3, names /usr/bin/py, as the spelling with no ".." does, and not the
// python3 it runs. The name is the image walk's own (execImage.name), made
// before the answer: the fake reads an answered notification gone, as the kernel does. A spelling with no ".." keeps
// its spelling, as before.
//
// Spec: docs/p0/supervisor.md R15b, R16b.
func TestExecLineNamesWhereADotDotSpellingLands(t *testing.T) {
	for _, tc := range []struct {
		name, spelled, image string
		// dir is where the image walk lands the spelling's directory, joined with its final name, when it is not the
		// lexical clean of the spelling.
		dir, line string
		verdict   record.Verdict
	}{
		{"a dot-dot after a symlink names the image it reaches", "/usr/bin/link/../python3", "/tmp/evil/python3", "/tmp/evil/python3", "/tmp/evil/python3", record.VerdictRefused},
		{"a dot-dot whose final name is a symlink names the link, not the image", "/usr/lib/../bin/py", "/usr/bin/python3", "", "/usr/bin/py", record.VerdictAllow},
		{"control: a symlink with no dot-dot keeps its spelling", "/usr/bin/py", "/usr/bin/python3", "", "/usr/bin/py", record.VerdictAllow},
	} {
		for _, handoff := range []bool{false, true} {
			t.Run(map[bool]string{false: tc.name + "/line", true: tc.name + "/handoff"}[handoff], func(t *testing.T) {
				f := newFake()
				f.goneOnSend = true
				f.tgid[42] = 40
				f.stats[40] = procStat{ppid: 1, start: 1234}
				img := fakeImage(tc.image)
				img.name = tc.dir // the image walk's name; the fake names a ".." spelling by its clean when it is ""
				f.images[cleanPath(tc.spelled)] = img
				l, sink := newTestLoop(t, f, searchPolicy())
				l.kernelExecHandoff = func() bool { return handoff }
				l.mono = func() uint64 { return 100 }
				execAt(l, f, nrFor(t, "execve"), 42, 0, tc.spelled, "python3", "-c", "1")
				if handoff {
					n, ok := l.ContinuedExec(42, 40, 1234*proc.NanosPerTick+99, 110)
					if !ok || n.Path != tc.line {
						t.Fatalf("the kernel recorder's naming %+v (found %v), want path %q", n, ok, tc.line)
					}
					return
				}
				ev := sink.one(t)
				if ev.Verdict != tc.verdict {
					t.Errorf("verdict = %s (%s), want %s", ev.Verdict, ev.Rule, tc.verdict)
				}
				var p execPayload
				if err := ev.DecodePayload(&p); err != nil {
					t.Fatal(err)
				}
				if p.Path != tc.line {
					t.Errorf("the line names %q, want %q: what the pathname reaches", p.Path, tc.line)
				}
			})
		}
	}
}

// TestExecIsDecidedWhereItIsNamed: an exec spelled with a ".." is decided on the name its line gives it, the image
// walk's (execImage.name), never on R6's lexical clean. A file entry with no identity at the start (its file missing
// then, so not pinned: execPinned) is matched by name; /grant/lk/../x cleans to the entry's /grant/x while the kernel
// runs /elsewhere/x, and the line read "allow /elsewhere/x, rule exec[/grant/x]", a rule that never covered the file
// it names. The entry's own spelling still matches it.
//
// Spec: docs/p0/supervisor.md R15b, R16b.
func TestExecIsDecidedWhereItIsNamed(t *testing.T) {
	for _, tc := range []struct {
		name, spelled, image string
		verdict              record.Verdict
	}{
		{"a dot-dot after a symlink is decided where it is named", "/grant/lk/../x", "/elsewhere/x", record.VerdictRefused},
		{"control: the entry's own spelling", "/grant/x", "/grant/x", record.VerdictAllow},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake()
			f.statErrs["/grant/x"] = unix.ENOENT // missing at the start: matched by name, not by identity
			img := fakeImage(tc.image)
			img.name = tc.image // the image walk's name of a ".." spelling
			if tc.spelled == tc.image {
				img.name = ""
			}
			f.images[cleanPath(tc.spelled)] = img
			pol := testPolicy(nil, nil, nil)
			pol.Rules.Exec = []agent.ExecRule{{Raw: "/grant/x", Path: "/grant/x", Source: agent.ExecSourceAllow}}
			l, sink := newTestLoop(t, f, pol)
			execAt(l, f, nrFor(t, "execve"), 42, 0, tc.spelled, "x")
			ev := sink.one(t)
			var p execPayload
			if err := ev.DecodePayload(&p); err != nil {
				t.Fatal(err)
			}
			if p.Path != tc.image || ev.Verdict != tc.verdict {
				t.Errorf("line: %s %q rule %s; want %s %q", ev.Verdict, p.Path, ev.Rule, tc.verdict, tc.image)
			}
			wantExecAnswer(t, f, tc.verdict)
		})
	}
}

// TestExecOfADeclaredMCPServerByAnotherSpellingEmitsMCP:a declared MCP server's start is recorded however the exec
// spells its command[0], as long as it runs that file with the declared arguments. npx is a symlink to npx-cli.js on
// Debian and Ubuntu. "/usr/lib/../bin/npx" is named /usr/bin/npx (lineName never follows the final link), and its line
// is the declared server's; in an earlier build it was named npx-cli.js, the mcp table keyed by /usr/bin/npx
// missed it, and drift read a server that started as one that never ran (2c6-1).
// The link's target itself, run directly, is the same file by identity (inode and resolved path, as the exec grant
// matches it: mcpIDs). Other arguments, or another file, start no server, and neither does another name of the same
// inode (a hard link, another mount of the filesystem): the identity is the inode and its resolved path both.
//
// Spec: docs/p0/supervisor.md R16b; P0-DESIGN §2.2.
func TestExecOfADeclaredMCPServerByAnotherSpellingEmitsMCP(t *testing.T) {
	const npx, cli, hardLink = "/usr/bin/npx", "/usr/lib/node_modules/npm/bin/npx-cli.js", "/usr/local/bin/npx-copy"
	c := &agent.Contract{MCP: []agent.MCPServer{{Name: "fs", Command: []string{"npx", "-y", "@mcp/server-fs"}}}}
	for _, tc := range []struct {
		name, spelled string
		argv          []string
		line, server  string
	}{
		{"a harmless dot-dot through the link", "/usr/lib/../bin/npx", []string{"npx", "-y", "@mcp/server-fs"}, npx, "fs"},
		{"the link's target, by identity", cli, []string{"npx-cli.js", "-y", "@mcp/server-fs"}, cli, "fs"},
		{"control: as declared", npx, []string{"npx", "-y", "@mcp/server-fs"}, npx, "fs"},
		{"control: other arguments start none", "/usr/lib/../bin/npx", []string{"npx", "prettier", "."}, npx, ""},
		{"another name of the same inode starts none", hardLink, []string{"npx", "-y", "@mcp/server-fs"}, hardLink, ""},
	} {
		for _, handoff := range []bool{false, true} {
			t.Run(map[bool]string{false: tc.name + "/line", true: tc.name + "/handoff"}[handoff], func(t *testing.T) {
				pol := contractPolicy(c, nil, nil)
				pol.Rules.Exec = []agent.ExecRule{{Raw: "npx", Path: npx, Basename: "npx", ByName: true, Source: "mcp:fs", Verdict: agent.VerdictAllow}}
				f := newFake()
				f.goneOnSend = true
				f.tgid[42] = 40
				f.stats[40] = procStat{ppid: 1, start: 1234}
				f.images[npx] = fakeImage(cli)
				f.statIDs[npx] = fakeID(cli)
				copied := fakeImage(hardLink)
				copied.id = fakeID(cli) // the same inode as npx-cli.js, by another path
				f.images[hardLink] = copied
				f.evalLinks[npx] = cli
				l, sink := newTestLoop(t, f, pol)
				l.kernelExecHandoff = func() bool { return handoff }
				l.mono = func() uint64 { return 100 }
				execAt(l, f, nrFor(t, "execve"), 42, 0, tc.spelled, tc.argv...)
				if handoff {
					n, ok := l.ContinuedExec(42, 40, 1234*proc.NanosPerTick+99, 110)
					if !ok || n.Path != tc.line || n.MCPName != tc.server {
						t.Fatalf("the kernel recorder's naming %+v (found %v), want path %q and server %q", n, ok, tc.line, tc.server)
					}
					return
				}
				var exec record.ExecPayload
				var servers []string
				for _, ev := range sink.all() {
					switch ev.Kind {
					case record.KindExec:
						if ev.Verdict != record.VerdictAllow {
							t.Errorf("exec line %s (%s), want allow: the declared command's file", ev.Verdict, ev.Rule)
						}
						if err := ev.DecodePayload(&exec); err != nil {
							t.Fatal(err)
						}
					case record.KindMCP:
						servers = append(servers, ev.Rule)
					}
				}
				if exec.Path != tc.line {
					t.Errorf("the exec line names %q, want %q", exec.Path, tc.line)
				}
				want := 0
				if tc.server != "" {
					want = 1
				}
				if len(servers) != want || (want == 1 && servers[0] != "mcp["+tc.server+"]") {
					t.Errorf("mcp lines %v, want %d naming mcp[%s]", servers, want, tc.server)
				}
			})
		}
	}
}

// TestExecLineNameIsTheImagesWalk: an exec spelled with a ".." is named by the walk that reached its image, never by a
// second walk. In an earlier build the image was the exec walk's and the name a second, fs walk's:
// with /w/lk moved between the two, from /w/evil/sub to /usr/bin/sub, "/w/lk/../npx" ran the agent's /w/evil/npx and
// its line read "exec allow rule=exec[/w/evil/npx] path=/usr/bin/npx", with an mcp[fs] line for a declared server that
// never started. The fake's image walk lands /w/lk/.. on /w/evil, and its fs walk,
// which no exec may ask, answers /usr/bin/npx.
//
// Spec: docs/p0/supervisor.md R16b.
func TestExecLineNameIsTheImagesWalk(t *testing.T) {
	const npx, evil = "/usr/bin/npx", "/w/evil/npx"
	c := &agent.Contract{MCP: []agent.MCPServer{{Name: "fs", Command: []string{"npx", "-y", "@mcp/server-fs"}}}}
	for _, handoff := range []bool{false, true} {
		t.Run(map[bool]string{false: "line", true: "handoff"}[handoff], func(t *testing.T) {
			pol := contractPolicy(c, nil, nil)
			pol.Rules.Exec = []agent.ExecRule{
				{Raw: "npx", Path: npx, Basename: "npx", ByName: true, Source: "mcp:fs", Verdict: agent.VerdictAllow},
				{Raw: evil, Path: evil, Source: agent.ExecSourceAllow, Verdict: agent.VerdictAllow},
			}
			f := newFake()
			f.goneOnSend = true
			f.tgid[42] = 40
			f.stats[40] = procStat{ppid: 1, start: 1234}
			f.images[npx] = fakeImage(npx)
			f.statIDs[npx] = fakeID(npx)
			f.statIDs[evil] = fakeID(evil)
			img := fakeImage(evil)
			img.name = evil // the image's walk: /w/lk -> /w/evil/sub, so /w/lk/.. is /w/evil
			f.images["/w/npx"] = img
			f.fsTargets["/w/npx"] = npx // a second walk, after /w/lk moved to /usr/bin/sub
			l, sink := newTestLoop(t, f, pol)
			l.kernelExecHandoff = func() bool { return handoff }
			l.mono = func() uint64 { return 100 }
			execAt(l, f, nrFor(t, "execve"), 42, 0, "/w/lk/../npx", "npx", "-y", "@mcp/server-fs")
			if handoff {
				n, ok := l.ContinuedExec(42, 40, 1234*proc.NanosPerTick+99, 110)
				if !ok || n.Path != evil || n.MCPName != "" {
					t.Fatalf("the kernel recorder's naming %+v (found %v), want path %q and no server", n, ok, evil)
				}
				return
			}
			var lines []string
			for _, ev := range sink.all() {
				var p record.ExecPayload
				if ev.Kind == record.KindExec {
					if err := ev.DecodePayload(&p); err != nil {
						t.Fatal(err)
					}
				}
				lines = append(lines, string(ev.Kind)+" "+string(ev.Verdict)+" rule="+ev.Rule+" path="+p.Path)
			}
			if want := "exec allow rule=exec[" + evil + "] path=" + evil; len(lines) != 1 || lines[0] != want {
				t.Errorf("lines %q, want only %q: the image's walk names it, and no server started", lines, want)
			}
		})
	}
}
