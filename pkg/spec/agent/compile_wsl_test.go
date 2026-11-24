// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// WSL launch and GUI servers act outside the run. ADR 0113's fixed refusal must
// survive both the general host-socket opt-out and an unrelated Unix allow.
func TestBuiltinWSLServersHaveNoContractOptOut(t *testing.T) {
	for _, extra := range []string{"", "host_sockets: true\n", "net: {allow: [\"unix:/srv/app/server.sock\"]}\n"} {
		t.Run(extra, func(t *testing.T) {
			f := newFixture(t)
			rt, _ := f.compile(f.load("version: 0\nname: wsl-ipc\ncommand: [\"python\"]\n" + extra))
			for _, path := range []string{
				"/run/WSL/123_interop", "/mnt/wslg/.X11-unix/X0",
				"/mnt/wslg/runtime-dir/wayland-0", "/mnt/wslg/PulseServer",
			} {
				if got := rt.BuiltinUnixRule(path); got != BuiltinHostIPC {
					t.Errorf("%s: refusal %q, want %s", path, got, BuiltinHostIPC)
				}
				if got, ok := rt.DenyWriteTarget(path, false); !ok || got.RuleName() != BuiltinHostIPC {
					t.Errorf("%s: immutable write target %+v, found %v", path, got, ok)
				}
			}
		})
	}
}

func TestBuiltinWSLAllowIsAContradiction(t *testing.T) {
	for _, path := range []string{"/run/WSL/123_interop", "/mnt/wslg/runtime-dir/wayland-0", "/mnt/wslg/PulseServer"} {
		t.Run(path, func(t *testing.T) {
			f := newFixture(t)
			_, ds, err := f.compileErr(f.load(builtinAllowContract("unix:" + path)))
			if err == nil || len(contradictions(ds)) != 1 {
				t.Fatalf("protected WSL socket admitted: err=%v diagnostics=%s", err, render(ds))
			}
		})
	}
}

// wslRefusals are the diagnostics in ds that carry the WSL launcher's words.
func wslRefusals(ds []Diagnostic) []Diagnostic {
	var out []Diagnostic
	for _, d := range ds {
		if strings.Contains(d.Message, wslLauncherWords) {
			out = append(out, d)
		}
	}
	return out
}

// TestWSLLauncherCannotBeGiven is the WSL launcher at compile (ADR 0113, amended 2026-11-19): on WSL, a contract
// cannot give a run WSL's Windows launcher. A net.allow or net.ask unix: entry or a filesystem grant that names the
// launcher's folder, a path beneath it, or one of its sockets by another name (a link, a hard link), and
// host_sockets: true where a launcher socket lies outside every built-in refusal, are each refused with the words,
// naming the entry, once. The machine's WSL facts are injected. Off WSL, and in a record-only run, nothing of this is
// said (the built-in contradiction of a /run/WSL unix: entry stays as it was).
func TestWSLLauncherCannotBeGiven(t *testing.T) {
	f := newSocketFixture(t, "project/s")
	sock := filepath.Join(f.project, "s")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	hard := filepath.Join(f.project, "hard")
	if err := os.Link(sock, hard); err != nil {
		t.Fatal(err)
	}
	soft := filepath.Join(f.project, "soft")
	if err := os.Symlink(sock, soft); err != nil {
		t.Fatal(err)
	}
	onWSL := withWSLFacts(true, "/run/WSL/1_interop", sock)
	unixAllow := func(entry string) string { return builtinAllowContract(entry) }
	for _, tc := range []struct {
		name, contract, names string
	}{
		{"a unix: allow of an interop socket", unixAllow("unix:/run/WSL/1_interop"), "net[unix:/run/WSL/1_interop]"},
		{"a unix: allow of another session's socket", unixAllow("unix:/run/WSL/4711_interop"), "net[unix:/run/WSL/4711_interop]"},
		{"a unix: allow of a link to a launcher socket", unixAllow("unix:" + soft), "net[unix:" + soft + "] (resolves to " + sock + ")"},
		{"a unix: allow of a hard link to a launcher socket", unixAllow("unix:" + hard), "net[unix:" + hard + "]"},
		{"a unix: ask of an interop socket", "version: 0\nname: t\ncommand: [\"python\"]\nnet: {ask: [\"unix:/run/WSL/1_interop\"]}\n", "net[unix:/run/WSL/1_interop]"},
		{"a write grant of the launcher's folder", "version: 0\nname: t\ncommand: [\"python\"]\nfs: {write: [\"/run/WSL\"]}\n", "fs.write[/run/WSL]"},
		{"host_sockets: true with a launcher socket no built-in covers", "version: 0\nname: t\ncommand: [\"python\"]\nhost_sockets: true\n", "host_sockets: true reaches " + sock},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rt, ds, err := f.compileErr(f.load(tc.contract), onWSL)
			got := wslRefusals(ds)
			if err == nil || rt != nil || len(got) != 1 {
				t.Fatalf("want one error with the WSL launcher's words, got err %v and:\n%s", err, render(ds))
			}
			if d := got[0]; !d.IsError() || d.Line == 0 || !strings.HasPrefix(d.Message, tc.names) || d.Fix == "" {
				t.Errorf("the error does not name the entry %q at its line, or has no fix: %+v", tc.names, d)
			}
			for _, d := range ds {
				if d.IsError() && strings.Contains(d.Message, "ADR 0113") && strings.Contains(d.Message, "WSL") {
					t.Errorf("the entry is refused twice: %s", d.Message)
				}
			}
		})
	}
	// host_sockets: true where every launcher socket is under the built-in refusal of /run/WSL compiles: the run
	// refuses the socket whatever the contract says (ADR 0113), so nothing is given.
	if _, ds, err := f.compileErr(f.load("version: 0\nname: t\ncommand: [\"python\"]\nhost_sockets: true\n"), withWSLFacts(true, "/run/WSL/1_interop")); err != nil || len(wslRefusals(ds)) != 0 {
		t.Errorf("host_sockets: true with the launcher's sockets under the built-in refusal: err %v\n%s", err, render(ds))
	}
	// Off WSL: no WSL words; the built-in contradiction of the /run/WSL entry is the one error, as before.
	_, ds, err := f.compileErr(f.load(unixAllow("unix:/run/WSL/1_interop")))
	if err == nil || len(wslRefusals(ds)) != 0 || len(contradictions(ds)) != 1 || !strings.Contains(contradictions(ds)[0].Message, BuiltinHostIPC) {
		t.Errorf("off WSL: err %v\n%s", err, render(ds))
	}
	if _, ds, err := f.compileErr(f.load(unixAllow("unix:" + soft))); err != nil || len(wslRefusals(ds)) != 0 {
		t.Errorf("off WSL, a socket of no launcher: err %v\n%s", err, render(ds))
	}
	// A record-only run refuses nothing and has nothing to contradict.
	if _, ds, err := f.compileErr(f.load(unixAllow("unix:"+soft)), onWSL, WithObserve()); len(wslRefusals(ds)) != 0 {
		t.Errorf("a record-only run on WSL: err %v\n%s", err, render(ds))
	}
	// A path beneath the folder, by either spelling, names the launcher (a write grant beneath it needs the folder to
	// exist, which this host's does not); a path beside it does not.
	facts := wslFacts{on: true}
	for path, want := range map[[2]string]bool{
		{"/run/WSL/x", ""}: true, {"/run/WSL/", ""}: true, {"/run/x", "/run/WSL/1_interop"}: true, {"/run/WSL/../x", ""}: false,
		{"/run/WSLx", ""}: false, {"/run", ""}: false, {"/", ""}: false,
	} {
		if got := facts.reachesWSLLauncher(path[0], path[1]); got != want {
			t.Errorf("reachesWSLLauncher(%q, %q) = %v; want %v", path[0], path[1], got, want)
		}
	}
	// The same marks as internal/platform/peer's gate.
	if !slices.Equal(wslMarks, []string{"/run/WSL", "/proc/sys/fs/binfmt_misc/WSLInterop", "/proc/sys/fs/binfmt_misc/WSLInterop-late"}) {
		t.Errorf("wslMarks = %v", wslMarks)
	}
}

// TestWSLRestrictionOnOneMark (ADR 0100, amended 2026-11-19, round 5): refusing WSL's launcher is a restriction, so
// compile restricts the machine as WSL where any ONE of three independent marks holds (the kernel release names
// Microsoft or WSL, WSL's launcher folder, one of its binfmt_misc entries), the careful side of the peer gate's
// asymmetric detection (TestWSLDetection there): a distribution with interop off shows its release alone and is
// restricted. Only a machine with none of the marks is not.
func TestWSLRestrictionOnOneMark(t *testing.T) {
	folder := func(p string) bool { return p == "/run/WSL" }
	binfmt := func(p string) bool { return p == "/proc/sys/fs/binfmt_misc/WSLInterop" }
	late := func(p string) bool { return p == "/proc/sys/fs/binfmt_misc/WSLInterop-late" }
	both := func(p string) bool { return folder(p) || binfmt(p) }
	none := func(string) bool { return false }
	const wsl, plain = "6.18.58.1-microsoft-standard-WSL2", "6.17.0-41-generic"
	for _, c := range []struct {
		name    string
		release string
		read    bool
		exists  func(string) bool
		want    bool
	}{
		{"WSL 2: kernel, folder and binfmt entry", wsl, true, both, true},
		{"kernel and folder", wsl, true, folder, true},
		{"kernel and binfmt entry", wsl, true, binfmt, true},
		{"folder and late binfmt entry", plain, true, func(p string) bool { return folder(p) || late(p) }, true},
		{"unreadable release and folder", "", false, folder, true},
		{"ordinary Linux", plain, true, none, false},
		{"one mark: the kernel alone (interop off)", wsl, true, none, true},
		{"one mark: a refused look at /run/WSL", plain, true, folder, true},
		{"one mark: the binfmt entry alone", plain, true, binfmt, true},
		{"one mark: both binfmt entries", plain, true, func(p string) bool { return binfmt(p) || late(p) }, true},
		{"one mark: an unreadable release alone", "", false, none, true},
	} {
		if got := restrictAsWSL(c.release, c.read, c.exists); got != c.want {
			t.Errorf("%s: restricted as WSL = %v; want %v", c.name, got, c.want)
		}
	}
}
