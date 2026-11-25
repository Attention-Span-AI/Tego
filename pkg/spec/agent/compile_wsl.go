// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// WSLLauncherDir is where WSL keeps its program launcher's (interop) sockets, /run/WSL/<pid>_interop. A process that
// connects to one, or runs a Windows program through WSL's binfmt_misc entry (whose handler, /init, connects to one),
// has WSL start a program outside the distribution's cgroups: outside the run and its rules (ADR 0113, the WSL
// launcher; ADR 0100's amendment of 2026-11-19).
const WSLLauncherDir = "/run/WSL"

// wslLauncherWords is the refusal of a contract entry that would give a run WSL's launcher.
const wslLauncherWords = "a run cannot be given WSL's Windows launcher: a program started through it runs outside the run and its rules"

// wslLauncherFix is the fix of such an entry.
const wslLauncherFix = "remove the entry; WSL's launcher sockets under " + WSLLauncherDir + " are refused in every run, " +
	"and a Windows program the agent needs is started by a helper outside the run that does that one thing " +
	"(https://attention-span.ai/docs/built-in-refusals/)"

// maxWSLSockets bounds the launcher sockets compile looks at: WSL makes one per session.
const maxWSLSockets = 256

// wslFacts is what compile knows of WSL on this machine: whether it is a WSL distribution, and the launcher's
// sockets found under WSLLauncherDir, each with its identity.
type wslFacts struct {
	on      bool
	sockets []wslSocket
}

type wslSocket struct {
	path     string
	dev, ino uint64
}

// wslMarks are the files a WSL 2 distribution has: the launcher's folder and the binfmt_misc entries that hand
// Windows programs to it. internal/platform/peer reads the same marks for its gate; each package's test pins the same
// list (TestWSLLauncherCannotBeGiven here, TestWSLDetection there).
var wslMarks = []string{WSLLauncherDir, "/proc/sys/fs/binfmt_misc/WSLInterop", "/proc/sys/fs/binfmt_misc/WSLInterop-late"}

// probeWSL reads this machine's WSL facts. Refusing WSL's launcher is a restriction, so any ONE of three independent
// marks is enough (wslMarkCount; ADR 0100, amended 2026-11-19, round 5: detection is asymmetric, a hold or a
// restriction on one mark, a relaxation on two, internal/platform/peer's gate): the kernel release names Microsoft or
// WSL, WSL's launcher folder is there, one of its binfmt_misc entries is there. A release that cannot be read, and a
// mark that cannot be looked at, count as their mark, so a distribution with interop off (its release alone) is
// restricted as WSL is. Never an environment variable.
func probeWSL() wslFacts {
	if !machineOnWSL() {
		return wslFacts{}
	}
	f := wslFacts{on: true}
	entries, err := os.ReadDir(WSLLauncherDir)
	if err != nil {
		return f
	}
	for _, e := range entries {
		if len(f.sockets) == maxWSLSockets {
			break
		}
		p := filepath.Join(WSLLauncherDir, e.Name())
		var st unix.Stat_t
		if unix.Lstat(p, &st) == nil && st.Mode&unix.S_IFMT == unix.S_IFSOCK {
			f.sockets = append(f.sockets, wslSocket{path: p, dev: st.Dev, ino: st.Ino})
		}
	}
	return f
}

func machineOnWSL() bool {
	var u unix.Utsname
	read := unix.Uname(&u) == nil
	return restrictAsWSL(unix.ByteSliceToString(u.Release[:]), read, func(p string) bool {
		var st unix.Stat_t
		err := unix.Lstat(p, &st)
		return err == nil || !errors.Is(err, unix.ENOENT) && !errors.Is(err, unix.ENOTDIR)
	})
}

// restrictAsWSL reports whether compile restricts the machine as WSL: any one of WSL's marks holds (probeWSL).
func restrictAsWSL(release string, releaseRead bool, exists func(string) bool) bool {
	return wslMarkCount(release, releaseRead, exists) >= 1
}

// wslMarkCount counts the independent marks of WSL that hold: the kernel release names Microsoft or WSL (a release
// that cannot be read counts), the launcher's folder is there, and one of the binfmt_misc entries is there (the two
// entries are one mark). internal/platform/peer counts the same marks for its gate (TestWSLDetection there).
func wslMarkCount(release string, releaseRead bool, exists func(string) bool) int {
	n := 0
	release = strings.ToLower(release)
	if !releaseRead || strings.Contains(release, "microsoft") || strings.Contains(release, "wsl") {
		n++
	}
	if exists(wslMarks[0]) {
		n++
	}
	if exists(wslMarks[1]) || exists(wslMarks[2]) {
		n++
	}
	return n
}

// wsl is this compile's WSL facts: a test's (withWSLFacts), or this machine's.
func (k *compiler) wsl() wslFacts {
	if k.o.wsl != nil {
		return *k.o.wsl
	}
	f := probeWSL()
	k.o.wsl = &f
	return f
}

// reachesWSLLauncher reports whether an entry declared at path, resolving to resolved ("" for none), names WSL's
// launcher: WSLLauncherDir or a path beneath it, by either spelling, or a file that is one of the launcher's
// sockets by identity (a hard link elsewhere, a spelling compile did not resolve).
func (f wslFacts) reachesWSLLauncher(path, resolved string) bool {
	for _, p := range []string{path, resolved} {
		if p == "" {
			continue
		}
		if p = filepath.Clean(p); p == WSLLauncherDir || strings.HasPrefix(p, WSLLauncherDir+"/") {
			return true
		}
	}
	at := resolved
	if at == "" {
		at = path
	}
	var st unix.Stat_t
	if at == "" || unix.Stat(at, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFSOCK {
		return false
	}
	for _, s := range f.sockets {
		if s.dev == st.Dev && s.ino == st.Ino {
			return true
		}
	}
	return false
}

// wslLauncherRefused is the WSL launcher at compile (ADR 0113, amended 2026-11-19): on WSL, a contract cannot give a
// run WSL's Windows launcher. A net.allow or net.ask unix: entry or a filesystem grant (fs.write, fs.ask) that names
// the launcher's folder, a path beneath it or one of its sockets, and host_sockets: true where a launcher socket lies
// outside every built-in refusal, is an error naming the entry. The built-in refusal of the folder (builtin.host_ipc)
// would refuse each in the run too; compile says why before the run starts, in the person's words. A record-only run
// (--observe, tego watch) refuses nothing and has nothing to contradict. It returns the unix: entries it refused, by
// position, so builtinRefusedAllows does not refuse them a second time.
func (k *compiler) wslLauncherRefused() map[Pos]bool {
	if k.o.observe || k.rt.Builtins == nil {
		return nil
	}
	f := k.wsl()
	if !f.on {
		return nil
	}
	refused := map[Pos]bool{}
	for _, r := range append(append([]NetRule{}, k.rt.Net...), k.rt.NetAsk...) {
		if r.Runtime != "" || r.Proto != ProtoUnix || r.Abstract || (r.Verdict != VerdictAllow && r.Verdict != VerdictAsk) {
			continue
		}
		if f.reachesWSLLauncher(r.UnixPath, r.UnixResolved) {
			k.ds.errorf(r.Pos, CodeContradiction, "%s%s: %s", r.RuleName(), resolvedNote(r.UnixPath, r.UnixResolved), wslLauncherWords).fix(wslLauncherFix)
			refused[r.Pos] = true
		}
	}
	for _, r := range append(append([]FSRule{}, k.rt.FS...), k.rt.FSAsk...) {
		if r.Raw == "" || r.BuiltIn || (r.Kind != FSWrite && r.Kind != FSAsk) {
			continue
		}
		if f.reachesWSLLauncher(r.Path, r.Resolved) {
			k.ds.errorf(r.Pos, CodeContradiction, "%s%s: %s", r.RuleName(), resolvedNote(r.Path, r.Resolved), wslLauncherWords).fix(wslLauncherFix)
		}
	}
	if k.c.Net == nil && k.c.HostSockets {
		for _, s := range f.sockets {
			if k.rt.BuiltinUnixRule(s.path) == "" {
				k.ds.errorf(k.pos("host_sockets"), CodeContradiction, "host_sockets: true reaches %s, a socket of WSL's launcher "+
					"that no built-in refusal covers: %s", s.path, wslLauncherWords).
					fix("remove host_sockets: true and add a net: section naming each endpoint the agent needs")
				break
			}
		}
	}
	return refused
}
