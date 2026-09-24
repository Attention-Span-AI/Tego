// SPDX-License-Identifier: Apache-2.0

package uprobe

import (
	"bytes"
	"context"
	"debug/elf"
	bin "encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	goruntime "runtime"
	"time"
)

// preattachPID is the pid a run's pre-attach takes its attach-cache reference under. No process of a run is
// pid 0, so the reference is never given back by an exit: it stands for the whole run and goes at Stop's
// sweep with the rest of the source's references (R8, I9).
const preattachPID = 0

// MaxPreattach bounds how many distinct files Start pre-attaches. A host normally has one libssl per
// OpenSSL major version it keeps; past a handful, what is left is found at its open as before.
const MaxPreattach = 8

// DefaultPreattachBudget bounds the time Start spends pre-attaching (preattach), because the agent waits on
// it: source.Source's Start must return promptly. Most of an attach is the kernel's uprobe_register, which
// walks every process that maps the file, so a host with many processes on its libssl pays for it here; a
// budget spent leaves the rest to be attached at their open, which is where they were attached before
// pre-attach existed. See Options.PreattachBudget.
const DefaultPreattachBudget = time.Second

// maxLdCache bounds how much of /etc/ld.so.cache is read. The cache names every library on the host and is
// a few hundred KiB on a large one.
const maxLdCache = 16 << 20

// preattach places the probes on the host's libssl before the run's first process exists (R4, edge case 2).
//
// A uprobe belongs to a file, not to a process: once placed, it fires for every process that maps the file,
// and the capture programs keep only what the run set names (R9). Placed when the run's process opens the
// library, the probes are late by the kernel record's drain of that open plus the attach, and a client that
// writes its first request straight after `import ssl` writes it before they are in place. On the 6.1 and
// 6.12 kernels of the matrix that was every run of kill test 2's agent. Placed here, they are there before
// the agent execs: Start runs before the run's ack releases the child (runtime-launch.md §4.1 step 8).
//
// A library found only when a process opens it is still attached then (OnOpen), and that one is still late:
// a private copy loaded from a path this list does not name (a venv's or a bundled OpenSSL, LD_LIBRARY_PATH),
// or a library in a container's own mount namespace, which is a different file from the host's (R39).
//
// A failure here records nothing against the run: no process has mapped anything yet. The attach cache
// keeps the failure against the binary (§7's one attempt), and a process that maps that library later gets
// the gap it would have got at its open.
//
// The agent waits for this, so it is bounded: by PreattachBudget and by ctx, checked before each file's
// reads and before each library's attach, as OnExec checks its AttachBudget before each candidate. The
// first library in the list, the loader cache's first libssl when it names one, is always attempted. What
// the bound leaves is logged and attached at its open, late as it was before pre-attach. A read or an
// attach already under way is not interrupted: a single stat, ELF read or uprobe_register that never
// returns holds Start as it would hold OnExec.
//
// Under record: off nothing is placed, here or later (capturesNothing, live), unless the run's stall_after is
// bounded (stampsActivity): the capture programs record nothing for such a run (tego_recording), so pre-attaching
// would delay the agent by up to the budget and make every host process's SSL_read and SSL_write trap for the whole
// run, to capture nothing (R4). An activity-only run pre-attaches as a capture run does, for its stall check: the
// kernel record carries no opens under off, so CPython's dlopened libssl would otherwise never be probed (A-REC-4).
func (u *Uprobe) preattach(ctx context.Context) {
	if u.capturesNothing() && !u.stampsActivity() {
		u.log("uprobe: no pre-attach under record: off: the capture programs record nothing for this run, " +
			"so probes on the host's libssl would cost every process that calls it and capture nothing (R4)")
		return
	}
	start := u.opts.Now()
	deadline := start.Add(u.opts.PreattachBudget)
	over := func() bool { return ctx.Err() != nil || u.opts.Now().After(deadline) }
	list := u.opts.Preattach
	if list == nil {
		if !u.opts.Kernel {
			return
		}
		list = func() []string { return systemLibraries("/", over) }
	}
	paths := list()
	var attached int
	for i, path := range paths {
		if i > 0 && over() {
			u.warn("uprobe: pre-attach stopped after %s (budget %s): %q attach when a process opens them, "+
				"and an exchange a process starts before that attach is done can be lost (R4)",
				u.opts.Now().Sub(start), u.opts.PreattachBudget, paths[i:])
			break
		}
		ok, err := u.attachCandidate(preattachPID, candidate{Path: path, Name: path})
		if ok {
			attached++
			continue
		}
		if err != nil {
			u.log("uprobe: pre-attach of %s: %v", path, err)
		}
	}
	u.log("uprobe: pre-attached %d of %d libraries in %s", attached, len(paths), u.opts.Now().Sub(start))
}

// systemLibraries lists the libssl files a process on this host loads by name, one path per file: first
// every libssl the dynamic loader's cache names (/etc/ld.so.cache, which is where the loader resolves a
// SONAME such as libssl.so.3 when no LD_LIBRARY_PATH or RUNPATH says otherwise), then every libssl in the
// directories a loader searches by default. A file reached by two names (libssl.so and libssl.so.3, /lib
// and /usr/lib on a merged-/usr host) is listed once, by its identity with the build id (R7), and a file
// built for another machine (a multilib i386 copy) is left out, because this build's capture programs read
// its own architecture's registers. root is prefixed to every path, for a test. stop, when it reports true,
// ends the list before the next file is read, once it names one library: the reads are the part of the
// listing that can be slow (see preattach). A nil stop never does.
func systemLibraries(root string, stop func() bool) []string {
	var names []string
	if data, err := readLimited(filepath.Join(root, "etc", "ld.so.cache"), maxLdCache); err == nil {
		for _, p := range parseLdCache(data) {
			names = append(names, filepath.Join(root, p))
		}
	}
	for _, dir := range libDirs() {
		matches, _ := filepath.Glob(filepath.Join(root, dir, "libssl.so*"))
		for _, m := range matches {
			if libsslName.MatchString(filepath.Base(m)) {
				names = append(names, m)
			}
		}
	}
	seen := map[identity]bool{}
	var out []string
	for _, p := range names {
		if len(out) == MaxPreattach || (len(out) > 0 && stop != nil && stop()) {
			break
		}
		id, err := candidateIdentity(p)
		if err != nil || seen[id] || !nativeELF(p) {
			continue
		}
		seen[id] = true
		out = append(out, p)
	}
	return out
}

// libDirs are the directories a dynamic loader searches when its cache has no answer: glibc's trusted
// directories and Debian's multiarch ones, musl's defaults, and /usr/local.
func libDirs() []string {
	dirs := []string{"/lib64", "/usr/lib64", "/lib", "/usr/lib", "/usr/local/lib64", "/usr/local/lib"}
	if t := multiarch(); t != "" {
		dirs = append([]string{"/lib/" + t, "/usr/lib/" + t}, dirs...)
	}
	return dirs
}

// multiarch is Debian's triplet directory name for this build's architecture.
func multiarch() string {
	switch goruntime.GOARCH {
	case "amd64":
		return "x86_64-linux-gnu"
	case "arm64":
		return "aarch64-linux-gnu"
	}
	return ""
}

// nativeMachine is the ELF machine this build's capture object reads registers for.
func nativeMachine() elf.Machine {
	switch goruntime.GOARCH {
	case "amd64":
		return elf.EM_X86_64
	case "arm64":
		return elf.EM_AARCH64
	}
	return elf.EM_NONE
}

// nativeELF reports whether a file is a 64-bit ELF for this build's machine.
func nativeELF(path string) bool { return checkNativeELF(path) == nil }

// checkNativeELF is nativeELF with the reason: ErrNotELF for a file that is an ELF of another class or
// machine, openELF's own error for one that could not be read. The probes read their arguments as this
// machine's 64-bit calling convention lays them out, so a probe on a 32-bit or foreign library would read
// garbage for the buffer and the length.
func checkNativeELF(path string) error {
	f, err := openELF(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	if f.Class != elf.ELFCLASS64 || f.Machine != nativeMachine() {
		return fmt.Errorf("%w: %s is %s %s, not %s %s", ErrNotELF, path, f.Class, f.Machine, elf.ELFCLASS64,
			nativeMachine())
	}
	return nil
}

// readLimited reads at most max bytes of a file.
func readLimited(path string, max int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return io.ReadAll(io.LimitReader(f, max))
}

// The two layouts of glibc's loader cache (sysdeps/generic/dl-cache.h). The old one is a header and 12-byte
// entries; glibc before 2.32 wrote it with the new one after it, aligned, and the loader reads only the new.
const (
	ldCacheOldMagic = "ld.so-1.7.0"
	ldCacheNewMagic = "glibc-ld.so.cache1.1"
	// ldCacheOldEntry is struct file_entry: flags, key, value.
	ldCacheOldEntry = 12
	// ldCacheNewHeader is struct cache_file_new up to its first entry, and ldCacheNewEntry is struct
	// file_entry_new: flags, key, value, osversion, hwcap.
	ldCacheNewHeader = 48
	ldCacheNewEntry  = 24
	// maxLdCacheString bounds one name or path read out of the string table.
	maxLdCacheString = 4096
)

// parseLdCache returns the path of every entry of a loader cache whose name is a libssl (R4's
// libssl\.so(\.\d+)*), in the cache's order, which is the order the loader prefers them in. It reads the
// layout the loader reads: the new format, at the start of the file or after an old-format section, whose
// string offsets count from the new header. An entry whose strings do not read is passed over, the walk
// ends where the file does, and nothing in the file can make it panic (FuzzParseLdCache).
func parseLdCache(data []byte) []string {
	base := uint64(0)
	if bytes.HasPrefix(data, []byte(ldCacheOldMagic)) {
		if len(data) < 16 {
			return nil
		}
		n := uint64(bin.NativeEndian.Uint32(data[12:16]))
		base = (16 + n*ldCacheOldEntry + 7) &^ 7 // ALIGN_CACHE: struct cache_file_new is 8-aligned
	}
	if base > uint64(len(data)) || !bytes.HasPrefix(data[base:], []byte(ldCacheNewMagic)) {
		return nil
	}
	hdr := data[base:]
	if len(hdr) < ldCacheNewHeader {
		return nil
	}
	n := uint64(bin.NativeEndian.Uint32(hdr[20:24]))
	var out []string
	for i := uint64(0); i < n; i++ {
		off := ldCacheNewHeader + i*ldCacheNewEntry
		if off+ldCacheNewEntry > uint64(len(hdr)) {
			break
		}
		e := hdr[off : off+ldCacheNewEntry]
		name, ok := cacheString(hdr, bin.NativeEndian.Uint32(e[4:8]))
		if !ok || !libsslName.MatchString(name) {
			continue
		}
		path, ok := cacheString(hdr, bin.NativeEndian.Uint32(e[8:12]))
		if !ok || !filepath.IsAbs(path) {
			continue
		}
		out = append(out, path)
	}
	return out
}

// cacheString reads the NUL-terminated string at off in the cache's string table.
func cacheString(data []byte, off uint32) (string, bool) {
	if uint64(off) >= uint64(len(data)) {
		return "", false
	}
	s := data[off:]
	if len(s) > maxLdCacheString {
		s = s[:maxLdCacheString]
	}
	end := bytes.IndexByte(s, 0)
	if end <= 0 {
		return "", false
	}
	return string(s[:end]), true
}
