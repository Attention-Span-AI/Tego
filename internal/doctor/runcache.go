// SPDX-License-Identifier: Apache-2.0

package doctor

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"golang.org/x/sys/unix"

	bpfobj "github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// The run-probe cache (R27 "What a run probes"): D7's tier-2 rows, the decision plane's mode probe and D8's answer, kept by a root run at reach
// cgroup so the next root run of the same binary on the same boot does not load every tier-2 program again.
// Those are the checks that cost. What the kernel answers them depends on two things. One is the machine: the
// kernel, its boot, its LSM list and lockdown mode, and the programs and the code judging them. The other is
// the process asking: its effective capabilities, its LSM labels, its user and mount namespaces, its own
// cgroup and cgroup namespace, and the invoking uid whose delegated cgroup D7 attaches in. A root process whose
// bounding set lost CAP_BPF, that runs in a confined SELinux domain, or whose cgroup has too little memory left
// for the programs' maps, is refused a program load the unrestricted root beside it is not. The key holds both
// halves, and each set of process privileges keeps its own entry, so one process's answer is never read by
// another that could not have got it. A process under a seccomp filter never uses the cache, since which
// syscalls its filter refuses cannot be read back. Everything else a run needs is probed afresh on every
// run.
//
// Only an answer that vouches for tier cgroup is kept. A fresh answer that does not vouch removes the entry
// for its own key. A run started from an entry that then fails removes that entry too
// (Report.DiscardCache). Either way the next run sees the change without a reboot, and /run is a tmpfs, so
// a reboot empties the cache anyway. What the key does not hold is a per-process restriction that leaves no
// trace in /proc (a Landlock domain, another tool's BPF LSM program, an LSM that keeps no label in
// /proc/<pid>/attr) and the process's resource limits (/proc/<pid>/limits). It can offer tier cgroup to a
// process the kernel then refuses. Such a run stops at Prepare, exit 125 before run_start, because Prepare
// does the same program loads and makes the same fanotify group. It never runs at a lower tier than it was
// selected for.

// runCacheVersion is the entry's format. It is part of the key, so an entry of another format is never read.
// Version 2 added the process's privilege to the key, and version 3 its mount namespace, its own cgroup and its
// cgroup namespace to that. Version 4 added the decision plane's answer (plane.go), and version 5
// vm.memfd_noexec (MemfdNoexec) to the key, with a faulted plane answer no longer kept. Version 6 added D2's answer
// and the kernel's functions a run asks its BTF about (runCacheEntry.BTF, KernelFuncs). Version 7 keeps an entry
// whose plane probe faulted without its plane answer (runCacheEntry.Plane), and D2 only when it passed.
const runCacheVersion = 7

// maxRunCacheBytes bounds what readFile reads: an entry is a few kilobytes of JSON.
const maxRunCacheBytes = 1 << 20

// runCacheKey is everything a cached answer depends on. A mismatch in any field is a fresh probe.
type runCacheKey struct {
	Version int `json:"version"`
	// BootID is /proc/sys/kernel/random/boot_id: a reboot, even into the same kernel with the same command
	// line, is a new machine as far as a cached answer is concerned.
	BootID string `json:"boot_id"`
	// Kernel is D1's release.
	Kernel string `json:"kernel"`
	// LSM is the active LSM list (D6's unprivileged half), in the kernel's order.
	LSM []string `json:"lsm"`
	// Lockdown is /sys/kernel/security/lockdown as the kernel prints it, "" without the file. Raising it
	// needs no reboot and changes which programs load.
	Lockdown string `json:"lockdown"`
	// BPFHash is the build's bpf_hash (R30), which names the programs D7 loaded.
	BPFHash string `json:"bpf_hash"`
	// MemfdNoexec is vm.memfd_noexec, "" when the kernel has none. At 2 the plane probe cannot make the executable
	// memfd it execs, and that answer is kept, so a change of the sysctl must not read it.
	MemfdNoexec string `json:"memfd_noexec"`
	// Binary is the running executable's device, inode, size and modification time: an upgraded or rebuilt
	// tego judges with its own code, even when its programs hash the same.
	Binary string `json:"binary"`
	// Process is the privilege of the process that asked. D7 and D8 are the only functional proof that it
	// may load programs and make a fanotify group, and missingFor's root line reads its euid alone.
	Process processPrivilege `json:"process"`
}

// processPrivilege is what, besides the machine, decides whether the kernel lets a process load a tier-2
// program, attach it in the invoking uid's cgroup, and make a fanotify group.
type processPrivilege struct {
	// CapEff is the status file's CapEff mask: CAP_BPF, CAP_PERFMON, CAP_NET_ADMIN and CAP_SYS_ADMIN are
	// what bpf(2) and fanotify_init(2) check, and a root process started with a reduced bounding set
	// (systemd's CapabilityBoundingSet=, setpriv --bounding-set) lacks them at euid 0.
	CapEff string `json:"cap_eff"`
	// Labels is the task's LSM labels, "<file>=<value>" for attr/current and each LSM's own
	// attr/<lsm>/current, in the directory's order, a value "" where the LSM keeps none for it: a confined
	// SELinux or AppArmor domain can be refused bpf(2) that an unconfined one is allowed.
	Labels []string `json:"labels"`
	// UserNS is the user namespace's device and inode. A process's capabilities count for bpf(2) only in
	// the initial one.
	UserNS string `json:"user_ns"`
	// MountNS is the mount namespace's device and inode: it decides which cgroupfs D7 finds the invoking uid's
	// delegated subtree through, and which file system D8 marks.
	MountNS string `json:"mnt_ns"`
	// Cgroup is the process's cgroup file as the kernel prints it, one line per hierarchy. Since 5.11 the
	// memory of a BPF map or program is charged to the memory cgroup of the process that creates it, so a
	// process whose cgroup has less memory left than the programs' maps need is refused a load that one in
	// another cgroup is not; and a cgroup is what another tool's cgroup-attached programs (BPF_LSM_CGROUP,
	// device programs) apply to. Two processes alike in every other respect but their cgroup keep an entry
	// each.
	Cgroup string `json:"cgroup"`
	// CgroupNS is the cgroup namespace's device and inode. Cgroup's paths are relative to that namespace's
	// root, so one path in two namespaces names two cgroups.
	CgroupNS string `json:"cgroup_ns"`
	// UID is the invoking uid. D7 attaches in a scratch cgroup under that uid's delegated subtree
	// (newScratchCgroup), and whether a program attaches there depends on what that subtree's ancestors hold.
	UID int `json:"uid"`
}

// runCacheEntry is one kept answer.
type runCacheEntry struct {
	Key      runCacheKey  `json:"key"`
	Programs Result       `json:"programs"`
	Hooks    []HookResult `json:"hooks"`
	// Plane and PlaneRows are the decision plane's mode probe and its rows (docs/p0/enforce-plane.md R21), kept
	// whatever it found except a skipped probe or one in which a mode faulted: tier cgroup falls back to fanotify
	// without a plane mode, so no other plane answer stops the entry vouching. A faulted answer's cause may pass,
	// so record keeps the entry's tier-2 half alone, Plane and PlaneRows nil, and a run that reads such an entry
	// answers the plane and nothing else (ForRun); loadIdentified refuses a skipped or faulted Plane. Its Selected
	// is re-derived from the machine's bpf.plane on every read.
	Plane         *PlaneState   `json:"plane"`
	PlaneRows     []HookResult  `json:"plane_rows"`
	Fanotify      Result        `json:"fanotify"`
	FanotifyState FanotifyState `json:"fanotify_state"`
	// BTF is D2's answer, and KernelFuncs whether the kernel's BTF has each of bpf.KernelFuncNames
	// (bpf.KernelFuncFacts). Both read the kernel's BTF alone, which a boot never changes and the key's boot, kernel
	// and binary pin, so a run that reads the entry parses no BTF: 50-100 ms of CPU in the KVM guests
	// (enforce-plane §2.18). Either is nil where the run that kept the entry had none to keep; that part is then
	// probed or parsed as before. BTF is kept only when D2 passed: a failed D2 is probed again.
	BTF         *Result         `json:"btf,omitempty"`
	KernelFuncs map[string]bool `json:"kernel_funcs,omitempty"`
}

// kernelAnswers is what an entry keeps of the kernel's BTF (runCacheEntry.BTF, KernelFuncs).
type kernelAnswers struct {
	btf   *Result
	funcs map[string]bool
}

// runCache is where entries live and how their key is read.
type runCache struct {
	// base is trusted as it is: "/" in production. dir is the path below it, walked one component at a time
	// with O_NOFOLLOW so no component can be a link (openDir).
	base string
	dir  []string
	// owner is the only uid that may own the directory and the entry: 0 in production. A test runs as
	// itself.
	owner int
	// key reads the key for a kernel release D1 reported and the invoking uid D3 and D7 were handed; ok is
	// false when any part cannot be read, and then nothing is read or written.
	key func(release string, uid int) (runCacheKey, bool)
	// refused is why openDir last refused the directory, or "": a directory that is there and not one only root may
	// write (a hand-made 1770 root:tego one, withdrawn by ADR 0042 (3)(b); a full or read-only disk) leaves every
	// run probing, and the report says so (Report.CacheNote). A directory that does not exist yet is not a refusal.
	refused string
	// waiting, when set, is called with a flight lock's name the first time a lockFlight call finds it held by
	// another caller: a test's way to know a caller waits rather than is about to take the lock. nil in
	// production.
	waiting func(name string)
}

// cachedAnswer is the entry a Report was built from.
type cachedAnswer struct {
	cache *runCache
	key   runCacheKey
	id    entryID // the file it was read from
}

// defaultRunCache is /run/tego, the directory the tier-2 backend keeps its build lock and slot table in
// (enforce-cgroup-observe.md §3), owned by root.
func defaultRunCache() *runCache {
	return &runCache{base: "/", dir: []string{"run", "tego"}, owner: 0, key: machineRunCacheKey}
}

// machineRunCacheKey reads this machine's key and this process's privilege. Any part it cannot read leaves
// the cache unused.
func machineRunCacheKey(release string, uid int) (runCacheKey, bool) {
	k := runCacheKey{Version: runCacheVersion, Kernel: release}
	if release == "" {
		return k, false
	}
	b, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if k.BootID = strings.TrimSpace(string(b)); err != nil || k.BootID == "" {
		return k, false
	}
	lsm, err := ReadLSMState()
	if err != nil {
		return k, false
	}
	k.LSM = lsm.Modules
	switch b, err := os.ReadFile(lockdownPath); {
	case err == nil:
		k.Lockdown = strings.TrimSpace(string(b))
	case !errors.Is(err, os.ErrNotExist):
		return k, false
	}
	switch b, err := os.ReadFile(memfdNoexecPath); {
	case err == nil:
		k.MemfdNoexec = strings.TrimSpace(string(b))
	case !errors.Is(err, os.ErrNotExist):
		return k, false
	}
	if k.BPFHash, err = bpfobj.Hash(); err != nil {
		return k, false
	}
	var st unix.Stat_t
	if err := unix.Stat("/proc/self/exe", &st); err != nil {
		return k, false
	}
	k.Binary = fmt.Sprintf("%d:%d:%d:%d.%09d", st.Dev, st.Ino, st.Size, st.Mtim.Sec, st.Mtim.Nsec)
	if k.Process, err = ownPrivilege(uid); err != nil {
		return k, false
	}
	return k, true
}

// ownPrivilege reads this process's privilege from the calling thread's view, /proc/thread-self: the kernel
// keeps credentials, labels, filters, namespaces and cgroup per thread, and every thread Go code runs on
// shares the process's, which is what D7 and D8 ran under. /proc/self shows the main thread instead, which Go
// parks for good, with whatever a locked goroutine left on it, when that goroutine exits. D5 used to be such
// a goroutine, and /proc/self then read "Seccomp: 2" for a process none of whose running threads had a
// filter, so the cache was never used after D5; D5 no longer runs on the main thread (onThrowawayThread), and
// the calling thread's view does not depend on that.
func ownPrivilege(uid int) (processPrivilege, error) {
	return readProcessPrivilege("/proc/thread-self", uid)
}

// lockdownPath is securityfs's lockdown file.
const lockdownPath = "/sys/kernel/security/lockdown"

// errUnderSeccomp is a process under a seccomp filter, whose refusals no file shows: an entry kept by a
// process without the filter could offer it a tier its filter keeps from loading, so it never uses the cache.
var errUnderSeccomp = errors.New("under a seccomp filter")

// readProcessPrivilege reads the privilege of the process whose /proc directory proc is.
func readProcessPrivilege(proc string, uid int) (processPrivilege, error) {
	p := processPrivilege{UID: uid}
	status, err := os.ReadFile(filepath.Join(proc, "status"))
	if err != nil {
		return p, err
	}
	fields := map[string]string{}
	for _, line := range strings.Split(string(status), "\n") {
		if name, value, ok := strings.Cut(line, ":"); ok {
			fields[name] = strings.TrimSpace(value)
		}
	}
	// A kernel without CONFIG_SECCOMP prints no Seccomp line; with none, a filter cannot be ruled out.
	switch mode, ok := fields["Seccomp"]; {
	case !ok:
		return p, errors.New("status: no Seccomp line")
	case mode != "0":
		return p, errUnderSeccomp
	}
	if p.CapEff = fields["CapEff"]; p.CapEff == "" {
		return p, errors.New("status: no CapEff line")
	}
	if p.Labels, err = readTaskLabels(filepath.Join(proc, "attr")); err != nil {
		return p, err
	}
	for _, ns := range []struct {
		name string
		id   *string
	}{{"user", &p.UserNS}, {"mnt", &p.MountNS}, {"cgroup", &p.CgroupNS}} {
		var st unix.Stat_t
		if err := unix.Stat(filepath.Join(proc, "ns", ns.name), &st); err != nil {
			return p, err
		}
		*ns.id = fmt.Sprintf("%d:%d", st.Dev, st.Ino)
	}
	cgroup, err := os.ReadFile(filepath.Join(proc, "cgroup"))
	if err != nil {
		return p, err
	}
	if p.Cgroup = strings.TrimSpace(string(cgroup)); p.Cgroup == "" {
		return p, errors.New("cgroup: empty")
	}
	return p, nil
}

// readTaskLabels reads attr/current and each LSM's own attr/<lsm>/current. EINVAL is an LSM that keeps no
// label for this task, or no LSM that answers current at all, and reads as "". A missing attr directory is
// a kernel with no LSM labels to read, and gives no labels. Any other error leaves the cache unused.
func readTaskLabels(attr string) ([]string, error) {
	var out []string
	read := func(name string) error {
		b, err := os.ReadFile(filepath.Join(attr, name))
		switch {
		case errors.Is(err, unix.EINVAL):
			b = nil
		case errors.Is(err, os.ErrNotExist):
			return nil
		case err != nil:
			return err
		}
		out = append(out, name+"="+strings.TrimRight(string(b), "\x00\n"))
		return nil
	}
	if err := read("current"); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(attr)
	if errors.Is(err, os.ErrNotExist) {
		return out, nil
	}
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		if e.IsDir() {
			if err := read(filepath.Join(e.Name(), "current")); err != nil {
				return nil, err
			}
		}
	}
	return out, nil
}

// name is the entry's file name: one per build, per set of process privileges and per binary, so two builds on
// one machine keep an answer each, and so do a full-root process and a restricted one, whose answers differ, and
// two binaries of one build (two installs, or a copy at another inode), which under one file would each read the
// other's entry as a miss and replace it, and so probe cold on every run.
func (c *runCache) name(k runCacheKey) string {
	b, _ := json.Marshal(k.Process)
	sum := sha256.Sum256(b)
	bin := sha256.Sum256([]byte(k.Binary))
	return "doctor-probe-" + k.BPFHash + "-" + hex.EncodeToString(sum[:8]) + "-" + hex.EncodeToString(bin[:8]) + ".json"
}

// openDir opens the cache directory, refusing any path an unprivileged user could have put there: each
// component below base is opened with O_NOFOLLOW, must be owned by root or owner, and may be writable by
// group or others only when sticky and not the last (a sticky directory lets others add entries but not
// replace another's). The last must be owner's own and writable by nobody else. With create, a missing last
// component is made 0700.
func (c *runCache) openDir(create bool) (fd int, err error) {
	defer func() {
		switch {
		case err == nil:
			c.refused = ""
		case !errors.Is(err, unix.ENOENT):
			c.refused = err.Error()
		}
	}()
	fd, err = unix.Open(c.base, unix.O_DIRECTORY|unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	for i, name := range c.dir {
		last := i == len(c.dir)-1
		var next int
		next, err = unix.Openat(fd, name, unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if errors.Is(err, unix.ENOENT) && create && last {
			if err = unix.Mkdirat(fd, name, 0o700); err == nil || errors.Is(err, unix.EEXIST) {
				next, err = unix.Openat(fd, name, unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_RDONLY|unix.O_CLOEXEC, 0)
			}
		}
		_ = unix.Close(fd)
		if err != nil {
			return -1, err
		}
		var st unix.Stat_t
		if err := unix.Fstat(next, &st); err != nil {
			_ = unix.Close(next)
			return -1, err
		}
		othersWrite := st.Mode&0o022 != 0 && (last || st.Mode&unix.S_ISVTX == 0)
		if othersWrite || (int(st.Uid) != c.owner && st.Uid != 0) || (last && int(st.Uid) != c.owner) {
			_ = unix.Close(next)
			return -1, fmt.Errorf("%s: owner %d, mode %#o: not a directory only root may write", name, st.Uid, st.Mode&0o7777)
		}
		fd = next
	}
	return fd, nil
}

// entryID names one file of the cache, not one key: a rename over the name gives the new file another inode
// or modification time.
type entryID struct {
	dev, ino uint64
	mtime    unix.Timespec
}

func idOf(st *unix.Stat_t) entryID { return entryID{uint64(st.Dev), st.Ino, st.Mtim} }

// loadIdentified returns the entry for k when there is a valid one, and the identity of the file it was read
// from: a regular file of owner's, with one link, no access for group or others, at most maxRunCacheBytes,
// whose key is k and whose answer vouches for tier cgroup with exactly this binary's tier-2 rows. Anything
// else is no entry, and the run probes.
func (c *runCache) loadIdentified(k runCacheKey) (runCacheEntry, entryID, bool) {
	b, id, ok := c.readFile(c.name(k))
	if !ok {
		return runCacheEntry{}, entryID{}, false
	}
	var e runCacheEntry
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&e); err != nil || !reflect.DeepEqual(e.Key, k) ||
		(e.Plane != nil && (e.Plane.Skipped || e.Plane.faulted())) || (e.Plane == nil && e.PlaneRows != nil) ||
		(e.BTF != nil && !passedBTF(*e.BTF)) || !vouches(e.Programs, e.Hooks, e.Fanotify, e.FanotifyState) {
		return runCacheEntry{}, entryID{}, false
	}
	return e, id, true
}

// readFile reads the cache's file name when it is a regular file of owner's, with one link, no access for group or
// others, and at most maxRunCacheBytes; ok is false otherwise.
func (c *runCache) readFile(name string) (b []byte, id entryID, ok bool) {
	dir, err := c.openDir(false)
	if err != nil {
		return nil, entryID{}, false
	}
	defer func() { _ = unix.Close(dir) }()
	fd, err := unix.Openat(dir, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, entryID{}, false
	}
	f := os.NewFile(uintptr(fd), name)
	defer func() { _ = f.Close() }()
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || int(st.Uid) != c.owner ||
		st.Mode&0o077 != 0 || st.Nlink != 1 || st.Size > maxRunCacheBytes {
		return nil, entryID{}, false
	}
	b, err = io.ReadAll(io.LimitReader(f, maxRunCacheBytes+1))
	if err != nil || len(b) > maxRunCacheBytes {
		return nil, entryID{}, false
	}
	return b, idOf(&st), true
}

// recordWith keeps a fresh answer that vouches for tier cgroup, with what the run learned of the kernel's BTF
// beside it, and removes k's entry otherwise. A plane answer in which a mode's probe faulted is not kept: its
// cause (a full or read-only fixtures directory, a timeout under load) is not in the key and may be gone by
// the next run, so that run probes the plane again. D7's tier-2 rows and D8's answer do not depend on it and
// are kept without a plane answer (runCacheEntry.Plane). It never fails the run: an entry it cannot write is
// an entry the next run does not find, and that run probes. It returns the kept file's identity, nil when it
// kept none.
func (c *runCache) recordWith(k runCacheKey, programs Result, rows []HookResult, plane *PlaneState,
	planeRows []HookResult, fan Result, fanState FanotifyState, kern kernelAnswers) *entryID {
	if !vouches(programs, rows, fan, fanState) || plane == nil || plane.Skipped {
		c.drop(k)
		return nil
	}
	if plane.faulted() {
		plane, planeRows = nil, nil
	}
	if kern.btf != nil && !passedBTF(*kern.btf) {
		kern.btf = nil
	}
	id, err := c.storeID(runCacheEntry{Key: k, Programs: programs, Hooks: rows, Plane: plane, PlaneRows: planeRows,
		Fanotify: fan, FanotifyState: fanState, BTF: kern.btf, KernelFuncs: kern.funcs})
	if err != nil {
		c.refused = "write: " + err.Error()
		return nil
	}
	return &id
}

// passedBTF reports whether r is a passing D2, the only D2 an entry keeps.
func passedBTF(r Result) bool { return r.ID == CheckBTF && r.OK && !r.Skipped }

// storeID writes e as owner's 0600 file, through a temporary file and a rename in the same directory, so a
// reader sees the old entry or the new one and never part of one. It returns the identity of the file it
// wrote: the rename keeps its inode and modification time.
func (c *runCache) storeID(e runCacheEntry) (id entryID, err error) {
	b, err := json.Marshal(e)
	if err != nil {
		return id, err
	}
	return c.writeFile(c.name(e.Key), b)
}

// writeFile writes b as the cache's file name, owner's and 0600, through a temporary file and a rename in the same
// directory, and returns the identity of the file it wrote: the rename keeps its inode and modification time.
func (c *runCache) writeFile(name string, b []byte) (id entryID, err error) {
	dir, err := c.openDir(true)
	if err != nil {
		return id, err
	}
	defer func() { _ = unix.Close(dir) }()
	tmp := fmt.Sprintf(".%s.%d.tmp", name, os.Getpid())
	_ = unix.Unlinkat(dir, tmp, 0) // one a killed run of the same pid left
	fd, err := unix.Openat(dir, tmp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return id, err
	}
	f := os.NewFile(uintptr(fd), tmp)
	defer func() {
		if err != nil {
			_ = unix.Unlinkat(dir, tmp, 0)
		}
	}()
	if _, err = f.Write(b); err != nil {
		_ = f.Close()
		return id, err
	}
	var st unix.Stat_t
	if err = unix.Fstat(fd, &st); err != nil {
		_ = f.Close()
		return id, err
	}
	if err = f.Close(); err != nil {
		return id, err
	}
	return idOf(&st), unix.Renameat(dir, tmp, dir, name)
}

// drop removes k's entry, if any.
func (c *runCache) drop(k runCacheKey) { c.dropIf(k, nil) }

// dropName removes the cache's file name, if any.
func (c *runCache) dropName(name string) {
	dir, err := c.openDir(false)
	if err != nil {
		return
	}
	defer func() { _ = unix.Close(dir) }()
	_ = unix.Unlinkat(dir, name, 0)
}

// dropIf removes k's entry, and with id non-nil only while the file under that name is still the one id names:
// another run's fresh answer renamed over it is not the answer the caller doubts. The check and the unlink are
// two calls, so a rename between them can still lose a fresh entry; that costs the next run a probe and nothing
// more.
func (c *runCache) dropIf(k runCacheKey, id *entryID) {
	dir, err := c.openDir(false)
	if err != nil {
		return
	}
	defer func() { _ = unix.Close(dir) }()
	if id != nil {
		var st unix.Stat_t
		if err := unix.Fstatat(dir, c.name(k), &st, unix.AT_SYMLINK_NOFOLLOW); err != nil || idOf(&st) != *id {
			return
		}
	}
	_ = unix.Unlinkat(dir, c.name(k), 0)
}

// vouches reports whether D7's tier-2 rows and D8's answer say tier cgroup's own checks hold: D7 and D8 both
// passed, D8's FAN_DENY refused the probe's open, and the rows are exactly this binary's tier-2 hooks, in
// order, each loaded and attached or an optional hook this kernel predates. It is the only answer the cache
// keeps, and a loaded entry is held to it again, so an entry can never hold a failure a run would then miss.
// A capability-only network row is kept as it was probed, failed or not: it gates no tier (programsVerdict,
// missingHooks), so a run reading it misses nothing a probe would have refused. Amended 2026-10-05: such a row
// that failed used to fail the vouch, so one kernel without syscall tracepoints kept every root run probing.
func vouches(programs Result, rows []HookResult, fan Result, fanState FanotifyState) bool {
	if programs.ID != CheckPrograms || !programs.OK || fan.ID != CheckFanotify || !fan.OK || !fanState.Refuses {
		return false
	}
	want := tierHooks(backend.TierCgroup)
	if len(rows) != len(want) {
		return false
	}
	for i, h := range want {
		r := rows[i]
		if r.Hook != h.Name || r.Tier != h.Tier || r.Capture {
			return false
		}
		if !r.OK() && !(h.optional && r.Absent) && !h.capabilityOnly {
			return false
		}
	}
	return true
}

// CacheNote says why the run-probe cache could not be used when a run tried it and was refused: the directory
// is not one only root may write, or an entry could not be written. "" when the cache worked, was not asked, or
// simply had no entry. Every such run probes D7, the plane and D8 afresh, so the note is what tells an operator
// why runs are slow; it never fails a run.
func (r *Report) CacheNote() string {
	if r == nil {
		return ""
	}
	return r.cacheNote
}

// CoordinationNote says why a run could not coordinate its probe with a concurrent run's of the same key (R27
// "Concurrent misses"): another run held the lock past the wait, a lock file or its directory failed its
// checks, or no lock file could be added. "" when it coordinated or did not need to. The run probed as it
// would have without coordination, and still read and kept the run-probe cache, so it is not CacheNote's
// "unusable"; it never fails a run.
func (r *Report) CoordinationNote() string {
	if r == nil {
		return ""
	}
	return r.coordinationNote
}

// FromCache reports whether D7's tier-2 rows and D8's answer in this report were read from the run-probe
// cache rather than probed (ForRun). doctor.Run's report never is.
func (r *Report) FromCache() bool { return r != nil && r.cached != nil }

// DiscardCache removes the cached answer this report was built from, if it was built from one. `tego run`
// calls it when a run it selected from this report could not start: the answer vouched for a tier the run
// then could not prepare, so the next run probes afresh instead of trusting it again.
func (r *Report) DiscardCache() {
	if !r.FromCache() {
		return
	}
	r.cached.cache.dropIf(r.cached.key, &r.cached.id)
}
