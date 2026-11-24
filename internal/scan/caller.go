// SPDX-License-Identifier: Apache-2.0

package scan

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unicode"

	"github.com/attention-span-ai/tego/internal/grouptrust"
	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/internal/runscope"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"golang.org/x/sys/unix"
)

// Caller contains kernel identity facts supplied by the CLI, never from saved data.
// Sudo means SUDO_UID is present, even if empty or malformed.
type Caller struct {
	UID, EUID       uint32
	PID             int
	Sudo            bool
	CgroupNamespace uint64
	// PIDNamespace is the inode of the caller's own PID namespace (PIDNamespace reads it through /proc/self, which
	// a freshly mounted /proc cannot fake). Zero means it could not be read. Anything but InitPIDNS refuses a
	// negative answer: a scan from a nested namespace sees only that namespace's processes.
	PIDNamespace uint64
	// Membership is the caller's own answer to "outside every tego run?", which the command line computes for its
	// own process (internal/platform/peer.Self) and hands in; scan makes no such proof itself. Its zero value is
	// inside, and anything but an outside answer refuses the scan. In the kernel's first cgroup namespace it agrees
	// with the path scan reads itself; in any other it is what admits a caller at all.
	Membership runscope.Answer
	// InitialRoot is the same config.InitNSRoot fact used by tego agents.
	InitialRoot bool
	Recipient   uint32
}

type callerIdentity struct {
	UID, GID                         uint32
	Home, Boot                       string
	OuterNamespace, NamespaceUnknown bool
	Accounts                         []localAccount
	Recipient                        uint32
	Sources                          []processSource
}

// InitPIDNS is the inode of the initial PID namespace (PROC_PID_INIT_INO, include/linux/proc_ns.h). It is fixed:
// a namespace made later gets a dynamic inode from 0xF0000000 up, so no other PID namespace has it.
const InitPIDNS uint64 = 0xEFFFFFFC

// CgroupNamespace reads the caller's namespace inode, without opening namespace contents.
func CgroupNamespace(root string, pid int) (uint64, error) {
	fs, err := openProc(root)
	if err != nil {
		return 0, err
	}
	defer fs.close()
	p, err := fs.open(pid)
	if err != nil {
		return 0, err
	}
	defer p.close()
	// ns/cgroup is a kernel namespace link. It is not a content-source link.
	fd, err := p.(*processFS).dir.Openat("ns", unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return 0, err
	}
	defer func() { _ = fd.Close() }()
	ns, err := fd.Openat("cgroup", unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		return 0, err
	}
	defer func() { _ = ns.Close() }()
	return namespaceInode(ns)
}

// PIDNamespace reads the inode of the PID namespace the calling process is in. It goes through root/self, never a
// number: a /proc mounted fresh inside a nested namespace shows that namespace's pid 1 and the caller's pid there
// like an initial /proc would, and its NSpid line has one entry, but ns/pid of the process itself is the kernel's
// answer for where it runs. A /proc of a namespace the caller is not in has no "self" for it, so that fails too.
func PIDNamespace(root string) (uint64, error) {
	fs, err := openProc(root)
	if err != nil {
		return 0, err
	}
	defer fs.close()
	ns, err := fs.dir.Openat("self/ns/pid", unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		return 0, err
	}
	defer func() { _ = ns.Close() }()
	return namespaceInode(ns)
}

// Namespaces reads the caller's cgroup and PID namespace inodes; either is zero when it could not be read, which
// the scan treats as a namespace it cannot judge.
func Namespaces(root string, pid int) (cgroup, pidns uint64) {
	cgroup, _ = CgroupNamespace(root, pid)
	pidns, _ = PIDNamespace(root)
	return cgroup, pidns
}

// namespaceInode returns the inode of an open namespace handle after proving it is one (nsfs).
func namespaceInode(ns *sys.FD) (uint64, error) {
	var filesystem unix.Statfs_t
	if err := ns.Fstatfs(&filesystem); err != nil {
		return 0, err
	}
	if filesystem.Type != unix.NSFS_MAGIC {
		return 0, errType
	}
	var st unix.Stat_t
	if err := ns.Fstat(&st); err != nil {
		return 0, err
	}
	return st.Ino, nil
}

// unjudgedNamespace reports a caller in a cgroup namespace that is not the kernel's first one, or whose namespace
// could not be read, without an outside answer of its own: there every cgroup path is read from the namespace's
// root, a run's scope above that root would not show, and only the rule's proof (Membership) says none is there.
func unjudgedNamespace(c Caller) bool {
	return c.CgroupNamespace != runscope.InitCgroupNS && !c.Membership.Outside()
}

// identifyCaller refuses before discovery. Failed guard reads never become an
// outside answer, including a private cgroup namespace which hides ancestors.
func identifyCaller(ctx context.Context, fs procAccess, root, passwd, boot string, c Caller) (callerIdentity, string) {
	return identifyCallerMode(ctx, fs, root, passwd, boot, c, false)
}

func identifyCallerMode(ctx context.Context, fs procAccess, root, passwd, boot string, c Caller, advanced bool) (callerIdentity, string) {
	out := callerIdentity{UID: c.UID, Recipient: c.UID, Sources: []processSource{}}
	if advanced {
		if !c.InitialRoot || c.UID != 0 || c.EUID != 0 {
			return out, "privilege"
		}
		out.Recipient = c.Recipient
		c.Sudo = false // Root is authorized; SUDO_UID chooses only the save recipient.
	}
	if ctx.Err() != nil {
		return out, "deadline"
	}
	if c.UID != c.EUID || c.Sudo || unjudgedNamespace(c) {
		return out, "privilege"
	}
	p, err := fs.open(c.PID)
	if err != nil {
		return out, "privilege"
	}
	defer p.close()
	st, err := callerStatus(ctx, p)
	if err != nil {
		return out, "privilege"
	}
	owner, err := p.owner()
	if err != nil || owner != c.UID {
		return out, "privilege"
	}
	if reason := callerPrivilege(c, st, owner); reason != "" {
		return out, reason
	}
	if ctx.Err() != nil {
		return out, "deadline"
	}
	b, err := p.read("cgroup", maxProcText)
	if err != nil {
		return out, "governed"
	}
	if _, err := parseCgroup(b, c.UID); err != nil {
		return out, "governed"
	}
	cg, err := runscope.Unified(b)
	if err != nil || runscope.LooksGoverned(cg) || runscope.OutsideNamespace(cg) || !c.Membership.Outside() {
		return out, "governed"
	}
	after, err := callerStatus(ctx, p)
	afterOwner, ownerErr := p.owner()
	if err != nil || ownerErr != nil || owner != afterOwner || st != after {
		return out, "privilege"
	}
	// More than one NSpid entry means this /proc is an outer namespace's; a nested namespace's own fresh /proc shows
	// one entry, so the caller's own PID namespace inode is the proof of the initial one. A time, uts, ipc or mount
	// namespace changes nothing about which processes /proc lists (a private /proc mount of the same PID namespace
	// lists the same ones), and a /proc of another PID namespace is the case above: the caller is not in it, so
	// root/self has no namespace for it and PIDNamespace is zero.
	out.OuterNamespace = st.nspids > 1 || c.PIDNamespace != 0 && c.PIDNamespace != InitPIDNS
	out.NamespaceUnknown = st.nspids == 0 || c.PIDNamespace == 0
	out.Sources = append(out.Sources, procSource(filepath.Join(root, strconv.Itoa(c.PID), "status"), nil, false), procSource(filepath.Join(root, strconv.Itoa(c.PID), "cgroup"), nil, false))
	b, err = callerAccountBytes(ctx, passwd)
	out.Sources = append(out.Sources, procSource(passwd, err, false))
	if err != nil {
		source := &out.Sources[len(out.Sources)-1]
		source.Reason = "owner"
		source.AccountRepair = grouptrust.AccountRepair(err)
		return out, "owner"
	}
	if advanced {
		out.Accounts, err = parseLocalAccounts(b)
	}
	if err == nil {
		out.Home, out.GID, err = parsePasswd(b, out.Recipient)
	}
	if err != nil {
		out.Sources[len(out.Sources)-1] = procSource(passwd, err, false)
		return out, "owner"
	}
	b, err = readLocalMetadata(ctx, boot, 64, c.UID)
	if err == nil {
		out.Boot, err = parseBoot(b)
	}
	out.Sources = append(out.Sources, procSource(boot, err, false))
	return out, ""
}

// Caller identity and discovery share the same resolver, root placement policy,
// byte comparison and retained descriptors across two fresh passes (ADR 0145).
func callerAccountBytes(ctx context.Context, path string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	read := func(p string) ([]byte, error) { return grouptrust.ReadAccountFileAt("/", p, 0) }
	if fixture, ok := ctx.Value(callerAccountReaderKey{}).(func(string) ([]byte, error)); ok {
		read = fixture
	}
	b, err := read(path)
	if err == nil {
		err = ctx.Err()
	}
	return b, err
}

// readLocalMetadata uses the same pin/type/data-open/recheck sequence as proc.
// Callers name boot_id or a typed run record under the trusted ledger root; passwd uses the shared account collector.
// No path comes from record content.
func readLocalMetadata(ctx context.Context, path string, limit int, uid uint32) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	pin, _, err := metadataPath(ctx, path, false)
	if err != nil {
		return nil, err
	}
	defer func() { _ = pin.Close() }()
	var b []byte
	err = withMetadataFile(ctx, pin, uid, false, func(f *os.File, size int64) error {
		if size > int64(limit) {
			return errSize
		}
		var err error
		b, err = io.ReadAll(io.LimitReader(f, int64(limit)+1))
		if err == nil && len(b) > limit {
			return errSize
		}
		return err
	})
	return b, err
}

func withMetadataFile(ctx context.Context, pin *sys.FD, uid uint32, appendOnly bool, visit func(*os.File, int64) error) error {
	var before unix.Stat_t
	if err := pin.Fstat(&before); err != nil {
		return err
	}
	if before.Mode&unix.S_IFMT == unix.S_IFLNK {
		return unix.ELOOP
	}
	if before.Mode&unix.S_IFMT != unix.S_IFREG || before.Nlink != 1 {
		return errType
	}
	if before.Uid != uid && before.Uid != 0 {
		return errOwner
	}
	if before.Mode&0022 != 0 {
		return errOwner
	}
	if before.Size < 0 {
		return errSize
	}
	var fd *sys.FD
	err := pin.ProcPath(func(path string) error {
		var e error
		fd, e = sys.Own(unix.Open(path, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0))
		return e
	})
	if err != nil {
		return err
	}
	f, err := fd.Release("scan-local-metadata")
	if err != nil {
		_ = fd.Close()
		return err
	}
	defer func() { _ = f.Close() }()
	var opened unix.Stat_t
	if err := sys.FstatFile(f, &opened); err != nil {
		return err
	}
	if !sameInode(before, opened) && (!appendOnly || !sameGrowingRecord(before, opened)) {
		return errChanged
	}
	if err := visit(f, before.Size); err != nil {
		return err
	}
	var after unix.Stat_t
	if err := sys.FstatFile(f, &after); err != nil {
		return err
	}
	unchanged := sameInode(before, after)
	if appendOnly {
		// An active writer appends while the bounded probe runs. Preserve the
		// pinned identity and trust checks without treating normal growth as loss.
		unchanged = sameGrowingRecord(before, after)
	}
	if !unchanged {
		return errChanged
	}
	return ctx.Err()
}

func sameGrowingRecord(a, b unix.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Mode == b.Mode && a.Uid == b.Uid && a.Gid == b.Gid && a.Nlink == b.Nlink && b.Size >= a.Size
}

// localAccount retains only the local identity needed for fixed unit/spool paths.
type localAccount struct {
	UID, GID   uint32
	Home, Name string
}

func parsePasswd(b []byte, uid uint32) (string, uint32, error) {
	accounts, err := parseAccounts(b, false)
	if err != nil {
		return "", 0, err
	}
	home := ""
	var gid uint32
	for _, a := range accounts {
		if a.UID != uid {
			continue
		}
		if home != "" || !plainPath(a.Home) || filepath.Clean(a.Home) != a.Home {
			return "", 0, errSyntax
		}
		home, gid = a.Home, a.GID
	}
	if home == "" {
		return "", 0, errOwner
	}
	return home, gid, nil
}

func parseLocalAccounts(b []byte) ([]localAccount, error) { return parseAccounts(b, true) }

// One passwd grammar serves the basic lookup and advanced account inventory.
// Password, GECOS and shell fields are discarded and never enter an observation.
func parseAccounts(b []byte, all bool) ([]localAccount, error) {
	if len(b) > 1<<20 {
		return nil, errSize
	}
	accounts := []localAccount{}
	names := map[string]bool{}
	for _, line := range bytes.Split(b, []byte{'\n'}) {
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		f := bytes.Split(line, []byte{':'})
		if len(f) != 7 {
			return nil, errSyntax
		}
		n, e := strconv.ParseUint(string(f[2]), 10, 32)
		if e != nil || n == 4294967295 {
			return nil, errSyntax
		}
		g, e := strconv.ParseUint(string(f[3]), 10, 32)
		if e != nil || g == 4294967295 {
			return nil, errSyntax
		}
		a := localAccount{UID: uint32(n), GID: uint32(g), Home: string(f[5])}
		if all {
			if len(accounts) >= 4096 {
				return nil, errLimit
			}
			a.Name = string(f[0])
			if !plainAccountName(a.Name) || names[a.Name] || !plainPath(a.Home) || filepath.Clean(a.Home) != a.Home {
				return nil, errSyntax
			}
			names[a.Name] = true
		}
		accounts = append(accounts, a)
	}
	return accounts, nil
}

func plainAccountName(s string) bool {
	if len(s) == 0 || len(s) > 256 || s == "." || s == ".." {
		return false
	}
	for _, r := range s {
		if !unicode.IsPrint(r) || unicode.IsSpace(r) || r == ':' || r == '/' {
			return false
		}
	}
	return true
}

func parseBoot(b []byte) (string, error) {
	s := strings.TrimSuffix(string(b), "\n")
	if len(s) != 36 {
		return "", errSyntax
	}
	for i, c := range []byte(s) {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return "", errSyntax
			}
		} else if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return "", errSyntax
		}
	}
	return s, nil
}

func callerPrivilege(c Caller, st statusInfo, owner uint32) string {
	if c.UID != c.EUID || c.Sudo || unjudgedNamespace(c) || owner != c.UID {
		return "privilege"
	}
	for _, id := range st.uids {
		if id != c.UID {
			return "privilege"
		}
	}
	if st.capsSeen != 4 || st.caps != 0 && c.UID != 0 {
		return "privilege"
	}
	return ""
}

func callerStatus(ctx context.Context, p processFiles) (statusInfo, error) {
	if err := ctx.Err(); err != nil {
		return statusInfo{}, err
	}
	return readStatus(p)
}

// WithRecordLock pins and opens a regular lock under the borrowed run directory.
// Type and trust checks precede the data open. This stricter scan policy stays
// local instead of adding a /proc reopen dependency to every ledger reader.
func WithRecordLock(ctx context.Context, dir sys.Lender, uid uint32, visit func(*os.File) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	var pin *sys.FD
	err := dir.Borrow(func(n int) error {
		var err error
		pin, err = sys.Own(unix.Openat(n, "lock", unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0))
		return err
	})
	if err != nil {
		return err
	}
	defer func() { _ = pin.Close() }()
	return withMetadataFile(ctx, pin, uid, false, func(f *os.File, _ int64) error {
		return visit(f)
	})
}

// WithRecordBytes pins a trusted run directory and its regular events file. The
// callback may use the directory for bounded ledger state probes before and after
// calling readStart, which reads at most 64 KiB. Descriptors stay owned here.
func WithRecordBytes(ctx context.Context, root, id string, uid uint32, visit func(sys.Lender, *os.File, func() ([]byte, error)) error) error {
	if !identity.RunID(id).Valid() || !plainPath(root) {
		return errSyntax
	}
	dir, _, err := metadataPath(ctx, filepath.Join(root, id), false)
	if err != nil {
		return err
	}
	defer func() { _ = dir.Close() }()
	var before unix.Stat_t
	if err := dir.Fstat(&before); err != nil {
		return err
	}
	if before.Mode&unix.S_IFMT != unix.S_IFDIR {
		return errType
	}
	if before.Uid != uid && before.Uid != 0 || before.Mode&0022 != 0 {
		return errOwner
	}
	pin, err := dir.Openat("events.jsonl", unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer func() { _ = pin.Close() }()
	err = withMetadataFile(ctx, pin, uid, true, func(f *os.File, _ int64) error {
		return visit(dir, f, func() ([]byte, error) {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			const limit = 64 << 10
			b, err := bufio.NewReaderSize(io.NewSectionReader(f, 0, limit+1), limit+1).ReadSlice('\n')
			if len(b) > limit || err == bufio.ErrBufferFull {
				return nil, errSize
			}
			if err == io.EOF {
				return nil, errSyntax
			}
			return b, err
		})
	})
	if err != nil {
		return err
	}
	// Directory timestamps may not advance when a name is swapped within one
	// filesystem clock tick. Bind the current name to the pinned record too.
	var pinned, named unix.Stat_t
	if err := pin.Fstat(&pinned); err != nil {
		return err
	}
	if err := dir.Fstatat("events.jsonl", &named, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return errChanged
	}
	if !sameGrowingRecord(pinned, named) {
		return errChanged
	}
	var after unix.Stat_t
	if err := dir.Fstat(&after); err != nil {
		return err
	}
	if !sameInode(before, after) {
		return errChanged
	}
	return ctx.Err()
}

// RecordReadReason maps a transient record-probe error to the closed reason codes
// used by scan sources. No operating-system text or record payload is retained.
func RecordReadReason(err error) string {
	if err == nil {
		return "none"
	}
	return fixedReason(err)
}
