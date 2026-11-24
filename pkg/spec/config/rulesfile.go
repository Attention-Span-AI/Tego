// SPDX-License-Identifier: Apache-2.0

package config

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// This file is how every rules file is read (ADR 0059, amended 2026-11-19, rounds 4 and 5): a contract, a profile it
// extends, a file it includes, a registry entry and `tego run <name>`'s lookup of one, a .tego/agents entry, a general
// policy layer, a run's recorded copy, a test table. ReadRulesFile is the one function that reads them, and it checks
// the file system of the descriptor it reads (fstatfs on that open file, never a second lookup of the name), so no
// reader can check one file and read another. TestRulesFilesAreReadThroughOneFunction holds the tree to it.

// ErrOwnerUnreliable is a rules file on a file system whose owner and permissions tego cannot rely on.
var ErrOwnerUnreliable = errors.New("its file system's owner and permissions cannot be relied on")

// ErrNotAFile is input that is neither a regular file, a pipe nor a socket (a device, a directory): it is refused by
// name rather than read, since a tty would wait forever.
var ErrNotAFile = errors.New("not a regular file or a pipe")

// ReadRulesFile reads a rules file from f, a file its caller opened (and checked as it must: the one-name rule, the
// owner and mode rules), at most limit bytes: callers pass their cap plus one, so a file past the cap is told apart
// without reading more (a YAML bomb never reaches the decoder). It first refuses f when its file system's owner and
// permission bits cannot be relied on (ownerUnreliable, on f's own descriptor), and reads only from a regular file, a
// pipe or a socket: a socket is standard input handed over as a stream, as a pipe is (Node's child_process stdio
// 'pipe' is a socketpair); a path names no socket that open(2) can read, so only a descriptor reaches here as one.
// A done ctx stops the read between two reads of f (a profile graph's budget), and its error is returned.
func ReadRulesFile(ctx context.Context, f *os.File, name string, limit int64) ([]byte, error) {
	if err := ownerUnreliable(f, name); err != nil {
		return nil, err
	}
	st, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("agent: %w", err)
	}
	if m := st.Mode(); !m.IsRegular() && m.Type() != fs.ModeNamedPipe && m.Type() != fs.ModeSocket {
		return nil, fmt.Errorf("agent: %s: %w", name, ErrNotAFile)
	}
	data, err := io.ReadAll(io.LimitReader(ctxReader{ctx: ctx, r: f}, limit))
	if err == nil {
		err = ctx.Err()
	}
	if err != nil {
		return nil, fmt.Errorf("agent: read %s: %w", name, err)
	}
	return data, nil
}

// ctxReader reads r until ctx is done: cancellation is observed between two reads of a regular file; it cannot
// interrupt a file system call already in progress.
type ctxReader struct {
	ctx context.Context
	r   io.Reader
}

func (r ctxReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.r.Read(p)
}

// ownerFSError is a rules file refused for its file system: what the file system is and why that matters.
type ownerFSError struct {
	path, what string
	windows    bool
}

func (e ownerFSError) Error() string {
	who := "anything that writes that disk or share outside Linux"
	if e.windows {
		who = "any Windows program"
	}
	return fmt.Sprintf("agent: rules file %s is on %s, a file system whose owner and permissions tego cannot rely on: "+
		"%s can change the rules between runs, and nothing on the file says so; keep the rules file, and every file "+
		"it extends, in your Linux home (for example ~/tego/), and run it from there: the project may stay where it is",
		e.path, e.what, who)
}

func (e ownerFSError) Unwrap() []error { return []error{ErrOwnerUnreliable, ErrUntrusted} }

// ownerUnreliable refuses f, an open rules file, when its file system's owner and permission bits cannot be relied on
// (ownerFSKind). Only a regular file is asked: a pipe or a socket handed over as standard input is no file on a disk.
// A file that cannot be looked at, or whose file system cannot be read, is refused too (fail closed).
func ownerUnreliable(f *os.File, path string) error {
	fi, err := f.Stat()
	if err != nil {
		return ownerFSError{path: path, what: "a file tego could not look at (" + err.Error() + ")"}
	}
	if !fi.Mode().IsRegular() {
		return nil
	}
	magic, fstype, point, super, err := rulesFileFS(f)
	if err != nil {
		return ownerFSError{path: path, what: "a file system tego could not read (" + err.Error() + ")"}
	}
	if what, windows := ownerFSKind(magic, fstype, point, super); what != "" {
		return ownerFSError{path: path, what: what, windows: windows}
	}
	return nil
}

// The statfs magic numbers golang.org/x/sys/unix does not name.
const (
	ntfsMagic  = 0x5346544e // fs/ntfs NTFS_SB_MAGIC, the driver ntfs3 replaced
	ntfs3Magic = 0x7366746e // fs/ntfs3/super.c
)

// rulesFileFS is what ownerUnreliable asks of f's file system: its statfs magic, and, where the magic alone cannot
// answer (9p, which WSL's Windows drive is, and FUSE, which virtiofs and fuseblk are), its mount row's type, mount
// point and super options (fileMountRow; "" for each when the row cannot be read). Every other file system is
// decided by its magic, so loading a rules file on an ordinary disk reads no mount table. A variable so a test
// describes a file on a Windows drive without one (and SetRulesFileFSForTest in a test build, for other packages).
var rulesFileFS = func(f *os.File) (magic int64, fstype, point, super string, err error) {
	var sfs unix.Statfs_t
	if err := lendFD(f, func(fd int) error { return unix.Fstatfs(fd, &sfs) }); err != nil {
		return 0, "", "", "", err
	}
	if sfs.Type == unix.V9FS_MAGIC || sfs.Type == unix.FUSE_SUPER_MAGIC {
		fstype, point, super = fileMountRow(f)
	}
	return int64(sfs.Type), fstype, point, super, nil //nolint:unconvert // Statfs_t.Type is an int64 on amd64, a uint32 on s390x
}

// ownerFSKind names a file system whose owner and permission bits tego cannot rely on, from its statfs magic and its
// mount row's type, mount point and super options ("" for each the mount table could not give), and says whether it
// is WSL's view of a Windows drive. "" when the bits can be relied on. Refused:
//   - WSL's Windows drives: 9p (or virtiofs) with drvfs's options, or WSL 1's drvfs;
//   - every other 9p share (V9FS_MAGIC) and virtiofs share: the host's files, owners mapped by the host;
//   - FAT, exFAT and NTFS disks (MSDOS_SUPER_MAGIC, EXFAT_SUPER_MAGIC, NTFS_SB_MAGIC, ntfs3's), and fuseblk (ntfs-3g,
//     exfat-fuse): every file's owner and mode come from the mount's options;
//   - SMB shares (CIFS_SUPER_MAGIC, SMB2_SUPER_MAGIC, SMB_SUPER_MAGIC; cifs, smb3): owners from the mount's options;
//   - a FUSE file system whose mount row cannot be read (ADR 0059): FUSE alone does not say whether it is a share of
//     another system's files (virtiofs, fuseblk) or a daemon the user runs.
//
// Not refused: ordinary Linux file systems, NFS (owners are the server's uids), tmpfs, overlay, and FUSE file systems
// other than virtiofs and fuseblk whose row says what they are (their owner is set by a daemon the user runs).
func ownerFSKind(magic int64, fstype, point, super string) (what string, windows bool) {
	at := ""
	if point != "" {
		at = " mounted at " + point
	}
	drvfs := fstype == "drvfs" || strings.Contains(","+super+",", ",aname=drvfs,") || strings.Contains(super, "aname=drvfs;")
	switch {
	case drvfs:
		return "the Windows drive (" + orName(fstype, "9p") + at + ")", true
	case magic == unix.V9FS_MAGIC || fstype == "9p":
		return "a 9p share" + at, false
	case fstype == "virtiofs":
		return "a virtiofs share of the host's files" + at, false
	case magic == unix.MSDOS_SUPER_MAGIC || fstype == "vfat" || fstype == "msdos":
		return "a FAT disk" + at, false
	case magic == unix.EXFAT_SUPER_MAGIC || fstype == "exfat":
		return "an exFAT disk" + at, false
	case magic == ntfsMagic || magic == ntfs3Magic || fstype == "ntfs" || fstype == "ntfs3":
		return "an NTFS disk" + at, false
	case fstype == "fuseblk":
		return "a disk mounted through FUSE (fuseblk)" + at, false
	case magic == unix.CIFS_SUPER_MAGIC || magic == unix.SMB2_SUPER_MAGIC || magic == unix.SMB_SUPER_MAGIC ||
		fstype == "cifs" || fstype == "smb3":
		return "an SMB share" + at, false
	case magic == unix.FUSE_SUPER_MAGIC && fstype == "":
		return "a FUSE file system whose mount tego could not look up", false
	}
	return "", false
}

func orName(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

// liveMountInfo is this process's own mount table.
const liveMountInfo = "/proc/self/mountinfo"

// maxMountInfoBytes bounds the table fileMountRow reads.
const maxMountInfoBytes = 16 << 20

// fileMountRow is the type, mount point and super options of the mount f is on, from this process's mount table by
// the mount id statx gives f ("" for each when either cannot be read: the statfs magic still decides, and a FUSE file
// system no row describes is refused).
func fileMountRow(f *os.File) (fstype, point, super string) {
	var sx unix.Statx_t
	if err := lendFD(f, func(fd int) error { return unix.Statx(fd, "", unix.AT_EMPTY_PATH, unix.STATX_MNT_ID, &sx) }); err != nil ||
		sx.Mask&unix.STATX_MNT_ID == 0 {
		return "", "", ""
	}
	mi, err := os.Open(liveMountInfo)
	if err != nil {
		return "", "", ""
	}
	defer func() { _ = mi.Close() }() // read-only
	data, err := io.ReadAll(io.LimitReader(mi, maxMountInfoBytes+1))
	if err != nil || len(data) > maxMountInfoBytes {
		return "", "", ""
	}
	return mountRowByID(data, strconv.FormatUint(sx.Mnt_id, 10))
}

// mountRowByID is the type, mount point and super options of the mountinfo row whose mount id is id ("" for each when
// no well-formed row has it): "<id> <parent> <maj:min> <root> <point> <options> [<optional>...] - <type> <source>
// <super options>", the point unescaped (\040, \011, \012, \134).
func mountRowByID(data []byte, id string) (fstype, point, super string) {
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64<<10), maxMountInfoBytes)
	for sc.Scan() {
		fields := strings.Split(sc.Text(), " ")
		if len(fields) < 10 || fields[0] != id {
			continue
		}
		sep := -1
		for i := 6; i < len(fields); i++ {
			if fields[i] == "-" {
				sep = i
				break
			}
		}
		if sep < 0 || sep+2 >= len(fields) {
			return "", "", ""
		}
		super := ""
		if sep+3 < len(fields) {
			super = fields[sep+3]
		}
		return fields[sep+1], unescapeMountField(fields[4]), super
	}
	return "", "", ""
}

// unescapeMountField undoes mountinfo's octal escapes of a space, a tab, a newline and a backslash.
func unescapeMountField(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) && isOctal(s[i+1]) && isOctal(s[i+2]) && isOctal(s[i+3]) {
			b.WriteByte((s[i+1]-'0')<<6 | (s[i+2]-'0')<<3 | (s[i+3] - '0'))
			i += 3
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func isOctal(c byte) bool { return c >= '0' && c <= '7' }

// lendFD lends f's descriptor number to call for the one call, through the File's RawConn (ADR 0023: pkg/spec takes
// the standard library's lease, never Fd()).
func lendFD(f *os.File, call func(fd int) error) error {
	rc, err := f.SyscallConn()
	if err != nil {
		return err
	}
	var cerr error
	if err := rc.Control(func(fd uintptr) { cerr = call(int(fd)) }); err != nil {
		return err
	}
	return cerr
}
