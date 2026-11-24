// SPDX-License-Identifier: Apache-2.0

package grouptrust

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"syscall"

	"github.com/attention-span-ai/tego/pkg/spec/config"
	"golang.org/x/sys/unix"
)

const accountFileLimit = 1 << 20

type groupUse struct {
	name    string
	members []string
}

// Policy holds bounded local account evidence for discovery only.
// It cannot establish exclusive kernel write authority.
type Policy struct {
	uid      uint32
	failure  string
	repair   string
	names    map[string]uint32
	accounts map[uint32]uint32
	groups   map[uint32]groupUse
}

// ForUID selects an owner while reusing the immutable local account snapshot.
// No descriptor or additional account read is retained by this projection.
func (p Policy) ForUID(uid uint32) Policy {
	p.uid = uid
	return p
}

// System reads bounded local files without invoking a name service.
func System(uid int) Policy {
	data, err := collectAccountFiles([3]string{"/etc/passwd", "/etc/group", "/etc/nsswitch.conf"})
	return accountPolicy(uid, data, err)
}

func accountPolicy(uid int, data [3][]byte, err error) Policy {
	p := Load(uid, func(path string) ([]byte, error) {
		for i, name := range []string{"/etc/passwd", "/etc/group", "/etc/nsswitch.conf"} {
			if path == name {
				return data[i], err
			}
		}
		return nil, os.ErrNotExist
	})
	if err != nil && !errors.Is(err, errAccountLimit) {
		p.repair = AccountRepair(err)
	}
	return p
}

// AccountRepair names the failed account-file check and the administrator repair.
// It is shared by discovery evidence and pre-discovery caller identification.
func AccountRepair(err error) string {
	if err == nil {
		return ""
	}
	detail := strconv.QuoteToASCII(err.Error())
	if len(detail) > 1500 {
		// Keep the account pathname at the start and the cause at the end.
		detail = detail[:1000] + "..." + detail[len(detail)-500:]
	}
	return "Ask the administrator to repair the account file and its placement: " + detail + "; use readable regular root-owned account files, root-owned placement and no group/other write bits; use shorter verified symlink paths if the link limit was reached, then run the scan again."
}

// accountObservation is one bounded read pass and its descriptor/path facts.
// Keeping the pass injectable makes timestamp collisions testable without a clock.
type accountObservation struct {
	data                     [3][]byte
	before, descriptor, path [3]os.FileInfo
}

func collectAccountFiles(paths [3]string) (data [3][]byte, err error) {
	return collectAccountFilesWith(paths, func(path string) (*config.SystemFile, error) { return config.OpenSystemFileAt("/", path, 0) })
}

// ReadAccountFileAt uses the account collector's two pinned passes for one file.
// Production uses root "/" and rootUID 0; controlled fixture roots model ownership.
func ReadAccountFileAt(root, path string, rootUID int) ([]byte, error) {
	data, err := collectAccountFilesCount([3]string{path}, func(p string) (*config.SystemFile, error) { return config.OpenSystemFileAt(root, p, rootUID) }, 1)
	return data[0], err
}

func collectAccountFilesWith(paths [3]string, open func(string) (*config.SystemFile, error)) (data [3][]byte, err error) {
	return collectAccountFilesCount(paths, open, 3)
}

func collectAccountFilesCount(paths [3]string, open func(string) (*config.SystemFile, error), count int) (data [3][]byte, err error) {
	var held []*config.SystemFile
	// Keep both passes' descriptors alive through comparison so replaced inodes
	// cannot be reused to defeat the identity comparison between fresh opens.
	defer func() {
		for _, f := range held {
			if e := f.Close(); err == nil {
				err = e
			}
		}
	}()
	return collectAccountReads(count, func(pass int, first [3][]byte) (o accountObservation, err error) {
		var files [3]*os.File
		for i, path := range paths[:count] {
			verified, e := open(path)
			err = e
			if err != nil {
				return o, fmt.Errorf("account evidence %s: %w", path, err)
			}
			held = append(held, verified)
			files[i] = verified.File

			o.before[i], err = files[i].Stat()
			if err != nil {
				return o, err
			}
			if !o.before[i].Mode().IsRegular() {
				return o, errors.New("account database is not regular")
			}
		}
		for i, f := range files[:count] {
			if pass == 0 {
				o.data[i], err = readAccountDescriptor(f)
			} else {
				err = compareAccountReader(f, first[i])
				o.data[i] = first[i]
			}
			if err != nil {
				return o, fmt.Errorf("account evidence %s: %w", paths[i], err)
			}
		}
		for _, f := range held {
			if err := f.Recheck(); err != nil {
				return o, err
			}
		}
		for i, f := range files[:count] {
			o.descriptor[i], err = f.Stat()
			if err != nil {
				return o, err
			}
			o.path[i], err = held[pass*count+i].PathInfo()
			if err != nil {
				return o, err
			}
		}
		return o, nil
	})
}

func collectAccountReads(count int, read func(int, [3][]byte) (accountObservation, error)) (data [3][]byte, err error) {
	var first accountObservation
	for pass := 0; pass < 2; pass++ {
		o, err := read(pass, first.data)
		if err != nil {
			return data, err
		}
		for i := range o.data[:count] {
			if len(o.data[i]) >= accountFileLimit {
				return data, errAccountLimit
			}
			if !sameAccountFile(o.before[i], o.descriptor[i]) || !sameAccountFile(o.before[i], o.path[i]) {
				return data, fmt.Errorf("account evidence %s: account database changed during collection", [3]string{"/etc/passwd", "/etc/group", "/etc/nsswitch.conf"}[i])
			}
			if pass == 1 && (!bytes.Equal(first.data[i], o.data[i]) || !sameAccountFile(first.before[i], o.before[i])) {
				return data, fmt.Errorf("account evidence %s: account database changed during collection", [3]string{"/etc/passwd", "/etc/group", "/etc/nsswitch.conf"}[i])
			}
		}
		if pass == 0 {
			first = o
		}
	}
	return first.data, nil
}

func sameAccountFile(a, b os.FileInfo) bool {
	x, xok := a.Sys().(*syscall.Stat_t)
	y, yok := b.Sys().(*syscall.Stat_t)
	return xok && yok && x.Dev == y.Dev && x.Ino == y.Ino && x.Size == y.Size && x.Mtim == y.Mtim && x.Ctim == y.Ctim
}

func readAccountDescriptor(f io.Reader) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(f, accountFileLimit))
	if err != nil {
		return nil, err
	}
	if len(b) >= accountFileLimit {
		return nil, errAccountLimit
	}
	return b, nil
}

// compareAccountReader retains only a fixed buffer for the second pass.
// Reading through EOF also rejects a longer or shorter file.
func compareAccountReader(r io.Reader, first []byte) error {
	r = io.LimitReader(r, accountFileLimit)
	var buffer [4096]byte
	offset := 0
	for {
		n, err := r.Read(buffer[:])
		if offset+n >= accountFileLimit {
			return errAccountLimit
		}
		if offset+n > len(first) || !bytes.Equal(buffer[:n], first[offset:offset+n]) {
			return errors.New("account database changed during collection")
		}
		offset += n
		if err == io.EOF {
			if offset != len(first) {
				return errors.New("account database changed during collection")
			}
			return nil
		}
		if err != nil {
			return err
		}
	}
}

var errAccountLimit = errors.New("account database reached size limit")

// Load parses supplied database evidence or retains a refusal reason.
// The caller supplies the evidence; System compares two fresh bounded passes.
// See the package documentation for the root-editing limits.
// Both production and fixtures enforce the byte cap.
func Load(uid int, read func(string) ([]byte, error)) Policy {
	p := Policy{uid: uint32(uid), names: map[string]uint32{}, accounts: map[uint32]uint32{}, groups: map[uint32]groupUse{}}
	data := map[string][]byte{}
	for _, path := range []string{"/etc/passwd", "/etc/group", "/etc/nsswitch.conf"} {
		b, err := read(path)
		reason := ""
		switch {
		case errors.Is(err, errAccountLimit) || len(b) >= accountFileLimit:
			reason = "accounts-limit"
		case err != nil:
			reason = "accounts-unreadable"
			if p.repair == "" {
				p.repair = AccountRepair(fmt.Errorf("account evidence %s: %w", path, err))
			}
		case len(b) == 0 || b[len(b)-1] != '\n' || bytes.IndexByte(b, 0) >= 0 || bytes.IndexByte(b, '\r') >= 0:
			reason = "accounts-malformed"
		}
		if reason != "" && p.failure == "" {
			p.failure = reason
		}
		if reason == "" {
			data[path] = b
		}
	}
	bad := func() {
		if p.failure == "" {
			p.failure = "accounts-malformed"
		}
	}
	for _, line := range strings.Split(string(data["/etc/passwd"]), "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Split(line, ":")
		if len(f) != 7 || !accountName(f[0]) {
			bad()
			continue
		}
		u, ok := accountID(f[2])
		g, gok := accountID(f[3])
		if !ok || !gok {
			bad()
			continue
		}
		if _, exists := p.names[f[0]]; exists {
			bad()
		}
		if _, exists := p.accounts[u]; exists {
			bad()
		}
		p.names[f[0]] = u
		p.accounts[u] = g
	}
	groupNames := map[string]bool{}
	for _, line := range strings.Split(string(data["/etc/group"]), "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Split(line, ":")
		if len(f) != 4 || !accountName(f[0]) {
			bad()
			continue
		}
		g, ok := accountID(f[2])
		if !ok {
			bad()
			continue
		}
		if _, exists := p.groups[g]; exists || groupNames[f[0]] {
			bad()
		}
		use := groupUse{name: f[0]}
		if f[3] != "" {
			use.members = strings.Split(f[3], ",")
			for _, member := range use.members {
				if !accountName(member) {
					bad()
				}
			}
		}
		p.groups[g] = use
		groupNames[f[0]] = true
	}
	// A dangling membership name means the local databases are inconsistent.
	for _, use := range p.groups {
		for _, member := range use.members {
			if _, ok := p.names[member]; !ok {
				bad()
			}
		}
	}
	if p.failure == "" && !localAccountsOnly(data["/etc/nsswitch.conf"]) {
		p.failure = "directory-service"
	}
	return p
}
func accountID(s string) (uint32, bool) {
	if s == "" || strings.IndexFunc(s, func(r rune) bool { return r < '0' || r > '9' }) >= 0 {
		return 0, false
	}
	n, e := strconv.ParseUint(s, 10, 32)
	return uint32(n), e == nil && n != 1<<32-1
}
func accountName(s string) bool {
	return len(s) > 0 && len(s) <= 256 && strings.IndexFunc(s, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-' || r == '.' || r == '$')
	}) < 0
}
func localAccountsOnly(data []byte) bool {
	seen := map[string]bool{}
	for _, line := range bytes.Split(data, []byte{'\n'}) {
		text := strings.SplitN(string(line), "#", 2)[0]
		key, value, ok := strings.Cut(text, ":")
		key = strings.TrimSpace(key)
		if strings.TrimSpace(text) == "" {
			continue
		}
		if !ok {
			return false
		}
		if key != "passwd" && key != "group" {
			continue
		}
		if seen[key] || strings.TrimSpace(value) != "files" {
			return false
		}
		seen[key] = true
	}
	return seen["passwd"] && seen["group"]
}

// ErrOwner rejects an inode owned by neither the selected user nor root.
var ErrOwner = errors.New("untrusted owner; use a file owned by you or root")

// ErrMode rejects writable discovery sources without complete local evidence.
var ErrMode = errors.New("untrusted write permissions")

// ModeError retains a bounded group label and a closed evidence refusal code.
type ModeError struct{ Group, Evidence, AccountRepair string }

func (e *ModeError) Error() string {
	if e.Group != "" {
		text := fmt.Sprintf("group %q: %s; chmod g-w", e.Group, e.Evidence)
		if e.AccountRepair != "" {
			text += "; " + e.AccountRepair
		}
		return text
	}
	return "world writable; chmod o-w"
}

// Unwrap exposes the stable mode refusal.
func (e *ModeError) Unwrap() error { return ErrMode }

// Refusal names an inode group even when its database entry is unavailable.
func (p Policy) Refusal(gid uint32, evidence string) *ModeError {
	name := p.groups[gid].name
	if !accountName(name) {
		name = fmt.Sprintf("gid %d", gid)
	}
	repair := ""
	if evidence == "accounts-unreadable" {
		repair = p.repair
	}
	return &ModeError{Group: name, Evidence: evidence, AccountRepair: repair}
}

// Check applies strict local discovery evidence to an inode's owner and mode.
// No group decision is needed when group write is absent.
func (p Policy) Check(mode, owner, gid uint32) error {
	if owner != 0 && owner != p.uid {
		return ErrOwner
	}
	if mode&0002 != 0 {
		return &ModeError{}
	}
	if mode&0020 == 0 {
		return nil
	}
	why := p.failure
	if why == "" {
		if p.accounts == nil {
			why = "accounts-unreadable"
		} else if _, ok := p.accounts[owner]; !ok {
			why = "owner-not-local"
		} else if _, ok := p.groups[gid]; !ok {
			why = "group-missing"
		}
	}
	if why == "" {
		for u, g := range p.accounts {
			if g == gid && u != owner {
				why = "shared-primary"
				break
			}
		}
	}
	if why == "" {
		for _, member := range p.groups[gid].members {
			u, ok := p.names[member]
			if !ok || u != owner {
				why = "other-member"
				break
			}
		}
	}
	if why != "" {
		return p.Refusal(gid, why)
	}
	return nil
}

// AccessACLAbsent interprets a size-only access-ACL query on a pinned inode.
func AccessACLAbsent(err error) bool { return err == unix.ENODATA || err == unix.EOPNOTSUPP }
