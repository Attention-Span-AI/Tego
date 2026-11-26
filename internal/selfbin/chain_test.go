// SPDX-License-Identifier: Apache-2.0

package selfbin

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

type chainNode struct {
	path     string
	uid, gid uint32
	mode     os.FileMode
}
type chainInfo struct{ chainNode }

func (i chainInfo) Name() string       { return filepath.Base(i.path) }
func (i chainInfo) Size() int64        { return 0 }
func (i chainInfo) Mode() os.FileMode  { return i.mode }
func (i chainInfo) ModTime() time.Time { return time.Time{} }
func (i chainInfo) IsDir() bool        { return i.mode.IsDir() }
func (i chainInfo) Sys() any           { return &syscall.Stat_t{Uid: i.uid, Gid: i.gid} }

// Each row gives the resolved chain's owner, group and mode without chown,
// distro access, or running a Tego binary. The Arch row checks link resolution too.
func TestTrustedChainDefaultInstallLayouts(t *testing.T) {
	const uid, gid = 1000, 1000
	dir := func(p string, u, g uint32, m os.FileMode) chainNode { return chainNode{p, u, g, m | os.ModeDir} }
	root := dir("/", 0, 0, 0755)
	home := func(m os.FileMode) []chainNode {
		return []chainNode{root, dir("/home", 0, 0, 0755), dir("/home/person", uid, gid, m), dir("/home/person/.local", uid, gid, 0775), dir("/home/person/.local/bin", uid, gid, 0775), {"/home/person/.local/bin/tego", uid, gid, 0755}}
	}
	local := func(g uint32, m os.FileMode) []chainNode {
		return []chainNode{root, dir("/usr", 0, 0, 0755), dir("/usr/local", 0, 0, 0755), dir("/usr/local/bin", 0, g, m), {"/usr/local/bin/tego", 0, g, 0755}}
	}
	usr := []chainNode{root, dir("/usr", 0, 0, 0755), dir("/usr/bin", 0, 0, 0755), {"/usr/bin/tego", 0, 0, 0755}}
	for _, tc := range []struct {
		name          string
		nodes         []chainNode
		passwd, group string
		want          bool
	}{
		{"ubuntu 24.04 home 0750", home(0750), "person:x:1000:1000::/:/bin/sh\n", "person:x:1000:\n", true},
		{"fedora 44 home 0700", home(0700), "person:x:1000:1000::/:/bin/sh\n", "person:x:1000:person\n", true},
		{"almalinux 9.8 home 0755", home(0755), "person:x:1000:1000::/:/bin/sh\n", "person:x:1000:\n", true},
		{"usr local root", local(0, 0755), "", "root:x:0:\n", true},
		{"debian 13 empty staff", local(50, 0775|os.ModeSetgid), "", "staff:x:50:\n", true},
		{"usr bin", usr, "", "", true},
		{"arch bin symlink", usr, "", "", true},
		{"nix store", []chainNode{root, dir("/nix", 0, 0, 0755), dir("/nix/store", 0, 30000, 0775|os.ModeSticky), dir("/nix/store/hash-tego", 0, 0, 0555), dir("/nix/store/hash-tego/bin", 0, 0, 0555), {"/nix/store/hash-tego/bin/tego", 0, 0, 0555}}, "", "", true},
		{"debian staff another member", local(50, 0775|os.ModeSetgid), "person:x:1000:1000::/:/bin/sh\nother:x:1001:1001::/:/bin/sh\n", "staff:x:50:other\n", false},
		{"shared primary group", home(0750), "person:x:1000:1000::/:/bin/sh\nother:x:1001:1000::/:/bin/sh\n", "person:x:1000:\n", false},
		{"shared group two members", home(0750), "person:x:1000:1000::/:/bin/sh\nother:x:1001:1001::/:/bin/sh\n", "person:x:1000:person,other\n", false},
		{"world writable no sticky", []chainNode{root, dir("/shared", 0, 0, 0777), {"/shared/tego", uid, gid, 0755}}, "", "", false},
		{"sticky foreign child", []chainNode{root, dir("/shared", 0, 0, 0777|os.ModeSticky), dir("/shared/other", 1001, 1001, 0755), {"/shared/other/tego", uid, gid, 0755}}, "", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			policy := fixtureGroups(tc.passwd, tc.group, "passwd: files\ngroup: files\n", uid, gid)
			nodes := map[string]os.FileInfo{}
			for _, n := range tc.nodes {
				nodes[n.path] = chainInfo{n}
			}
			path := tc.nodes[len(tc.nodes)-1].path
			if tc.name == "arch bin symlink" {
				temp := t.TempDir()
				script(t, filepath.Join(temp, "usr/bin/tego"))
				if err := os.Symlink("usr/bin", filepath.Join(temp, "bin")); err != nil {
					t.Fatal(err)
				}
				resolved, err := filepath.EvalSymlinks(filepath.Join(temp, "bin/tego"))
				if err != nil {
					t.Fatal(err)
				}
				path = strings.TrimPrefix(resolved, temp)
			}
			stat := func(p string) (os.FileInfo, error) {
				if n, ok := nodes[p]; ok {
					return n, nil
				}
				return nil, os.ErrNotExist
			}
			if got := trustedChainWithGroups(path, uid, stat, policy, func(string) bool { return true }); got != tc.want {
				t.Fatalf("trusted=%v want=%v", got, tc.want)
			}
		})
	}
}

func fixtureGroups(passwd, group, nss string, uid, _ uint32) groupTrust {
	return loadGroupTrust(int(uid), func(p string) ([]byte, error) {
		switch p {
		case "/etc/passwd":
			return []byte("root:x:0:0::/:/bin/sh\n" + passwd), nil
		case "/etc/group":
			return []byte(group), nil
		case "/etc/nsswitch.conf":
			return []byte(nss), nil
		case "/etc/gshadow":
			// A normal user cannot read the shadow group file.
			return nil, os.ErrPermission
		}
		return nil, os.ErrNotExist
	})
}

// A group password admits accounts that no file lists (newgrp), so a folder that group can write is not private to
// the listed members. The shadow group file is preferred by newgrp and is readable by root alone: a normal user's
// view of a group marked "x" is the recorded residual (ADR 0142, 2026-11-18, group passwords).
func TestGroupPasswordRefusesTheWritableGroupException(t *testing.T) {
	const (
		hash      = "$6$fixture$0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ./0123456789abcdefghijklmn"
		des       = "abJnggxhB/yWI"
		inGroup   = "the group can be joined with a password (set in /etc/group)"
		inShadow  = "the group can be joined with a password (set in /etc/gshadow)"
		malformed = "/etc/gshadow is malformed"
	)
	closed := func() ([]byte, error) { return nil, os.ErrPermission }
	absent := func() ([]byte, error) { return nil, os.ErrNotExist }
	shadow := func(text string) func() ([]byte, error) {
		return func() ([]byte, error) { return []byte(text), nil }
	}
	dir := func(p string, u, g uint32, m os.FileMode) chainNode { return chainNode{p, u, g, m | os.ModeDir} }
	staff := []chainNode{dir("/", 0, 0, 0755), dir("/usr", 0, 0, 0755), dir("/usr/local", 0, 0, 0755), dir("/usr/local/bin", 0, 50, 0775|os.ModeSetgid), {"/usr/local/bin/tego", 0, 50, 0755}}
	home := []chainNode{dir("/", 0, 0, 0755), dir("/home", 0, 0, 0755), dir("/home/person", 1000, 1000, 0750), dir("/home/person/.local", 1000, 1000, 0775), dir("/home/person/.local/bin", 1000, 1000, 0775), {"/home/person/.local/bin/tego", 1000, 1000, 0755}}
	for _, tc := range []struct {
		name    string
		nodes   []chainNode
		group   string
		gshadow func() ([]byte, error)
		want    string // "" accepts; otherwise the refusal holds this text
	}{
		{"hash in the group file", staff, "staff:" + hash + ":50:\n", closed, inGroup},
		{"des hash in the group file", staff, "staff:" + des + ":50:\n", closed, inGroup},
		{"hash on the primary group", home, "person:" + hash + ":1000:\n", closed, inGroup},
		{"x with a readable shadow hash", staff, "staff:x:50:\n", shadow("staff:" + hash + "::\n"), inShadow},
		{"x on the primary group with a readable shadow hash", home, "person:x:1000:\n", shadow("person:" + hash + "::\n"), inShadow},
		{"locked group field with a readable shadow hash", staff, "staff:*:50:\n", shadow("staff:" + hash + "::\n"), inShadow},
		{"x with a locked shadow entry", staff, "staff:x:50:\n", shadow("staff:!::\n"), ""},
		{"x with a starred shadow entry", staff, "staff:x:50:\n", shadow("root:*::\nstaff:*::\n"), ""},
		{"x with a locked shadow hash", staff, "staff:x:50:\n", shadow("staff:!" + hash + "::\n"), ""},
		{"x with an empty shadow entry", staff, "staff:x:50:\n", shadow("staff:::\n"), ""},
		{"x with no shadow entry", staff, "staff:x:50:\n", shadow("root:*::\n"), ""},
		{"x with an unreadable shadow file", staff, "staff:x:50:\n", closed, ""},
		{"x on the primary group with an unreadable shadow file", home, "person:x:1000:\n", closed, ""},
		{"x with no shadow file", staff, "staff:x:50:\n", absent, ""},
		{"empty group field", staff, "staff::50:\n", closed, ""},
		{"starred group field", staff, "staff:*:50:\n", closed, ""},
		{"locked group field", staff, "staff:!:50:\n", closed, ""},
		{"locked hash in the group file", staff, "staff:!" + hash + ":50:\n", closed, ""},
		{"shadow entry lists another member", staff, "staff:x:50:\n", shadow("staff:*::other\n"), Untrusted},
		{"shadow entry lists another administrator", staff, "staff:x:50:\n", shadow("staff:*:other:\n"), Untrusted},
		{"shadow entry lists an unknown member", staff, "staff:x:50:\n", shadow("staff:*::directoryuser\n"), Untrusted},
		{"shadow entry lists only the person on the private group", home, "person:x:1000:\n", shadow("person:!::person\n"), ""},
		{"readable shadow file with a short record", staff, "staff:x:50:\n", shadow("staff:*\n"), malformed},
		{"readable shadow file with a repeated record", staff, "staff:x:50:\n", shadow("staff:*::\nstaff:" + hash + "::\n"), malformed},
		{"readable shadow file cut short", staff, "staff:x:50:\n", shadow("staff:*::"), "/etc/gshadow is truncated (no final newline)"},
		{"shadow file read fails", staff, "staff:x:50:\n", func() ([]byte, error) { return nil, syscall.EIO }, "/etc/gshadow could not be read"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			policy := loadGroupTrust(1000, func(p string) ([]byte, error) {
				switch p {
				case "/etc/passwd":
					return []byte("root:x:0:0::/:/bin/sh\nperson:x:1000:1000::/:/bin/sh\nother:x:1001:1001::/:/bin/sh\n"), nil
				case "/etc/group":
					return []byte(tc.group), nil
				case "/etc/nsswitch.conf":
					return []byte("passwd: files\ngroup: files\n"), nil
				case "/etc/gshadow":
					return tc.gshadow()
				}
				return nil, os.ErrNotExist
			})
			nodes := map[string]os.FileInfo{}
			for _, n := range tc.nodes {
				nodes[n.path] = chainInfo{n}
			}
			stat := func(p string) (os.FileInfo, error) {
				if n, ok := nodes[p]; ok {
					return n, nil
				}
				return nil, os.ErrNotExist
			}
			got := chainRefusal(tc.nodes[len(tc.nodes)-1].path, 1000, stat, func() groupTrust { return policy }, func(string) bool { return true })
			if tc.want == "" {
				if got != "" {
					t.Fatalf("refused %q, want the writable-group exception kept", got)
				}
				return
			}
			if !strings.Contains(got, tc.want) {
				t.Fatalf("got %q, want a refusal holding %q", got, tc.want)
			}
			if tc.want != Untrusted {
				folder := tc.nodes[len(tc.nodes)-2].path
				// Every group-writable folder of the chain is named, the innermost last, in the one chmod.
				for _, part := range []string{"no command is shown", "chmod g-w ", folder + ", then run this step again"} {
					if !strings.Contains(got, part) {
						t.Errorf("refusal %q lacks %q", got, part)
					}
				}
			}
		})
	}
}

func TestTrustedChainHostLocalBin(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	path, err := filepath.EvalSymlinks(filepath.Join(home, ".local/bin"))
	if err != nil {
		t.Logf("host local bin unavailable: %v", err)
		return
	}
	// Reuse the exact production walk, starting with the directory's metadata.
	// Its synthetic first regular file introduces no write and reads no executable.
	target := filepath.Join(path, ".read-only-trust-check")
	stat := func(p string) (os.FileInfo, error) {
		if p == target {
			return chainInfo{chainNode{p, uint32(os.Geteuid()), uint32(os.Getegid()), 0755}}, nil
		}
		return os.Lstat(p)
	}
	got := trustedChain(target, os.Geteuid(), stat)
	t.Logf("host chain %s trusted=%v (metadata and account reads only)", path, got)
}

func TestGroupTrustMembership(t *testing.T) {
	for _, tc := range []struct {
		name, passwd, group, nss string
		gid                      uint32
		want                     bool
	}{
		{"private", "person:x:1000:1000::/:/bin/sh\n", "person:x:1000:\n", "passwd: files\ngroup: files\n", 1000, true},
		{"root member trusted", "person:x:1000:1000::/:/bin/sh\n", "person:x:1000:root,person\n", "passwd: files\ngroup: files\n", 1000, true},
		{"empty", "", "staff:x:50:\n", "passwd: files\ngroup: files\n", 50, true},
		{"staff primary", "other:x:1001:50::/:/bin/sh\n", "staff:x:50:\n", "passwd: files\ngroup: files\n", 50, false},
		{"staff owner member", "person:x:1000:1000::/:/bin/sh\n", "staff:x:50:person\n", "passwd: files\ngroup: files\n", 50, false},
		{"nss own refused", "", "", "passwd: files sss\ngroup: files sss\n", 1000, false},
		{"nss empty refused", "", "staff:x:50:\n", "passwd: files sss\ngroup: files sss\n", 50, false},
		{"nss known sharing", "other:x:1001:1000::/:/bin/sh\n", "person:x:1000:\n", "passwd: files sss\ngroup: files sss\n", 1000, false},
		{"missing group known primary sharing", "other:x:1001:1000::/:/bin/sh\n", "", "", 1000, false},
		{"unknown member", "", "person:x:1000:directoryuser\n", "", 1000, false},
		{"duplicate group reveals member", "other:x:1001:1001::/:/bin/sh\n", "person:x:1000:\nalias:x:1000:other\n", "", 1000, false},
		{"compat entry empty refused", "+::::::\n", "staff:x:50:\n", "passwd: files\ngroup: files\n", 50, false},
		{"malformed empty refused", "bad\n", "staff:x:50:\n", "passwd: files\ngroup: files\n", 50, false},
		{"missing nss own refused", "", "", "", 1000, false},
		{"missing nss empty refused", "", "staff:x:50:\n", "", 50, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := fixtureGroups(tc.passwd, tc.group, tc.nss, 1000, 1000)
			if got := p.allows(tc.gid); got != tc.want {
				t.Fatalf("allows(%d)=%v want %v", tc.gid, got, tc.want)
			}
		})
	}
	for _, missing := range []string{"/etc/passwd", "/etc/group", "/etc/nsswitch.conf"} {
		t.Run("unreadable "+missing, func(t *testing.T) {
			p := loadGroupTrust(1000, func(path string) ([]byte, error) {
				if path == missing {
					return nil, os.ErrPermission
				}
				switch path {
				case "/etc/passwd":
					return []byte("other:x:1001:1000::/:/bin/sh\n"), nil
				case "/etc/group":
					return []byte("person:x:1000:other\nstaff:x:50:\n"), nil
				case "/etc/gshadow":
					return nil, os.ErrPermission // a normal user cannot read it
				default:
					return []byte("passwd: files\ngroup: files\n"), nil
				}
			})
			if p.allows(1000) || p.allows(50) {
				t.Fatal("unreadable database bypassed known sharing or accepted empty group")
			}
		})
	}
	t.Run("unreadable passwd own explicit member", func(t *testing.T) {
		p := loadGroupTrust(1000, func(path string) ([]byte, error) {
			if path == "/etc/passwd" {
				return nil, os.ErrPermission
			}
			if path == "/etc/group" {
				return []byte("person:x:1000:person\n"), nil
			}
			if path == "/etc/gshadow" {
				return nil, os.ErrPermission
			}
			return []byte("passwd: files\ngroup: files\n"), nil
		})
		if p.allows(1000) {
			t.Fatal("unreadable passwd allowed an unknown primary group")
		}
	})
	p := loadGroupTrust(1000, func(string) ([]byte, error) { return nil, os.ErrPermission })
	if p.allows(1000) || p.allows(50) {
		t.Fatal("unreadable databases must refuse unknown group membership")
	}
}

func TestReadAccountFileBound(t *testing.T) {
	for _, size := range []int{accountFileLimit, accountFileLimit + 1} {
		path := filepath.Join(t.TempDir(), "accounts")
		if err := os.WriteFile(path, []byte(strings.Repeat("x", size)), 0600); err != nil {
			t.Fatal(err)
		}
		got, err := readAccountFile(path)
		if size == accountFileLimit {
			if err != nil || len(got) != size {
				t.Fatalf("at limit: len %d err %v", len(got), err)
			}
		} else if err == nil {
			t.Fatal("accepted oversized database")
		}
	}
}

func TestTrustedChainRefusesAccessACL(t *testing.T) {
	nodes := map[string]os.FileInfo{
		"/":         chainInfo{chainNode{"/", 0, 0, 0755 | os.ModeDir}},
		"/bin":      chainInfo{chainNode{"/bin", 1000, 1000, 0775 | os.ModeDir}},
		"/bin/tego": chainInfo{chainNode{"/bin/tego", 1000, 1000, 0755}},
	}
	stat := func(p string) (os.FileInfo, error) { return nodes[p], nil }
	if trustedChainWithGroups("/bin/tego", 1000, stat, groupTrust{primary: 1000, primaryOK: true}, func(string) bool { return false }) {
		t.Fatal("private gid concealed named-user ACL or unreadable ACL metadata")
	}
}

func TestNoAccessACL(t *testing.T) {
	dir := t.TempDir()
	if !noAccessACL(dir) {
		t.Fatal("ordinary directory has unavailable access ACL metadata")
	}
	// Linux access ACL with a named foreign writer; no root or second account is needed.
	acl := make([]byte, 4+5*8)
	binary.LittleEndian.PutUint32(acl, 2)
	for i, e := range []struct {
		tag, perm uint16
		id        uint32
	}{{1, 7, ^uint32(0)}, {2, 2, uint32(os.Geteuid()) + 10001}, {4, 5, ^uint32(0)}, {16, 7, ^uint32(0)}, {32, 5, ^uint32(0)}} {
		at := 4 + i*8
		binary.LittleEndian.PutUint16(acl[at:], e.tag)
		binary.LittleEndian.PutUint16(acl[at+2:], e.perm)
		binary.LittleEndian.PutUint32(acl[at+4:], e.id)
	}
	if err := unix.Setxattr(dir, "system.posix_acl_access", acl, 0); err == unix.EOPNOTSUPP {
		t.Log("filesystem has no POSIX ACL support; injected refusal is covered separately")
		return
	} else if err != nil {
		t.Fatal(err)
	}
	if noAccessACL(dir) {
		t.Fatal("named-user ACL writer accepted as a private group")
	}
	if noAccessACL(filepath.Join(dir, "missing")) {
		t.Fatal("failed ACL lookup accepted")
	}
}

// An injected directory source knows a second primary-gid principal that the local
// files do not list. Printing a privileged command cannot rely on the primary gid.
func TestDirectoryOnlyPrincipalCannotReplacePrintedCommand(t *testing.T) {
	// What the directory service knows and no local file lists: a second account whose primary gid is the person's.
	directory := map[string]struct{ name, gid string }{
		"1000": {"person", "1000"},
		"1001": {"directory-person", "1000"},
	}
	if directory["1001"].gid != directory["1000"].gid {
		t.Fatal("fixture has no shared primary gid")
	}
	// The directory is never asked: sources other than files refuse by being named in nsswitch.conf.
	p := loadGroupTrust(1000, func(path string) ([]byte, error) {
		switch path {
		case "/etc/passwd":
			return []byte("person:x:1000:1000::/home/person:/bin/sh\n"), nil
		case "/etc/group":
			return []byte("person:x:1000:\n"), nil
		case "/etc/gshadow":
			return nil, os.ErrPermission // a normal user cannot read it
		default:
			return []byte("passwd: files sss\ngroup: files sss\n"), nil
		}
	})
	if p.allows(1000) {
		t.Fatal("printed root command trusts a group shared only through the directory source")
	}
}

func TestIncompletePrimaryGroupEvidenceRefuses(t *testing.T) {
	for _, tc := range []struct {
		name, path, text string
		err              error
	}{
		{"failed", "/etc/passwd", "", os.ErrPermission},
		{"truncated passwd", "/etc/passwd", "person:x:1000:1000::/:/bin/sh", nil},
		{"truncated group", "/etc/group", "person:x:1000:", nil},
		{"oversized", "/etc/passwd", strings.Repeat("x", accountFileLimit+1), nil},
		{"malformed", "/etc/passwd", "broken\n", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := loadGroupTrust(1000, func(path string) ([]byte, error) {
				if path == tc.path {
					return []byte(tc.text), tc.err
				}
				switch path {
				case "/etc/passwd":
					return []byte("person:x:1000:1000::/:/bin/sh\n"), nil
				case "/etc/group":
					return []byte("person:x:1000:\n"), nil
				case "/etc/gshadow":
					return nil, os.ErrPermission // a normal user cannot read it
				default:
					return []byte("passwd: files\ngroup: files\n"), nil
				}
			})
			if p.allows(1000) {
				t.Fatal("incomplete membership accepted for a printed privileged command")
			}
		})
	}
}

func BenchmarkPrintedCommandMembership(b *testing.B) {
	for _, slow := range []bool{false, true} {
		name := "files-only"
		if slow {
			name = "injected-2ms-passwd-read"
		}
		b.Run(name, func(b *testing.B) {
			for b.Loop() {
				p := loadGroupTrust(1000, func(path string) ([]byte, error) {
					if slow && path == "/etc/passwd" {
						time.Sleep(2 * time.Millisecond)
					}
					switch path {
					case "/etc/passwd":
						return []byte("person:x:1000:1000::/:/bin/sh\n"), nil
					case "/etc/group":
						return []byte("person:x:1000:\n"), nil
					case "/etc/gshadow":
						return nil, os.ErrPermission // a normal user cannot read it
					default:
						return []byte("passwd: files\ngroup: files\n"), nil
					}
				})
				if !p.allows(1000) {
					b.Fatal("complete private group refused")
				}
			}
		})
	}
}

func TestPrintedGroupRepairNamesTheDependency(t *testing.T) {
	p := fixtureGroups("person:x:1000:1000::/:/bin/sh\n", "person:x:1000:\n", "passwd: files sss\ngroup: files sss\n", 1000, 1000)
	nodes := map[string]os.FileInfo{
		"/":                    chainInfo{chainNode{"/", 0, 0, 0755 | os.ModeDir}},
		"/private folder":      chainInfo{chainNode{"/private folder", 1000, 1000, 0775 | os.ModeDir}},
		"/private folder/tego": chainInfo{chainNode{"/private folder/tego", 1000, 1000, 0755}},
	}
	why := chainRefusal("/private folder/tego", 1000, func(path string) (os.FileInfo, error) { return nodes[path], nil }, func() groupTrust { return p }, func(string) bool { return true })
	for _, want := range []string{"group person (gid 1000)", "folder '/private folder'", "passwd: files sss", "group: files sss", "no command is shown", "chmod g-w '/private folder'", "run this step again"} {
		if !strings.Contains(why, want) {
			t.Errorf("reason %q lacks %q", why, want)
		}
	}
}

// A source of account evidence that never answers cannot hold a printed command (review finding 5): the lookup is
// given up after accountEvidenceWait and the refusal names the file that gave no answer, and a path with no
// group-writable folder asks for no evidence at all. No name service is asked in either case: the caller's primary
// group comes from its passwd record.
func TestAccountEvidenceWaitIsBounded(t *testing.T) {
	never := make(chan struct{})
	var asked atomic.Int32
	oldRead, oldWait := accountRead, accountEvidenceWait
	accountRead = func(string) ([]byte, error) {
		asked.Add(1)
		<-never
		return nil, os.ErrClosed
	}
	accountEvidenceWait = 200 * time.Millisecond
	t.Cleanup(func() {
		close(never)
		accountRead, accountEvidenceWait = oldRead, oldWait
	})
	bin, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	bin = filepath.Join(bin, "tego")
	script(t, bin)
	// The real chain, shown as this user's with no group or world write, save the one folder named.
	chain := func(groupWritable string) func(string) (os.FileInfo, error) {
		return func(p string) (os.FileInfo, error) {
			info, err := os.Lstat(p)
			if err != nil {
				return nil, err
			}
			mode := info.Mode()&os.ModeType | 0755
			if p == groupWritable {
				mode |= 0020
			}
			return chainInfo{chainNode{p, uint32(os.Geteuid()), uint32(os.Getegid()), mode}}, nil
		}
	}
	self := func() (string, error) { return bin, nil }

	start := time.Now()
	word, why := namedPath(self, bin, chain(""))
	if took := time.Since(start); why != "" || word == "" || asked.Load() != 0 || took >= accountEvidenceWait {
		t.Fatalf("no group-writable folder: word %q, reason %q, %d account reads, %s; want the command at once and no read", word, why, asked.Load(), took)
	}

	start = time.Now()
	word, why = namedPath(self, bin, chain(filepath.Dir(bin)))
	took := time.Since(start)
	if took > accountEvidenceWait+2*time.Second {
		t.Fatalf("the refusal took %s, past the %s deadline", took, accountEvidenceWait)
	}
	if word != "" {
		t.Fatalf("a command was shown on evidence that never arrived: %q", word)
	}
	for _, want := range []string{"/etc/passwd could not be read: it gave no answer within 200ms", "no command is shown", "chmod g-w " + filepath.Dir(bin)} {
		if !strings.Contains(why, want) {
			t.Errorf("refusal %q lacks %q", why, want)
		}
	}
}

// Public issue 87. The installer made ~/.local and ~/.local/bin under the login umask 0002, both group-writable, and
// the refusal named one folder at a time: a person who ran its chmod met the next folder's refusal. One message names
// every folder whose membership cannot be established, with one command that cures them all, and still shows no sudo
// command until they are cured.
func TestOneRefusalNamesEveryFolderAndOneChmodCuresThem(t *testing.T) {
	const uid, gid = 1000, 1000
	dir := func(p string, g uint32, m os.FileMode) chainNode { return chainNode{p, uid, g, m | os.ModeDir} }
	root := chainNode{"/", 0, 0, 0755 | os.ModeDir}
	chain := func(local, bin os.FileMode) []chainNode {
		return []chainNode{root, {"/home", 0, 0, 0755 | os.ModeDir}, dir("/home/tego", gid, 0750), dir("/home/tego/.local", gid, local),
			dir("/home/tego/.local/bin", gid, bin), {"/home/tego/.local/bin/tego", uid, gid, 0755}}
	}
	const (
		ubuntuNSS = "passwd: files systemd\ngroup: files systemd\n"
		why       = "/etc/nsswitch.conf does not establish files-only passwd and group membership (passwd: files systemd; group: files systemd)"
	)
	refuse := func(t *testing.T, nodes []chainNode, nss string) string {
		t.Helper()
		policy := fixtureGroups("tego:x:1000:1000::/:/bin/sh\n", "tego:x:1000:\n", nss, uid, gid)
		byPath := map[string]os.FileInfo{}
		for _, n := range nodes {
			byPath[n.path] = chainInfo{n}
		}
		stat := func(p string) (os.FileInfo, error) {
			if n, ok := byPath[p]; ok {
				return n, nil
			}
			return nil, os.ErrNotExist
		}
		return chainRefusal(nodes[len(nodes)-1].path, uid, stat, func() groupTrust { return policy }, func(string) bool { return true })
	}
	t.Run("two folders, one message, one command", func(t *testing.T) {
		want := "cannot establish membership of group tego (gid 1000) for folders /home/tego/.local and /home/tego/.local/bin: " + why +
			"; no command is shown; run chmod g-w /home/tego/.local /home/tego/.local/bin, then run this step again."
		if got := refuse(t, chain(0775, 0775), ubuntuNSS); got != want {
			t.Fatalf("got  %q\nwant %q", got, want)
		}
	})
	t.Run("one folder reads as it always did", func(t *testing.T) {
		want := "cannot establish membership of group tego (gid 1000) for folder /home/tego/.local/bin: " + why +
			"; no command is shown; run chmod g-w /home/tego/.local/bin, then run this step again."
		if got := refuse(t, chain(0755, 0775), ubuntuNSS); got != want {
			t.Fatalf("got  %q\nwant %q", got, want)
		}
	})
	t.Run("none: the command is shown", func(t *testing.T) {
		if got := refuse(t, chain(0755, 0755), ubuntuNSS); got != "" {
			t.Fatalf("refused %q", got)
		}
		// Files-only sources establish the private group, however many folders it can write (Debian).
		if got := refuse(t, chain(0775, 0775), "passwd: files\ngroup: files\n"); got != "" {
			t.Fatalf("refused %q where the private group is established", got)
		}
	})
	t.Run("a refusal chmod cannot cure is not hidden behind the folders", func(t *testing.T) {
		nodes := chain(0775, 0775)
		nodes[1] = chainNode{"/home", 0, 0, 0777 | os.ModeDir} // world-writable, not sticky
		if got := refuse(t, nodes, ubuntuNSS); got != Untrusted {
			t.Fatalf("got %q, want %q", got, Untrusted)
		}
	})
	t.Run("folders of two groups name each group", func(t *testing.T) {
		nodes := chain(0775, 0775)
		nodes[4] = dir("/home/tego/.local/bin", 1000, 0775)
		nodes[3] = chainNode{"/home/tego/.local", uid, 1001, 0775 | os.ModeDir}
		got := refuse(t, nodes, ubuntuNSS)
		for _, part := range []string{"group unknown (gid 1001) for folder /home/tego/.local", "group tego (gid 1000) for folder /home/tego/.local/bin",
			"run chmod g-w /home/tego/.local /home/tego/.local/bin, then run this step again."} {
			if !strings.Contains(got, part) {
				t.Errorf("refusal %q lacks %q", got, part)
			}
		}
	})
}
