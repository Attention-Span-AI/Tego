// SPDX-License-Identifier: Apache-2.0

package grouptrust

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDiscoveryCompleteOrRefused(t *testing.T) {
	for _, tc := range []struct {
		name, path, data, reason string
		err                      error
	}{
		{name: "missing group", path: "/etc/group", data: "root:x:0:\n", reason: "group-missing"},
		{name: "read failure", path: "/etc/passwd", err: os.ErrPermission, reason: "accounts-unreadable"},
		{name: "at limit", path: "/etc/passwd", data: strings.Repeat("x", accountFileLimit), reason: "accounts-limit"},
		{name: "overflow", path: "/etc/passwd", data: strings.Repeat("x", accountFileLimit+1), reason: "accounts-limit"},
		{name: "truncated", path: "/etc/passwd", data: "person:x:1000:1000::/:/bin/sh", reason: "accounts-malformed"},
		{name: "malformed", path: "/etc/passwd", data: "bad\n", reason: "accounts-malformed"},
		{name: "duplicate uid", path: "/etc/passwd", data: "person:x:1000:1000::/:/bin/sh\nalias:x:1000:1001::/:/bin/sh\n", reason: "accounts-malformed"},
		{name: "directory service", path: "/etc/nsswitch.conf", data: "passwd: files sss\ngroup: files sss\n", reason: "directory-service"},
		{name: "directory only owner", path: "/etc/passwd", data: "root:x:0:0::/:/bin/sh\n", reason: "owner-not-local"},
		{name: "shared primary", path: "/etc/passwd", data: "person:x:1000:1000::/:/bin/sh\nother:x:1001:1000::/:/bin/sh\n", reason: "shared-primary"},
		{name: "explicit member", path: "/etc/group", data: "person:x:1000:person,other\n", reason: "other-member"},
		{name: "root is another member", path: "/etc/group", data: "person:x:1000:person,root\n", reason: "other-member"},
		{name: "unknown member in another group", path: "/etc/group", data: "person:x:1000:person\nunrelated:x:2000:missing\n", reason: "accounts-malformed"},
		{name: "duplicate group", path: "/etc/group", data: "person:x:1000:person\nalias:x:1000:\n", reason: "accounts-malformed"},
		{name: "compat", path: "/etc/passwd", data: "+::::::\n", reason: "accounts-malformed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			read := func(path string) ([]byte, error) {
				if path == tc.path {
					return []byte(tc.data), tc.err
				}
				switch path {
				case "/etc/passwd":
					return []byte("root:x:0:0::/:/bin/sh\nperson:x:1000:1000::/:/bin/sh\nother:x:1001:1001::/:/bin/sh\n"), nil
				case "/etc/group":
					return []byte("root:x:0:\nperson:x:1000:\n"), nil
				default:
					return []byte("passwd: files\ngroup: files\n"), nil
				}
			}
			p := Load(1000, read)
			var mode *ModeError
			if err := p.Check(0664, 1000, 1000); !errors.As(err, &mode) || mode.Evidence != tc.reason {
				t.Fatalf("incomplete evidence accepted: %v", err)
			}
		})
	}
}

func TestReadAccountFileCap(t *testing.T) {
	for _, size := range []int{accountFileLimit - 1, accountFileLimit, accountFileLimit + 1} {
		path := filepath.Join(t.TempDir(), "passwd")
		if e := os.WriteFile(path, []byte(strings.Repeat("x", size)), 0600); e != nil {
			t.Fatal(e)
		}
		b, e := readAccountFile(path)
		if size < accountFileLimit {
			if e != nil || len(b) != size {
				t.Fatalf("below cap: %d %v", len(b), e)
			}
		} else if !errors.Is(e, errAccountLimit) {
			t.Fatalf("size %d: %v", size, e)
		}
	}
}
func TestDiscoveryOwnerAndInodeFacts(t *testing.T) {
	p := Load(1000, func(path string) ([]byte, error) {
		switch path {
		case "/etc/passwd":
			return []byte("root:x:0:0::/:/bin/sh\nperson:x:1000:1000::/:/bin/sh\nother:x:1001:1001::/:/bin/sh\n"), nil
		case "/etc/group":
			return []byte("root:x:0:root\nperson:x:1000:person\nempty:x:2000:\n"), nil
		default:
			return []byte("passwd: files\ngroup: files\n"), nil
		}
	})
	for _, tc := range []struct {
		name             string
		mode, owner, gid uint32
		want             bool
	}{
		{"private file", 0664, 1000, 1000, true}, {"private directory", 0775, 1000, 1000, true},
		{"root vendor", 0664, 0, 0, true}, {"root file user member", 0664, 0, 1000, false},
		{"world", 0666, 1000, 1000, false}, {"foreign", 0644, 1001, 1000, false},
		{"unused group", 0664, 1000, 2000, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if e := p.Check(tc.mode, tc.owner, tc.gid); (e == nil) != tc.want {
				t.Fatalf("Check: %v", e)
			}
		})
	}
}

func TestDiscoveryEveryDatabaseComplete(t *testing.T) {
	for _, path := range []string{"/etc/passwd", "/etc/group", "/etc/nsswitch.conf"} {
		for _, kind := range []string{"failed", "truncated", "limit"} {
			t.Run(path+"/"+kind, func(t *testing.T) {
				p := Load(1000, func(name string) ([]byte, error) {
					if name == path {
						switch kind {
						case "failed":
							return nil, os.ErrPermission
						case "truncated":
							return []byte("incomplete"), nil
						default:
							return []byte(strings.Repeat("x", accountFileLimit)), nil
						}
					}
					switch name {
					case "/etc/passwd":
						return []byte("person:x:1000:1000::/:/bin/sh\n"), nil
					case "/etc/group":
						return []byte("person:x:1000:person\n"), nil
					default:
						return []byte("passwd: files\ngroup: files\n"), nil
					}
				})
				var mode *ModeError
				if e := p.Check(0664, 1000, 1000); !errors.As(e, &mode) {
					t.Fatalf("incomplete %s %s: %v", path, kind, e)
				}
			})
		}
	}
}

// Reads at the cap refuse too: a full buffer is not evidence of completeness.
func readAccountFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	b, err := readAccountDescriptor(f)
	closeErr := f.Close()
	if err != nil {
		return nil, err
	}
	if closeErr != nil {
		return nil, closeErr
	}
	if len(b) >= accountFileLimit {
		return nil, errAccountLimit
	}
	return b, nil
}
