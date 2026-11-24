// SPDX-License-Identifier: Apache-2.0

package scan

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/attention-span-ai/tego/internal/platform/sys"
)

func TestNonDiscoveryGroupWriteRefused(t *testing.T) {
	uid, gid := uint32(os.Getuid()), uint32(os.Getgid())
	ctx := fixtureModePolicy(t, uid, gid, false, false)
	for _, name := range []string{"passwd", "boot", "events", "lock", "run-directory"} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			const id = "r-0123abcd-0000000000000-abcdef"
			dir := filepath.Join(root, id)
			if e := os.Mkdir(dir, 0700); e != nil {
				t.Fatal(e)
			}
			for _, n := range []string{"passwd", "boot", id + "/events.jsonl", id + "/lock"} {
				if e := os.WriteFile(filepath.Join(root, n), []byte("{}\n"), 0600); e != nil {
					t.Fatal(e)
				}
			}
			path := filepath.Join(root, name)
			switch name {
			case "events":
				path = filepath.Join(dir, "events.jsonl")
			case "lock":
				path = filepath.Join(dir, "lock")
			case "run-directory":
				path = dir
			}
			mode := os.FileMode(0664)
			if name == "run-directory" {
				mode = 0775
			}
			if e := os.Chmod(path, mode); e != nil {
				t.Fatal(e)
			}
			visited := false
			var err error
			switch name {
			case "passwd", "boot":
				_, err = readLocalMetadata(ctx, path, 1024, uid)
			case "lock":
				pin, _, e := metadataPath(ctx, dir, false)
				if e != nil {
					t.Fatal(e)
				}
				defer func() { _ = pin.Close() }()
				err = WithRecordLock(ctx, pin, uid, func(*os.File) error { visited = true; return nil })
			default:
				err = WithRecordBytes(ctx, root, id, uid, func(sys.Lender, *os.File, func() ([]byte, error)) error { visited = true; return nil })
			}
			if !errors.Is(err, errOwner) || visited {
				t.Fatalf("%s group write accepted or wrong base refusal: visited=%v err=%v", name, visited, err)
			}
		})
	}
}
