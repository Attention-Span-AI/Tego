// SPDX-License-Identifier: Apache-2.0

package scan

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/attention-span-ai/tego/internal/scan/catalog"
	"github.com/attention-span-ai/tego/internal/watch/sig"
	"golang.org/x/sys/unix"
)

func writeProcFile(t *testing.T, root, name string, b []byte) {
	t.Helper()
	p := filepath.Join(root, name)
	if e := os.MkdirAll(filepath.Dir(p), 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(p, b, 0600); e != nil {
		t.Fatal(e)
	}
}

func TestProcBoundedNoFollow(t *testing.T) {
	root := t.TempDir()
	writeProcFile(t, root, "10/status", statusFixture(uint32(os.Getuid())))
	fs, e := openProc(root)
	if e != nil {
		t.Fatal(e)
	}
	defer fs.close()
	p, e := fs.open(10)
	if e != nil {
		t.Fatal(e)
	}
	defer p.close()
	if _, e := p.read("environ", maxProcText); !errors.Is(e, errType) {
		t.Fatalf("forbidden read error %v", e)
	}
	if _, e := p.read("status", maxProcText); e != nil {
		t.Fatal(e)
	}
	if _, e := p.read("status", 1); !errors.Is(e, errSize) {
		t.Fatalf("stat size bound %v", e)
	}
	for _, name := range []string{"fifo", "link", "directory", "socket", "hardlink"} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(root, "10", "stat")
			switch name {
			case "fifo":
				if e := unix.Mkfifo(path, 0600); e != nil {
					t.Fatal(e)
				}
			case "link":
				if e := os.Symlink("status", path); e != nil {
					t.Fatal(e)
				}
			case "directory":
				if e := os.Mkdir(path, 0700); e != nil {
					t.Fatal(e)
				}
			case "socket":
				// Bind the same inode by a short name even beneath a deep TMPDIR.
				t.Chdir(filepath.Dir(path))
				l, e := net.Listen("unix", filepath.Base(path))
				if e != nil {
					t.Fatal(e)
				}
				defer l.Close()
			case "hardlink":
				if e := os.Link(filepath.Join(root, "10", "status"), path); e != nil {
					t.Fatal(e)
				}
			}
			defer os.Remove(path)
			if _, e := p.read("stat", maxProcText); !errors.Is(e, errType) {
				t.Fatalf("special file was not refused before data open: %v", e)
			}
		})
	}
}

func TestProcDirectoryAndLinks(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"10/stat", "2/stat", "other/stat", "10/task/11/stat", "10/task/10/stat"} {
		writeProcFile(t, root, name, []byte("x"))
	}
	if e := os.Symlink("/usr/bin/node", filepath.Join(root, "10", "exe")); e != nil {
		t.Fatal(e)
	}
	fs, e := openProc(root)
	if e != nil {
		t.Fatal(e)
	}
	defer fs.close()
	ids, e := fs.pids(context.Background())
	if e != nil || !reflect.DeepEqual(ids, []int{2, 10}) {
		t.Fatalf("ids %v error %v", ids, e)
	}
	p, e := fs.open(10)
	if e != nil {
		t.Fatal(e)
	}
	defer p.close()
	if v, e := p.link("exe"); e != nil || v != "/usr/bin/node" {
		t.Fatalf("link %q %v", v, e)
	}
	if _, e := p.link("environ"); !errors.Is(e, errType) {
		t.Fatalf("link allowlist: %v", e)
	}
	threads, e := p.tasks(context.Background())
	if e != nil || !reflect.DeepEqual(threads, []int{10, 11}) {
		t.Fatalf("threads %v %v", threads, e)
	}
	thread, e := p.thread(11)
	if e != nil {
		t.Fatal(e)
	}
	thread.close()
	bounded, e := directoryIDs(context.Background(), fs.dir, 1)
	if !errors.Is(e, errLimit) || len(bounded) != 1 {
		t.Fatalf("cap %v %v", bounded, e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := fs.pids(ctx); !errors.Is(e, context.Canceled) {
		t.Fatalf("cancellation %v", e)
	}
	if e := os.Symlink("10", filepath.Join(root, "3")); e != nil {
		t.Fatal(e)
	}
	if _, e := fs.open(3); e == nil {
		t.Fatal("followed pid directory link")
	}
}

func TestProcReadLimitPlusOne(t *testing.T) {
	root := t.TempDir()
	writeProcFile(t, root, "10/cmdline", bytes.Repeat([]byte{'x'}, maxArgvBytes+1))
	fs, e := openProc(root)
	if e != nil {
		t.Fatal(e)
	}
	defer fs.close()
	p, e := fs.open(10)
	if e != nil {
		t.Fatal(e)
	}
	defer p.close()
	if _, e := p.read("cmdline", maxArgvBytes); !errors.Is(e, errSize) {
		t.Fatalf("oversize cmdline %v", e)
	}
}

func TestProcZeroSizeReadBound(t *testing.T) {
	for _, n := range []int{maxArgvBytes, maxArgvBytes + 1} {
		b, e := readBounded(bytes.NewReader(bytes.Repeat([]byte{'x'}, n)), maxArgvBytes)
		if n == maxArgvBytes && (e != nil || len(b) != n) {
			t.Fatalf("exact bound: %d %v", len(b), e)
		}
		if n > maxArgvBytes && !errors.Is(e, errSize) {
			t.Fatalf("size-zero source escaped sentinel bound: %v", e)
		}
	}
}

func TestObservedLinkPathsAreNotRewritten(t *testing.T) {
	root := t.TempDir()
	processFixture(t, root, 10, 1, 100, "/bin/claude (deleted)", []byte("claude\x00"), 0)
	cwd := filepath.Join(root, "10", "cwd")
	if e := os.Remove(cwd); e != nil {
		t.Fatal(e)
	}
	if e := os.Symlink("/home/project (deleted)", cwd); e != nil {
		t.Fatal(e)
	}
	fs, e := openProc(root)
	if e != nil {
		t.Fatal(e)
	}
	defer fs.close()
	p, e := fs.open(10)
	if e != nil {
		t.Fatal(e)
	}
	defer p.close()
	got, e := p.link("cwd")
	if e != nil || got != "/home/project (deleted)" {
		t.Fatalf("observed cwd changed to %q: %v", got, e)
	}
	snapshot := readProcesses(context.Background(), fs, root, uint32(os.Getuid()), catalog.Rows())
	if !snapshot.Unknown || len(snapshot.Processes) != 1 || snapshot.Processes[0].Exe != "/bin/claude (deleted)" || snapshot.Processes[0].Fact != sig.FactArgv0Name {
		t.Fatalf("path or fact was rewritten: %+v", snapshot)
	}
}
