// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// socketFile is one end of a unix socketpair as an *os.File, the other end closed with the test.
func socketFile(t *testing.T) *os.File {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	a, b := os.NewFile(uintptr(fds[0]), "sock-a"), os.NewFile(uintptr(fds[1]), "sock-b")
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
	return a
}

// TestDescribeStdioNamesEachKind: run_start says what each standard stream the agent keeps was.
func TestDescribeStdioNamesEachKind(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close(); _ = w.Close() })
	file, err := os.OpenFile(filepath.Join(t.TempDir(), "f"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = file.Close() })
	null, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = null.Close() })

	for _, tc := range []struct {
		name string
		s    Stdio
		want record.Stdio
	}{
		{"socket, pipe, file", Stdio{In: socketFile(t), Out: w, Err: file}, record.Stdio{Stdin: "socket", Stdout: "pipe", Stderr: "file"}},
		{"nothing given is /dev/null", Stdio{Out: null}, record.Stdio{Stdin: "null", Stdout: "null", Stderr: "null"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := stdioRecord(tc.s); *got != tc.want {
				t.Errorf("stdio = %+v, want %+v", *got, tc.want)
			}
		})
	}
	d := DescribeStdio(Stdio{Err: file})
	if d[2].Path != file.Name() || !d[2].Readable || !d[2].Writable {
		t.Errorf("a read-write file = %+v, want its path and both modes", d[2])
	}
}

// TestStdioBeyondContract: a socket on any stream, and a file outside
// every write entry that a stream opens beyond its own direction, give the agent access no rule does; output
// redirected into a file, or a stream the contract's write entry covers, does not.
func TestStdioBeyondContract(t *testing.T) {
	dir := t.TempDir()
	work := filepath.Join(dir, "work")
	if err := os.Mkdir(work, 0o700); err != nil {
		t.Fatal(err)
	}
	rt := &agent.RuleTable{Tier: backend.TierLandlock, Contract: &agent.Contract{Name: "a"},
		FS: []agent.FSRule{{Path: work, Kind: agent.FSWrite, Access: agent.AccessWriteFile | agent.AccessReadFile}}}
	open := func(p string, flag int) *os.File {
		f, err := os.OpenFile(p, flag|os.O_CREATE, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = f.Close() })
		return f
	}
	outside := filepath.Join(dir, "outside")
	for _, tc := range []struct {
		name string
		s    Stdio
		want []string
	}{
		{"a socket on stdin", Stdio{In: socketFile(t)}, []string{"stdin"}},
		{"stdin read-write outside the write entry", Stdio{In: open(outside, os.O_RDWR)}, []string{"stdin"}},
		{"stdin read-only", Stdio{In: open(outside, os.O_RDONLY)}, nil},
		{"stdout into a file", Stdio{Out: open(outside, os.O_WRONLY)}, nil},
		{"stdout read-write outside", Stdio{Out: open(outside, os.O_RDWR)}, []string{"stdout"}},
		{"stdin read-write inside the write entry", Stdio{In: open(filepath.Join(work, "in"), os.O_RDWR)}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var got []string
			for _, st := range StdioBeyondContract(rt, DescribeStdio(tc.s)) {
				got = append(got, st.Name)
			}
			if len(got) != len(tc.want) || (len(got) > 0 && got[0] != tc.want[0]) {
				t.Errorf("reported %v, want %v", got, tc.want)
			}
		})
	}
}
