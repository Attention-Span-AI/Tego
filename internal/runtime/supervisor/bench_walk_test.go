// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// BenchmarkNotificationRoundTripRealWalk is BenchmarkNotificationRoundTrip for the notified fs syscalls with
// the one cost the fake kernel otherwise hides: where each path lands (FSTarget, R15b) is resolved by the real
// kernel, in a real tree of a project's usual depth under TMPDIR, as this process's own lookup. The argument
// reads, ID_VALID and the response stay faked, so the figure is the loop's own work plus the resolution; the
// real ioctl round trip is TestIntegrationFastPathOps' to measure.
//
// The rows are the common cases: a read-open and a write-open of an existing file in the write entry, an
// O_CREAT open of a new one, a mkdir of an existing directory, a truncate and an fchmodat (record: full's
// metadata changes), each spelled absolute; and a read-open reached through a symlink the contract does not
// declare, which the walk must follow.
func BenchmarkNotificationRoundTripRealWalk(b *testing.B) {
	root := b.TempDir()
	proj := filepath.Join(root, "work", "proj")
	deep := filepath.Join(proj, "src", "pkg", "internal", "module")
	if err := os.MkdirAll(deep, 0o755); err != nil {
		b.Fatal(err)
	}
	file := filepath.Join(deep, "file.go")
	if err := os.WriteFile(file, []byte("package module\n"), 0o644); err != nil {
		b.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(proj, "src"), filepath.Join(proj, "alias")); err != nil {
		b.Fatal(err)
	}
	fs := []agent.FSRule{{Path: proj, Kind: agent.FSWrite}, {Path: filepath.Join(proj, ".git", "hooks"), Kind: agent.FSDenyWrite}}
	nr := func(name string) int32 {
		for k, e := range buildDispatch() {
			if e.name == name {
				return k.nr
			}
		}
		b.Skipf("%s does not exist on this architecture", name)
		return 0
	}
	type row struct {
		name string
		path string
		sys  string
		arg  func(addr uint64) []uint64
		full bool
	}
	openArgs := func(flags int) func(uint64) []uint64 {
		return func(a uint64) []uint64 { return []uint64{argCWD, a, uint64(flags)} }
	}
	rows := []row{
		{name: "read_open", path: file, sys: "openat", arg: openArgs(unix.O_RDONLY), full: true},
		{name: "read_open_via_symlink", path: filepath.Join(proj, "alias", "pkg", "internal", "module", "file.go"), sys: "openat", arg: openArgs(unix.O_RDONLY), full: true},
		{name: "write_open", path: file, sys: "openat", arg: openArgs(unix.O_WRONLY | unix.O_TRUNC)},
		{name: "create_open", path: filepath.Join(deep, "new.go"), sys: "openat", arg: openArgs(unix.O_WRONLY | unix.O_CREAT | unix.O_TRUNC)},
		{name: "mkdir_existing", path: deep, sys: "mkdirat", arg: func(a uint64) []uint64 { return []uint64{argCWD, a, 0o755} }},
		{name: "truncate", path: file, sys: "truncate", arg: func(a uint64) []uint64 { return []uint64{a, 0} }},
		{name: "fchmodat", path: file, sys: "fchmodat", arg: func(a uint64) []uint64 { return []uint64{argCWD, a, 0o644} }, full: true},
	}
	for _, walk := range []bool{false, true} {
		for _, r := range rows {
			name := r.name + "/fake_walk"
			if walk {
				name = r.name + "/real_walk"
			}
			b.Run(name, func(b *testing.B) {
				f := newFake()
				f.put(0x1000, cstr(r.path))
				f.realWalks = walk
				pol := testPolicy(nil, fs, nil)
				pol.Rules.Tier = backend.TierLandlock
				if r.full {
					pol.Rules.Record = agent.RecordFull
				}
				l := benchLoop(b, f, pol)
				proto := notifFor(nr(r.sys), 42, r.arg(0x1000)...)
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					n := *proto
					n.answered, n.gone = false, false
					l.handle(&n)
				}
			})
		}
	}
}
