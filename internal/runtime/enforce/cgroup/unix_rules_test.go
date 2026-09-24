// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/internal/policy/decide"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// lookupUnix answers a name the way the kernel's trie does: of every row covering the lookup key, the one with
// the longest prefix. ok is false when no row covers it, which connect_unix and sendmsg_unix refuse.
func lookupUnix(t *testing.T, m RuleMaps, sunPath string) (bpf.NetVerdict, bool) {
	t.Helper()
	key, err := bpf.LookupUnixKey(0, []byte(sunPath))
	if err != nil {
		t.Fatalf("LookupUnixKey(%q): %v", sunPath, err)
	}
	var best *UnixRow
	for i := range m.Unix {
		row := &m.Unix[i]
		if row.Key.Matches(key) && (best == nil || row.Key.PrefixLen > best.Key.PrefixLen) {
			best = row
		}
	}
	if best == nil {
		return bpf.NetVerdict{}, false
	}
	return best.Val, true
}

func unixEntry(raw string) agent.NetRule {
	r := agent.NetRule{Raw: raw, Proto: agent.ProtoUnix, Verdict: agent.VerdictAllow, Static: true}
	name := strings.TrimPrefix(raw, "unix:")
	if strings.HasPrefix(name, "@") {
		r.Abstract, r.UnixPath = true, name[1:]
	} else {
		r.UnixPath = name
	}
	return r
}

func unixFSEntry(kind agent.FSKind, path string) agent.FSRule {
	return agent.FSRule{Path: path, Kind: kind, Resolved: path}
}

// compactedEnvTable is a project /w, writable, with the built-in .env pair scoped to it and n .env files /w/s<i>/.env
// that D6 may compact (regular, one link, on ext4 in a case-exact directory).
func compactedEnvTable(n int) *agent.RuleTable {
	fs := []agent.FSRule{{Kind: agent.FSWrite, Path: "/w", Raw: "/w", Resolved: "/w", Access: agent.AccessWriteSet}}
	for i := range n {
		p := "/w/s" + strconv.Itoa(i) + "/.env"
		fs = append(fs, agent.FSRule{Kind: agent.FSDenyRead, Path: p, Resolved: p, BuiltIn: true, Unenforced: true,
			Regular: true, Nlink: 1, Filesystem: "ext4", DirCaseExact: true})
	}
	scopes := []agent.NameScope{{Canonical: "/w", Spelling: "/w"}}
	return &agent.RuleTable{FS: fs, Tier: backend.TierBPFLSM, Record: agent.RecordFull, NameDeny: []agent.NameDenyRule{
		{Literal: ".env", Scopes: scopes, BuiltIn: true},
		{Literal: ".env.", Prefix: true, Except: []string{".env.example", ".env.sample", ".env.template", ".env.dist"}, Scopes: scopes, BuiltIn: true},
	}}
}

// TestUnixRowsLeaveOutTheFilesThePlaneCompacted: a run a plane decides gets no unix row pair for a deny_read file
// the plane compacted (ADR 0043 D6), so 4,500 .env files beneath a write entry fit the trie every run of a build
// shares; the trie answers such a path as it answers a covered name made after compile, the write entry's, while
// the plane refuses the run a socket at the name and the file's unlink and rename. A file the plane kept keeps its
// pair, and the listener's run, given no plane rows, keeps every pair (and so cannot hold this table).
func TestUnixRowsLeaveOutTheFilesThePlaneCompacted(t *testing.T) {
	rt := compactedEnvTable(4500)
	rows, err := decide.CompilePlane(rt)
	if err != nil {
		t.Fatal(err)
	}
	if rows.Compacted == 0 {
		t.Fatal("nothing compacted")
	}
	if _, err := BuildRuleMaps(rt, 0, nil, nil); !errors.Is(err, ErrMapFull) {
		t.Fatalf("every pair kept: %v, want ErrMapFull", err)
	}
	m, err := BuildRuleMaps(rt, 0, nil, rows)
	if err != nil {
		t.Fatalf("the plane's run: %v", err)
	}
	if len(m.Unix) > bpf.UnixRowsMax {
		t.Fatalf("%d unix rows", len(m.Unix))
	}
	kept := 0
	for _, r := range rt.FS[1:] {
		compacted := rows.CompactedAt(r.Path)
		if !compacted {
			kept++
		}
		for _, name := range []string{r.Path, r.Path + "/x.sock"} {
			v, ok := lookupUnix(t, m, name)
			if allow := ok && v.Verdict == uint8(bpf.VerdictAllow); allow != compacted {
				t.Fatalf("%s (compacted %v): allow %v", name, compacted, allow)
			}
		}
	}
	if kept == 0 || kept+rows.Compacted != 4500 {
		t.Fatalf("%d kept, %d compacted", kept, rows.Compacted)
	}
}

// TestUnixRowsMirrorTheSupervisorNameCheck pins what connect_unix and sendmsg_unix admit by name to what the
// supervisor admits by name (supervisor.md R11, decideUnix; SEMANTICS §5), so the kernel only ever narrows
// what the supervisor decided and never refuses what the supervisor records as allowed: a unix: entry by its
// cleaned path or its exact abstract bytes, and otherwise the nearest filesystem entry at or above the name,
// admitting when it is a write entry. Without the name rows every unix destination is refused in the kernel.
func TestUnixRowsMirrorTheSupervisorNameCheck(t *testing.T) {
	t.Parallel()
	rt := table(
		inet("api:443", 443, "198.51.100.4"),
		unixEntry("unix:/run/pg.sock"),
		unixEntry("unix:/run//./docker.sock"), // cleaned, as the supervisor cleans it
		unixEntry("unix:@tego-bus"),
		unixEntry("unix:/tmp/work/declared.sock"), // declared beneath a deny_read: the entry wins
	)
	rt.FS = []agent.FSRule{
		unixFSEntry(agent.FSWrite, "/tmp/work/"),
		unixFSEntry(agent.FSDenyRead, "/tmp/work/secret"),
		unixFSEntry(agent.FSDenyRead, "/tmp/work/declared.sock"),
		unixFSEntry(agent.FSWatch, "/tmp/work/secret/watched"), // no rights: it must not shadow anything
		unixFSEntry(agent.FSWatch, "/tmp/work/logs"),           // nor the write entry right above it
		unixFSEntry(agent.FSImplicit, "/etc"),
		unixFSEntry(agent.FSWrite, "/srv/a"),
		unixFSEntry(agent.FSDenyRead, "/srv/a"), // one path twice: the first declared is the nearest (nearestIn)
	}
	m, err := BuildRuleMaps(rt, 0, nil, nil)
	if err != nil {
		t.Fatalf("BuildRuleMaps: %v", err)
	}

	cases := []struct {
		name    string
		sunPath string
		allow   bool
		ruleIdx uint16 // for an allow a unix: entry decided; 0 otherwise
	}{
		{"a declared pathname", "/run/pg.sock", true, 2},
		{"a declared pathname, cleaned", "/run/docker.sock", true, 3},
		{"a declared pathname followed by its NUL and garbage", "/run/pg.sock\x00zz", true, 2},
		{"a longer name that starts with a declared one", "/run/pg.sock2", false, 0},
		{"a declared abstract name", "\x00tego-bus", true, 4},
		{"an abstract name one byte longer", "\x00tego-bus\x00", false, 0},
		{"an abstract prefix of a declared one", "\x00tego-b", false, 0},
		{"a pathname spelling of the abstract name", "/tego-bus", false, 0},
		{"a socket under a write entry", "/tmp/work/pymp-1/listener", true, 0},
		{"the write entry itself", "/tmp/work", true, 0},
		{"a sibling that shares the write entry's bytes", "/tmp/workshop/x.sock", false, 0},
		{"a socket under a deny_read inside the write entry", "/tmp/work/secret/x.sock", false, 0},
		{"a watch entry does not shadow the deny_read above it", "/tmp/work/secret/watched/x.sock", false, 0},
		{"a watch entry does not shadow the write entry above it", "/tmp/work/logs/x.sock", true, 0},
		{"a watch entry's own path, under the write entry", "/tmp/work/logs", true, 0},
		{"a declared entry beneath a deny_read of the same path", "/tmp/work/declared.sock", true, 5},
		{"under a non-write entry", "/etc/x.sock", false, 0},
		{"under no entry", "/run/other.sock", false, 0},
		{"one path declared write, then deny_read", "/srv/a/x.sock", true, 0},
	}
	for _, tc := range cases {
		v, ok := lookupUnix(t, m, tc.sunPath)
		got := ok && v.Verdict == uint8(bpf.VerdictAllow)
		if got != tc.allow {
			t.Errorf("%s (%q): allow=%v, want %v (row %+v, found %v)", tc.name, tc.sunPath, got, tc.allow, v, ok)
			continue
		}
		if tc.allow && v.RuleIdx != tc.ruleIdx {
			t.Errorf("%s (%q): rule index %d, want %d", tc.name, tc.sunPath, v.RuleIdx, tc.ruleIdx)
		}
		if ok && !tc.allow && v.Reason != uint8(bpf.ReasonNetNotAllowed) {
			t.Errorf("%s (%q): a refusing row carries reason %d, want net-not-allowed", tc.name, tc.sunPath, v.Reason)
		}
	}
	if len(m.Skipped) != 0 {
		t.Errorf("unix entries were skipped: %+v", m.Skipped)
	}
	// /etc has no write entry at or above it: its rows could not change a verdict, so it has none.
	for _, row := range m.Unix {
		if strings.HasPrefix(string(row.Key.Name[:]), "/etc") {
			t.Errorf("a refusing entry with no write ancestor got a row: %q", row.Key.Name[:6])
		}
	}
}

// TestUnixRowsForTheRootAndLongEntries covers the edges of the row encoding: the root entry, which is its own
// separator and covers every absolute name; an entry that fills sun_path exactly, which gets an exact row
// without a NUL (no name is longer), so a deny_read of that length still refuses beneath a write entry; and an
// entry too long for any name to reach, which gets no row rather than an error.
func TestUnixRowsForTheRootAndLongEntries(t *testing.T) {
	t.Parallel()
	full := "/w/" + strings.Repeat("d", bpf.UnixNameMax-3) // 108 bytes
	rt := table(inet("api:443", 443, "198.51.100.4"))
	rt.FS = []agent.FSRule{
		unixFSEntry(agent.FSWrite, "/"),
		unixFSEntry(agent.FSDenyRead, full),
		unixFSEntry(agent.FSDenyRead, "/w/"+strings.Repeat("e", 300)),
	}
	m, err := BuildRuleMaps(rt, 0, nil, nil)
	if err != nil {
		t.Fatalf("BuildRuleMaps: %v", err)
	}
	if v, ok := lookupUnix(t, m, "/any/where.sock"); !ok || v.Verdict != uint8(bpf.VerdictAllow) {
		t.Errorf("a name under the root write entry: %+v %v, want allowed", v, ok)
	}
	if v, ok := lookupUnix(t, m, full); !ok || v.Verdict != uint8(bpf.VerdictRefused) {
		t.Errorf("a 108-byte name that is a deny_read entry: %+v %v, want refused", v, ok)
	}
}

// TestUnixEntryLongerThanSunPathIsLeftToTierOne covers a pathname unix: entry that is longer than sun_path
// once cleaned, which a contract can hold because the parser checks the length before ~/ is expanded. No
// absolute name reaches it, and the relative name that can is the supervisor's to decide, so it is skipped with
// SkipUnixLong. It used to fail BuildRuleMaps, and with it Prepare, on every kernel: a run tier 1 serves exited
// 125. The length is the cleaned one: a spelling that cleans to a name that fits still gets its row, and a name
// that fills sun_path exactly is admitted.
func TestUnixEntryLongerThanSunPathIsLeftToTierOne(t *testing.T) {
	t.Parallel()
	long := "/home/someuser/" + strings.Repeat("s", 100)                 // 115 bytes, as ~/sss... expands
	full := "/run/" + strings.Repeat("p", bpf.UnixNameMax-len("/run/"))  // 108 bytes
	shrinks := "/home/" + strings.Repeat("u", 100) + "/../../run/c.sock" // cleans to /run/c.sock
	rt := table(
		inet("api:443", 443, "198.51.100.4"),
		unixEntry("unix:"+long),
		unixEntry("unix:"+full),
		unixEntry("unix:"+shrinks),
	)
	m, err := BuildRuleMaps(rt, 0, nil, nil)
	if err != nil {
		t.Fatalf("BuildRuleMaps with a unix: entry past sun_path: %v", err)
	}
	if len(m.Skipped) != 1 || m.Skipped[0].Raw != "unix:"+long || m.Skipped[0].Why != SkipUnixLong {
		t.Fatalf("skipped %+v, want only the %d-byte entry, with SkipUnixLong", m.Skipped, len(long))
	}
	if v, ok := lookupUnix(t, m, full); !ok || v.Verdict != uint8(bpf.VerdictAllow) || v.RuleIdx != 3 {
		t.Errorf("a declared name that fills sun_path: %+v %v, want allowed by entry 3", v, ok)
	}
	if v, ok := lookupUnix(t, m, "/run/c.sock"); !ok || v.Verdict != uint8(bpf.VerdictAllow) || v.RuleIdx != 4 {
		t.Errorf("an entry that cleans to a name that fits: %+v %v, want allowed by entry 4", v, ok)
	}
	if v, ok := lookupUnix(t, m, long[:bpf.UnixNameMax]); ok && v.Verdict == uint8(bpf.VerdictAllow) {
		t.Errorf("the long entry's first 108 bytes are admitted: %+v", v)
	}

	f := newFixture(t)
	f.table.Net = append(f.table.Net, unixEntry("unix:"+long))
	h, err := f.backend.Prepare(context.Background(), f.table, f.run)
	if err != nil {
		t.Fatalf("Prepare with a unix: entry past sun_path: %v", err)
	}
	_ = h.Close()
}

// TestUnixRowsFollowTheRun asserts the name rows are this run's in every step that §5 R12 and §8 I5 govern:
// written at Prepare, removed at Detach, and purged when a slot is reclaimed from a launcher that died with
// rows still pinned. A row left behind would admit a later run's unix connect under a dead run's contract.
func TestUnixRowsFollowTheRun(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	f.table.Net = append(f.table.Net, unixEntry("unix:/run/pg.sock"), unixEntry("unix:@tego-bus"))
	h, err := f.backend.Prepare(context.Background(), f.table, f.run)
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if n := len(f.kernel.net.unix); n != len(h.Rules().Unix) || n < 2 {
		t.Fatalf("%d name rows written, want the %d the table compiled to", n, len(h.Rules().Unix))
	}
	slot := h.Slot()
	if err := h.Detach(); err != nil {
		t.Fatalf("Detach: %v", err)
	}
	if n := f.kernel.net.rowsFor(slot); n != 0 {
		t.Fatalf("%d rows of slot %d survive Detach", n, slot)
	}
	_ = h.Close()

	// A dead launcher's rows under the slot the next run is handed: purgeSlot removes them before this run's
	// own go in.
	stale, err := bpf.UnixPathKey(slot, "/stale.sock", false)
	if err != nil {
		t.Fatal(err)
	}
	f.kernel.net.unix[stale] = bpf.NetVerdict{Verdict: uint8(bpf.VerdictAllow)}
	h2, err := f.backend.Prepare(context.Background(), f.table, f.run)
	if err != nil {
		t.Fatalf("second Prepare: %v", err)
	}
	defer h2.Close()
	if h2.Slot() != slot {
		t.Fatalf("the second run got slot %d, not the released %d", h2.Slot(), slot)
	}
	if _, ok := f.kernel.net.unix[stale]; ok {
		t.Fatal("a dead run's unix name row survived the slot's reuse (§5 R12)")
	}
}

// TestAttachNamesTheRelayCgroup pins the half of connect_unix's relay rule that userspace owns: Attach writes
// this launcher's own cgroup into the owner, the one caller from which the supervisor's /proc/self/fd/<n>
// name is admitted (§5 R7), and refuses a cgroup it cannot name or one inside the run, where the agent's
// processes would share it and the name would be admitted from the agent too.
func TestAttachNamesTheRelayCgroup(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	h, err := f.backend.Prepare(context.Background(), f.table, f.run)
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	defer h.Close()
	if err := h.Attach(f.run.CgroupID); err != nil {
		t.Fatalf("Attach: %v", err)
	}
	want, err := cgroupIDOfPath(f.run.mount(), "/")
	if err != nil {
		t.Fatal(err)
	}
	if got := f.kernel.owner.RelayCgroupID; got != want || got == 0 || got == f.run.CgroupID {
		t.Fatalf("owner's relay cgroup = %d, want the launcher's own %d", got, want)
	}

	for name, self := range map[string]func() (string, error){
		"unreadable": func() (string, error) { return "", errors.New("no /proc") },
		"missing":    func() (string, error) { return "/no/such.scope", nil },
		"the run's":  func() (string, error) { return f.run.CgroupPath, nil },
		"beneath":    func() (string, error) { return f.run.CgroupPath + "/child", nil },
	} {
		g := newFixture(t, func(o *Options) { o.selfCgroup = self })
		if name == "beneath" {
			if err := os.MkdirAll(filepath.Join(g.run.mount(), g.run.CgroupPath, "child"), 0o755); err != nil {
				t.Fatal(err)
			}
		}
		h, err := g.backend.Prepare(context.Background(), g.table, g.run)
		if err != nil {
			t.Fatalf("%s: Prepare: %v", name, err)
		}
		if err := h.Attach(g.run.CgroupID); !errors.Is(err, ErrNotPrepared) {
			t.Errorf("%s launcher cgroup: Attach = %v, want ErrNotPrepared", name, err)
		}
		if g.kernel.attached != "" {
			t.Errorf("%s launcher cgroup: the programs were attached anyway", name)
		}
		_ = h.Close()
	}
}
