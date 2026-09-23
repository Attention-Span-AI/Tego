// SPDX-License-Identifier: Apache-2.0

package observe

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// ruleTable builds a compiled table by hand: newRuleIndex reads only the fields below, and building
// a real one would need a project on disk plus DNS.
func ruleTable(fs []agent.FSRule, net []agent.NetRule, exec []agent.ExecRule) *agent.RuleTable {
	return &agent.RuleTable{FS: fs, Net: net, Exec: exec}
}

func TestMatchFSIsNearestWins(t *testing.T) {
	ri := newRuleIndex(ruleTable([]agent.FSRule{
		{Path: "/work", Kind: agent.FSWrite, Raw: "."},
		{Path: "/work/out", Kind: agent.FSWrite, Raw: "./out"},
		{Path: "/work/secrets/key.pem", Kind: agent.FSDenyRead, Raw: "./secrets/key.pem"},
		{Path: "/home/u/.ssh", Kind: agent.FSDenyRead, BuiltIn: true},
		{Path: "/work/config", Kind: agent.FSWatch, Raw: "./config"},
	}, nil, nil))
	cases := []struct {
		name     string
		path     string
		rule     string
		watched  bool
		denyRead bool
	}{
		{"exact write entry", "/work/out", "fs.write[./out]", false, false},
		{"file under the nearer write entry", "/work/out/report.md", "fs.write[./out]", false, false},
		{"file under the outer write entry", "/work/main.py", "fs.write[.]", false, false},
		{"deny_read file", "/work/secrets/key.pem", "fs.deny_read[./secrets/key.pem]", false, true},
		{"sibling of a deny_read file", "/work/secrets/other.pem", "fs.write[.]", false, false},
		{"built-in deny_read", "/home/u/.ssh/id_ed25519", "fs.deny_read[/home/u/.ssh]", false, true},
		{"watched directory", "/work/config/app.yaml", "fs.watch[./config]", true, false},
		{"component boundary is respected", "/work-secret/x", RuleUnmatched, false, false},
		{"nothing declared", "/etc/passwd", RuleUnmatched, false, false},
		{"empty path", "", RuleUnmatched, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := ri.matchFS(tc.path)
			if m.Rule != tc.rule || m.Watched != tc.watched || m.DenyRead != tc.denyRead {
				t.Errorf("matchFS(%q) = %+v, want rule %q watched %v denyRead %v", tc.path, m, tc.rule, tc.watched, tc.denyRead)
			}
		})
	}
	if m := (*ruleIndex)(nil).matchFS("/x"); m.Rule != RuleUnmatched {
		t.Errorf("a nil index must answer unmatched, got %+v", m)
	}
	if ri := newRuleIndex(nil); ri.matchFS("/x").Rule != RuleUnmatched {
		t.Error("an index over a nil table must answer unmatched")
	}
}

// TestInferFS asks inferFS of hand-built matches. Entry names the action; Read and Write are the entries that
// decide it (agent.RuleTable.FSDecider), which a watch entry never is and an implicit one is only for a write.
func TestInferFS(t *testing.T) {
	write := &agent.FSRule{Path: "/work/out", Kind: agent.FSWrite}
	deny := &agent.FSRule{Path: "/work/secrets", Kind: agent.FSDenyRead}
	nested := &agent.FSRule{Path: "/work/out/secrets", Kind: agent.FSDenyRead, Unenforced: true}
	watch := &agent.FSRule{Path: "/work/config", Kind: agent.FSWatch}
	implicit := &agent.FSRule{Path: "/work", Kind: agent.FSImplicit}
	var ri *ruleIndex
	cases := []struct {
		name    string
		op      string
		write   bool
		m       fsMatch
		verdict record.Verdict
		reason  record.Reason
	}{
		{"read under a write entry", record.FSOpen, false, fsMatch{Entry: write, Read: write, Write: write}, record.VerdictAllow, ""},
		{"write under a write entry", record.FSOpen, true, fsMatch{Entry: write, Read: write, Write: write}, record.VerdictAllow, ""},
		{"write under an implicit entry", record.FSOpen, true, fsMatch{Entry: implicit, Write: implicit}, record.VerdictRefused, record.ReasonWriteOutsideContract},
		{"unlink under an implicit entry", record.FSUnlink, true, fsMatch{Entry: implicit, Write: implicit}, record.VerdictRefused, record.ReasonDeleteOutsideContract},
		{"rename under a watch entry", record.FSRename, true, fsMatch{Entry: watch}, record.VerdictRefused, record.ReasonRenameOutsideContract},
		{"mkdir under a watch entry", record.FSMkdir, true, fsMatch{Entry: watch}, record.VerdictRefused, record.ReasonMkdirOutsideContract},
		{"read of a deny_read entry", record.FSOpen, false, fsMatch{Entry: deny, Read: deny, Write: deny, DenyRead: true}, record.VerdictRefused, record.ReasonReadDenied},
		{"unlink of a deny_read entry", record.FSUnlink, true, fsMatch{Entry: deny, Read: deny, Write: deny, DenyRead: true}, record.VerdictRefused, record.ReasonDeleteOutsideContract},
		// Nested in a write entry, the inherited ruleset's union grants the write: it happened.
		{"write under a deny_read nested in a write entry", record.FSOpen, true, fsMatch{Entry: nested, Read: nested, Write: nested, DenyRead: true}, record.VerdictObserved, ""},
		{"read under a deny_read nested in a write entry", record.FSOpen, false, fsMatch{Entry: nested, Read: nested, Write: nested, DenyRead: true}, record.VerdictRefused, record.ReasonReadDenied},
		{"read under a watch entry", record.FSOpen, false, fsMatch{Entry: watch, Watched: true}, record.VerdictAllow, ""},
		{"nothing matched", record.FSOpen, true, fsMatch{Rule: RuleUnmatched}, record.VerdictObserved, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v, reason := ri.inferFS(tc.op, tc.write, tc.m)
			if v != tc.verdict || reason != tc.reason {
				t.Errorf("inferFS = %s/%s, want %s/%s", v, reason, tc.verdict, tc.reason)
			}
		})
	}
}

// TestMatchDir is R9: an unlink/rename/mkdir sample carries the parent directory's (dev, ino) and
// the final component, never a resolved path, and userspace turns that into a path only through the
// declared entries' own inode identities.
func TestMatchDir(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "out")
	if err := os.Mkdir(out, 0o755); err != nil {
		t.Fatal(err)
	}
	ri := newRuleIndex(ruleTable([]agent.FSRule{
		{Path: out, Kind: agent.FSWrite, Raw: "./out"},
		{Path: filepath.Join(dir, "missing"), Kind: agent.FSWrite, Raw: "./missing"},
	}, nil, nil))
	di, ok := statDevIno(out)
	if !ok {
		t.Fatal("could not stat the declared directory")
	}
	path, m, resolved := ri.matchDir(di.Dev, di.Ino, "report.md")
	if !resolved || path != filepath.Join(out, "report.md") || m.Rule != "fs.write[./out]" {
		t.Fatalf("hit: path %q rule %q resolved %v", path, m.Rule, resolved)
	}
	path, m, resolved = ri.matchDir(999999, 424242, "report.md")
	if resolved || m.Rule != RuleUnmatched || path != "999999:424242/report.md" {
		t.Fatalf("miss: path %q rule %q resolved %v", path, m.Rule, resolved)
	}
	if _, ok := statDevIno(filepath.Join(dir, "missing")); ok {
		t.Error("a path that does not exist must not produce a (dev, ino)")
	}
	if _, m, resolved := (*ruleIndex)(nil).matchDir(1, 2, "x"); resolved || m.Rule != RuleUnmatched {
		t.Error("a nil index must answer unmatched")
	}
}

// TestMatchDirNamesTheNearestEntry: a delete/rename of a watch or deny_read child of a write directory is
// named by the child's entry, the same as matchFS names that path.
func TestMatchDirNamesTheNearestEntry(t *testing.T) {
	dir := t.TempDir()
	ri := newRuleIndex(ruleTable([]agent.FSRule{
		{Path: dir, Kind: agent.FSWrite, Raw: "."},
		{Path: filepath.Join(dir, "config"), Kind: agent.FSWatch, Raw: "./config"},
		{Path: filepath.Join(dir, "secrets"), Kind: agent.FSDenyRead, Raw: "./secrets"},
	}, nil, nil))
	di, ok := statDevIno(dir)
	if !ok {
		t.Fatal("could not stat the directory")
	}
	for _, name := range []string{"config", "secrets", "plain"} {
		path, m, resolved := ri.matchDir(di.Dev, di.Ino, name)
		want := ri.matchFS(path)
		if !resolved || m.Rule != want.Rule || m.Watched != want.Watched {
			t.Errorf("%s: matchDir rule %q watched %v, matchFS rule %q watched %v", name, m.Rule, m.Watched, want.Rule, want.Watched)
		}
	}
	if _, m, _ := ri.matchDir(di.Dev, di.Ino, "config"); m.Rule != "fs.watch[./config]" || !m.Watched {
		t.Errorf("config: rule %q watched %v", m.Rule, m.Watched)
	}
}

// TestMatchDirKeysTheWholeInode pins the directory index's key to the inode number struct tego_ev_fsop
// carries, all 64 bits of it. A key cut to 32 bits makes two directories whose inodes share their low
// halves one entry, so an unlink in one is recorded against the other's rule and path — on XFS and btrfs,
// whose inode numbers pass 2^32, that is an ordinary pair of directories, not a contrived one.
func TestMatchDirKeysTheWholeInode(t *testing.T) {
	ri := newRuleIndex(ruleTable([]agent.FSRule{
		{Path: "/work/high", Kind: agent.FSWrite, Raw: "./high"},
		{Path: "/work/low", Kind: agent.FSWrite, Raw: "./low"},
	}, nil, nil))
	idx := map[string]int{}
	for i, e := range ri.fs {
		idx[e.rule.Path] = i
	}
	const dev = 2049
	low := uint64(0x1234)
	high := uint64(1)<<32 | low
	// Neither path exists here, so newRuleIndex indexed nothing; the pairs go in the way it puts them in.
	ri.dirs[dirKey(dev, high)] = idx["/work/high"]
	if p, _, ok := ri.matchDir(dev, low, "x"); ok {
		t.Fatalf("inode %#x resolved to %q through the entry of inode %#x", low, p, high)
	}
	ri.dirs[dirKey(dev, low)] = idx["/work/low"]
	for _, tc := range []struct {
		ino  uint64
		want string
	}{{high, "/work/high/x"}, {low, "/work/low/x"}} {
		if p, _, ok := ri.matchDir(dev, tc.ino, "x"); !ok || p != tc.want {
			t.Errorf("inode %#x resolved to %q (%v), want %q", tc.ino, p, ok, tc.want)
		}
	}
}

// TestDirIndexLeavesOutAnEntryStatDoesNotNameBySuperBlock is R9 on btrfs and on an overlayfs of one filesystem:
// an fs-operation record carries the parent's super block s_dev, dirIndex is built from stat(2)'s st_dev, and
// there the two are never equal (btrfs reports a subvolume's anonymous device, overlayfs a layer's), so every
// unlink, rename and mkdir under the entry missed while §2.4 said it resolved. Such an entry is left out of the
// index and named, for the run's gap. /proc/self/mountinfo's major:minor is the super block's.
func TestDirIndexLeavesOutAnEntryStatDoesNotNameBySuperBlock(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "out")
	if err := os.Mkdir(out, 0o755); err != nil {
		t.Fatal(err)
	}
	var stx unix.Statx_t
	if err := unix.Statx(unix.AT_FDCWD, out, 0, unix.STATX_MNT_ID, &stx); err != nil || stx.Mask&unix.STATX_MNT_ID == 0 {
		t.Skipf("statx names no mount id here: %v", err)
	}
	di, ok := statDevIno(out)
	if !ok {
		t.Fatal("stat the entry")
	}
	rt := ruleTable([]agent.FSRule{{Path: out, Kind: agent.FSWrite, Raw: "./out"}}, nil, nil)
	for _, tc := range []struct {
		name    string
		sbDev   uint64
		indexed bool
	}{
		{"stat names the super block", di.Dev, true},
		{"stat names another device", unix.Mkdev(0, 4242), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mountinfo := filepath.Join(t.TempDir(), "mountinfo")
			line := fmt.Sprintf("%d 1 %d:%d / %s rw - fs dev rw\n", stx.Mnt_id, unix.Major(tc.sbDev), unix.Minor(tc.sbDev),
				dir)
			if err := os.WriteFile(mountinfo, []byte("1 0 0:1 / / rw - rootfs rootfs rw\n"+line), 0o644); err != nil {
				t.Fatal(err)
			}
			ri := newRuleIndexAt(rt, mountinfo)
			_, indexed := ri.dirs[dirKey(di.Dev, di.Ino)]
			if indexed != tc.indexed {
				t.Errorf("indexed %v, want %v", indexed, tc.indexed)
			}
			if got := len(ri.unindexed); got != map[bool]int{true: 0, false: 1}[tc.indexed] {
				t.Errorf("unindexed %v", ri.unindexed)
			}
		})
	}
}

// (docs/p0/enforce-cgroup-observe.md §5 R3 and §6 E8: the recorder names the entry the kernel's exact-then-longest-prefix
// lookup decided by, whose rows carry the first declared covering entry when none refuses, SEMANTICS §5.)
func TestMatchNetExactBeforeCIDR(t *testing.T) {
	ip := netip.MustParseAddr("93.184.216.34")
	inside := netip.MustParseAddr("10.1.2.3")
	narrow := netip.MustParsePrefix("10.1.0.0/16")
	wide := netip.MustParsePrefix("10.0.0.0/8")
	// Every compiled entry carries a port (agent.ParseEndpoint wants host:port or cidr:port); 0 is the
	// explicit ICMP/raw entry, never "any port".
	ri := newRuleIndex(ruleTable(nil, []agent.NetRule{
		{Raw: "api.example.com:443", Host: "api.example.com", Port: 443, Proto: agent.ProtoInet, IPs: []netip.Addr{ip}, Verdict: agent.VerdictAllow},
		{Raw: "10.0.0.0/8:443", Port: 443, Proto: agent.ProtoInet, CIDR: &wide, Verdict: agent.VerdictAllow},
		{Raw: "10.1.0.0/16:443", Port: 443, Proto: agent.ProtoInet, CIDR: &narrow, Verdict: agent.VerdictAllow},
		{Raw: "ntp.example.com:123", Host: "ntp.example.com", Port: 123, Proto: agent.ProtoUDP, IPs: []netip.Addr{netip.MustParseAddr("1.2.3.4")}, Verdict: agent.VerdictAllow},
	}, nil))
	cases := []struct {
		name  string
		addr  netip.Addr
		port  uint16
		proto string
		rule  string
	}{
		{"exact host", ip, 443, agent.ProtoTCP, "net[api.example.com:443]"},
		{"exact host, wrong port", ip, 80, agent.ProtoTCP, RuleUnmatched},
		{"the first declared covering prefix names it", inside, 443, agent.ProtoTCP, "net[10.0.0.0/8:443]"},
		{"only the wide prefix covers", netip.MustParseAddr("10.9.9.9"), 443, agent.ProtoTCP, "net[10.0.0.0/8:443]"},
		{"a prefix entry's port still counts", netip.MustParseAddr("10.9.9.9"), 1, agent.ProtoTCP, RuleUnmatched},
		{"udp entry matches udp", netip.MustParseAddr("1.2.3.4"), 123, agent.ProtoUDP, "net[ntp.example.com:123]"},
		{"udp entry does not match tcp", netip.MustParseAddr("1.2.3.4"), 123, agent.ProtoTCP, RuleUnmatched},
		{"nothing covers", netip.MustParseAddr("8.8.8.8"), 53, agent.ProtoUDP, RuleUnmatched},
		{"invalid address", netip.Addr{}, 1, agent.ProtoTCP, RuleUnmatched},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rule, _ := ri.matchNet(tc.addr, tc.port, tc.proto)
			if rule != tc.rule {
				t.Errorf("matchNet(%s:%d/%s) = %q, want %q", tc.addr, tc.port, tc.proto, rule, tc.rule)
			}
		})
	}
}

// TestMatchNetPortZeroIsICMPOrRawOnly pins the port rule the enforcing sides use (dns.Set.Match,
// RuleTable.Evaluate): a port-0 entry is an ICMP or raw entry. It used to mean "any port" here, so a ping
// rule stamped every TCP connect to that host with the ping entry and allow.
func TestMatchNetPortZeroIsICMPOrRawOnly(t *testing.T) {
	ri := newRuleIndex(ruleTable(nil, []agent.NetRule{
		{Raw: "api.example.com", Host: "api.example.com", Port: 0, Proto: agent.ProtoInet,
			IPs: []netip.Addr{netip.MustParseAddr("1.1.1.1")}, Verdict: agent.VerdictAllow},
	}, nil))
	addr := netip.MustParseAddr("1.1.1.1")
	for _, port := range []uint16{80, 443, 9999} {
		if rule, _ := ri.matchNet(addr, port, agent.ProtoTCP); rule != RuleUnmatched {
			t.Errorf("tcp port %d: %q, want unmatched: a port-0 entry admits no TCP port", port, rule)
		}
	}
	if rule, _ := ri.matchNet(addr, 0, protoRaw); rule != "net[api.example.com]" {
		t.Errorf("icmp: %q", rule)
	}
	if rule, _ := ri.matchNet(addr, 7, protoRaw); rule != "net[api.example.com]" {
		t.Errorf("raw socket with a port: %q", rule)
	}
}

// TestMatchNetComparesUnmappedUnzonedAddresses pins the address rule: a rule address that is v4-mapped, or
// carries a zone from resolution, still names the kernel's plain address, as it does in dns.Set.
func TestMatchNetComparesUnmappedUnzonedAddresses(t *testing.T) {
	ri := newRuleIndex(ruleTable(nil, []agent.NetRule{
		{Raw: "v4.example.com:443", Host: "v4.example.com", Port: 443, Proto: agent.ProtoInet,
			IPs: []netip.Addr{netip.MustParseAddr("::ffff:1.2.3.4")}, Verdict: agent.VerdictAllow},
		{Raw: "link.example.com:443", Host: "link.example.com", Port: 443, Proto: agent.ProtoInet,
			IPs: []netip.Addr{netip.MustParseAddr("fe80::1%eth0")}, Verdict: agent.VerdictAllow},
	}, nil))
	if rule, _ := ri.matchNet(netip.MustParseAddr("1.2.3.4"), 443, agent.ProtoTCP); rule != "net[v4.example.com:443]" {
		t.Errorf("v4-mapped rule address: %q", rule)
	}
	if rule, _ := ri.matchNet(netip.MustParseAddr("fe80::1"), 443, agent.ProtoTCP); rule != "net[link.example.com:443]" {
		t.Errorf("zoned rule address: %q", rule)
	}
}

// TestMatchExec pins that the recorder names an exec exactly as RuleTable.Evaluate does in the run's tier,
// in every tier. An entry declared by path names that file and a directory entry what is under it; whether
// an entry the author wrote as a bare name also matches a same-named binary elsewhere is the tier's
// question (SEMANTICS §4), and Evaluate is where it is answered. The recorder's own matcher used to match
// every entry by basename in every tier, so /opt/bin/git was stamped with an entry that pinned
// /usr/bin/git, and allow.
func TestMatchExec(t *testing.T) {
	rt := ruleTable(nil, nil, []agent.ExecRule{
		{Raw: "/usr/bin/git", Path: "/usr/bin/git", Basename: "git", Verdict: agent.VerdictAllow},
		{Raw: "./venv/bin", Path: "/work/venv/bin", IsDir: true, Verdict: agent.VerdictAllow},
		{Path: "/usr/bin/python3.12", Basename: "python3.12", Source: "command", Verdict: agent.VerdictAllow},
		{Raw: "rg", Path: "/usr/bin/rg", Basename: "rg", ByName: true, Verdict: agent.VerdictAllow},
		{Raw: "/usr/bin/curl", Path: "/usr/bin/curl", Basename: "curl", Verdict: agent.VerdictRefused},
	})
	fixedCases := []struct {
		name, path, rule string
		verdict          record.Verdict
	}{
		{"resolved path", "/usr/bin/git", "exec[/usr/bin/git]", record.VerdictAllow},
		{"implicit grant has no declared text", "/usr/bin/python3.12", "exec[python3.12]", record.VerdictAllow},
		{"under a directory entry", "/work/venv/bin/pip", "exec[./venv/bin]", record.VerdictAllow},
		{"a same-named binary is not the entry declared by path", "/opt/bin/git", RuleUnmatched, record.VerdictObserved},
		{"a refused entry", "/usr/bin/curl", "exec[/usr/bin/curl]", record.VerdictRefused},
		{"nothing matched", "/usr/bin/wget", RuleUnmatched, record.VerdictObserved},
		{"empty", "", RuleUnmatched, record.VerdictObserved},
		// A relative name is what the process passed to execve, not a file: Evaluate took "./git" for the bare
		// name git and stamped it with the entry that pins /usr/bin/git. The recorder resolves it against
		// the process's working directory first; one it could not is matched to nothing.
		{"a relative name", "./git", RuleUnmatched, record.VerdictObserved},
		{"a relative path", "venv/bin/pip", RuleUnmatched, record.VerdictObserved},
	}
	for _, tier := range []backend.Tier{backend.TierLandlock, backend.TierCgroup, backend.TierBPFLSM} {
		rt.Tier = tier
		ri := newRuleIndex(rt)
		for _, tc := range fixedCases {
			t.Run(string(tier)+"/"+tc.name, func(t *testing.T) {
				m := ri.matchExec(tc.path)
				if m.Rule != tc.rule || m.Verdict != tc.verdict {
					t.Errorf("matchExec(%q) = %q %s, want %q %s", tc.path, m.Rule, m.Verdict, tc.rule, tc.verdict)
				}
			})
		}
		// The by-name entry: whatever the tier decides, the recorder says the same.
		for _, path := range []string{"/usr/bin/rg", "/opt/bin/rg"} {
			m := ri.matchExec(path)
			want := rt.Evaluate(agent.Action{Kind: agent.ActionExec, Path: path}, tier)
			wantRule := want.Rule
			if wantRule == agent.UnmatchedRule {
				wantRule = RuleUnmatched
			}
			if m.Rule != wantRule {
				t.Errorf("%s: matchExec(%q) names %q, Evaluate %q: the recorder and compile --test disagree",
					tier, path, m.Rule, want.Rule)
			}
		}
	}
	rt.Tier = backend.TierCgroup
	if m := newRuleIndex(rt).matchExec("/usr/bin/curl"); m.Reason != record.ReasonExecNotAllowed {
		t.Errorf("refused exec reason %q", m.Reason)
	}
}

// TestRuleNames (docs/p0/enforce-cgroup-observe.md §5 R17) pins that this package stamps the names agent.*.RuleName spells and no others: the
// recorder had its own renderers, and a second spelling of the `rule` field is what made every run
// look like drift (spec/record/v1/README.md).
func TestRuleNames(t *testing.T) {
	if got := (agent.FSRule{Path: "/x", Kind: agent.FSImplicit}).RuleName(); got != "fs.implicit[/x]" {
		t.Errorf("implicit entry renders as %q", got)
	}
	if got := (agent.NetRule{Host: "h"}).RuleName(); got != "net[h]" {
		t.Errorf("net entry renders as %q", got)
	}
	if got := (agent.ExecRule{Path: "/usr/bin/x"}).RuleName(); got != "exec[/usr/bin/x]" {
		t.Errorf("exec entry with no basename renders as %q", got)
	}
	// The index built from the table carries the same names, not a second rendering of its own.
	ri := newRuleIndex(&agent.RuleTable{FS: []agent.FSRule{{Path: "/w", Kind: agent.FSWrite, Raw: "./w"}}})
	if got := ri.matchFS("/w/f").Rule; got != "fs.write[./w]" {
		t.Errorf("matchFS names %q, want the declared entry", got)
	}
}
