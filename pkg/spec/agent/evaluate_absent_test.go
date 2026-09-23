// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestEvaluateNetWithNoNetSection pins SEMANTICS §1's "no `net:` — deny nothing" against "`net: {}` —
// all connects refused". The Landlock builder leaves the net rights unhandled for the first
// (netRestricted) and the supervisor leaves such a connect to the kernel; Evaluate refusing an
// undeclared host made `compile --test` certify as impossible a connect the run performs.
//
// Tier 2 is pinned on its own: its cgroup programs refused every TCP and UDP destination with no row,
// which is every destination of such a contract, until it stopped attaching them for one
// (internal/runtime/enforce/cgroup RuleMaps.Unrestricted). A TCP and a UDP connect of a contract with no
// net: then both succeeded as root in the KVM guest, and this is the answer that matches.
// agent-contract.md R21: an empty policy denies no connect.
func TestEvaluateNetWithNoNetSection(t *testing.T) {
	f := newFixture(t)
	rt, _ := f.compile(f.load("version: 0\nname: a\ncommand: [python]\n"))
	if !rt.NetUnrestricted() {
		t.Fatal("a contract with no net: section compiled as restricted")
	}
	hostSockets := []Action{
		{Kind: ActionNetConnect, Path: "/run/user/1000/bus"},
		{Kind: ActionNetConnect, Path: "@/tmp/.X11-unix/X0"},
		{Kind: ActionNetSend, Path: "/run/systemd/journal/socket"},
		{Kind: ActionNetSend, Path: "@/org/freedesktop/systemd1/notify"},
	}
	for _, a := range []Action{
		{Kind: ActionNetConnect, Host: "203.0.113.9", Port: 443},
		{Kind: ActionNetConnect, Host: "example.org", Port: 80, Proto: "udp"},
	} {
		for _, tier := range enforcingTiers() {
			if got := rt.Evaluate(a, tier); got.Verdict != VerdictAllow || got.Rule != UnmatchedRule {
				t.Errorf("tier %s: %+v with no net: section = %+v, want allow/%s", tier, a, got, UnmatchedRule)
			}
		}
	}
	// ADR 0070: the unix-only state. A unix socket no process of the run could have bound, pathname or abstract, is
	// refused host-sockets at every enforcing tier, a connect and a datagram alike; host_sockets: true restores the
	// allow, and observe enforces nothing.
	for _, a := range hostSockets {
		for _, tier := range enforcingTiers() {
			if got := rt.Evaluate(a, tier); got.Verdict != VerdictRefused || got.Rule != HostSocketsRule || got.Reason != record.ReasonNetNotAllowed {
				t.Errorf("tier %s: %+v with no net: section = %+v, want refused/%s", tier, a, got, HostSocketsRule)
			}
		}
		if got := rt.Evaluate(a, backend.TierObserve); got.Verdict != VerdictAllow {
			t.Errorf("observe: %+v = %+v, want allow", a, got)
		}
	}
	opened, _ := f.compile(f.load("version: 0\nname: a\ncommand: [python]\nhost_sockets: true\n"))
	for _, a := range hostSockets {
		for _, tier := range enforcingTiers() {
			if got := opened.Evaluate(a, tier); got.Verdict != VerdictAllow || got.Rule != UnmatchedRule {
				t.Errorf("tier %s: %+v under host_sockets: true = %+v, want allow/%s", tier, a, got, UnmatchedRule)
			}
		}
	}
	for _, a := range []Action{
		{Kind: ActionNetConnect, Host: "127.0.0.1", Port: 37271},
		{Kind: ActionNetConnect, Host: "127.0.0.1", Port: 35118, Proto: "udp"},
	} {
		if got := rt.Evaluate(a, backend.TierCgroup); got.Verdict != VerdictAllow || got.Rule != UnmatchedRule {
			t.Errorf("tier cgroup: %+v with no net: section = %+v, want allow/%s: tier 2 attaches no network program", a, got, UnmatchedRule)
		}
	}

	// The other arm of the tri-state keeps its restrictive default.
	rt, _ = f.compile(f.load("version: 0\nname: a\ncommand: [python]\nnet: {}\n"))
	for _, tier := range enforcingTiers() {
		got := rt.Evaluate(Action{Kind: ActionNetConnect, Host: "203.0.113.9", Port: 443}, tier)
		if got.Verdict != VerdictRefused || got.Reason != record.ReasonNetNotAllowed {
			t.Errorf("tier %s: net: {} = %+v, want refused/%s", tier, got, record.ReasonNetNotAllowed)
		}
	}

	// A populated section refuses what it does not name, and a table with no Contract fails closed.
	rt, _ = f.compile(f.load("version: 0\nname: a\ncommand: [python]\nnet:\n  allow: [\"127.0.0.1:8080\"]\n"))
	if got := rt.Evaluate(Action{Kind: ActionNetConnect, Host: "127.0.0.1", Port: 9090}, backend.TierLandlock); got.Verdict != VerdictRefused {
		t.Errorf("undeclared port under a populated net: = %+v, want refused", got)
	}
	hand := &RuleTable{Tier: backend.TierLandlock}
	if got := hand.Evaluate(Action{Kind: ActionNetConnect, Host: "203.0.113.9", Port: 443}, backend.TierLandlock); got.Verdict != VerdictRefused {
		t.Errorf("hand-built table with no Contract = %+v, want refused", got)
	}
}

// TestEvaluateWritesWithNoFSSection pins SEMANTICS §1's "no `fs:`" row as amended: no write entry is
// compiled, so every mutation is refused in every enforcing tier exactly as under `fs: {}`, while
// reads stay allowed and the built-in deny_read list stays in force. The unrestricted reading could
// not be built without giving up the implicit entries (Landlock is allow-only and cannot deny the
// run directory beneath an allow), so the spec now says what all three components do.
// agent-contract.md R21: with no fs: section every write is refused.
func TestEvaluateWritesWithNoFSSection(t *testing.T) {
	f := newFixture(t)
	noFS, _ := f.compile(f.load("version: 0\nname: a\ncommand: [python]\n"))
	emptyFS, _ := f.compile(f.load("version: 0\nname: a\ncommand: [python]\nfs: {}\n"))
	target := filepath.Join(f.project, "out", "report.md")
	for _, a := range []Action{
		{Kind: ActionFSWrite, Path: target},
		{Kind: ActionFSDelete, Path: target},
		{Kind: ActionFSMkdir, Path: filepath.Join(f.project, "newdir")},
		{Kind: ActionFSRename, Path: target, DestPath: filepath.Join(f.project, "out", "moved.md")},
	} {
		for _, tier := range enforcingTiers() {
			got := noFS.Evaluate(a, tier)
			if got.Verdict != VerdictRefused || got.Reason != FSReason(a.Kind) {
				t.Errorf("tier %s: %s %s with no fs: section = %+v, want refused/%s", tier, a.Kind, a.Path, got, FSReason(a.Kind))
			}
			if want := emptyFS.Evaluate(a, tier); want.Verdict != got.Verdict || want.Reason != got.Reason {
				t.Errorf("tier %s: %s with no fs: = %+v, with fs: {} = %+v; the two must refuse alike", tier, a.Kind, got, want)
			}
		}
	}
	for _, tier := range enforcingTiers() {
		if got := noFS.Evaluate(Action{Kind: ActionFSRead, Path: target}, tier); got.Verdict != VerdictAllow {
			t.Errorf("tier %s: read with no fs: section = %+v, want allow", tier, got)
		}
		got := noFS.Evaluate(Action{Kind: ActionFSRead, Path: filepath.Join(f.home, ".ssh", "id_rsa")}, tier)
		if got.Verdict != VerdictRefused || got.Reason != record.ReasonReadDenied {
			t.Errorf("tier %s: read under ~/.ssh with no fs: section = %+v, want refused/%s: the built-in list applies", tier, got, record.ReasonReadDenied)
		}
	}
}

// TestExecOfADeclaredFileThatIsADenyReadTarget: Landlock gives a declared file an fd of its own, but
// when that file is itself an enforced deny_read target the builder has already sealed its inode
// and fails Prepare rather than grant it (enforce-landlock E32 (c)); the root tiers' walk refuses the
// read in any case. Evaluate reported landlock allow for a run that never starts. A declared file
// *inside* a directory target, a target nested in another target, and an unenforced target are each
// a different case the builder grants, and stay allowed.
func TestExecOfADeclaredFileThatIsADenyReadTarget(t *testing.T) {
	f := newFixture(t)
	secret := filepath.Join(f.bin, "secret-tool")
	f.file(secret, string(elf64("", 2)), 0o755)
	rt, _ := f.compile(f.load("version: 0\nname: a\ncommand: [python]\nfs:\n  deny_read: [\"" + secret + "\"]\nexec:\n  allow: [\"" + secret + "\"]\n"))
	want := "fs.deny_read[" + secret + "]"
	for _, tier := range enforcingTiers() {
		got := rt.Evaluate(Action{Kind: ActionExec, Path: secret}, tier)
		if got.Verdict != VerdictRefused || got.Reason != record.ReasonReadDenied || got.Rule != want {
			t.Errorf("tier %s: exec of a declared file that is a deny_read target = %+v, want refused/%s/%s", tier, got, record.ReasonReadDenied, want)
		}
	}

	// Inside a directory target: a different inode with its own grant (I11 (1)).
	inside := filepath.Join(f.home, ".ssh", "tool")
	f.file(inside, string(elf64("", 2)), 0o755)
	rt, _ = f.compile(f.load("version: 0\nname: a\ncommand: [python]\nexec:\n  allow: [\"" + inside + "\"]\n"))
	wantLandlockAllow(t, rt, Action{Kind: ActionExec, Path: inside}, "exec["+inside+"]", "declared file inside ~/.ssh")

	// Nested inside another enforced target: E29 (a) drops it before anything is sealed.
	rt, _ = f.compile(f.load("version: 0\nname: a\ncommand: [python]\nfs:\n  deny_read: [\"" + inside + "\"]\nexec:\n  allow: [\"" + inside + "\"]\n"))
	wantLandlockAllow(t, rt, Action{Kind: ActionExec, Path: inside}, "exec["+inside+"]", "declared target nested in ~/.ssh")

	// Unenforced under a write entry: never enumerated (R4), so never sealed.
	out := filepath.Join(f.project, "out", "tool")
	f.file(out, string(elf64("", 2)), 0o755)
	rt, _ = f.compile(f.load("version: 0\nname: a\ncommand: [python]\nfs:\n  write: [out/]\n  deny_read: [out/tool]\nexec:\n  allow: [\"" + out + "\"]\n"))
	wantLandlockAllow(t, rt, Action{Kind: ActionExec, Path: out}, "exec["+out+"]", "declared target left unenforced by a write entry")
}

// TestExecLoaderUnderAnUnenforcedDenyRead pins the Landlock loader arm to Prepare's own check:
// governs() refuses a loader at or below any deny_read target, including one tier 1 leaves
// unenforced, where the read arm (evalFSLandlock) says allow. Here an exec.allow directory makes
// the deny_read unenforced (writablePaths), and the declared binary's loader lies inside it.
func TestExecLoaderUnderAnUnenforcedDenyRead(t *testing.T) {
	f := newFixture(t)
	tools := filepath.Join(f.project, "tools")
	ld := filepath.Join(tools, "secret", "ld.so")
	if err := os.MkdirAll(filepath.Dir(ld), 0o755); err != nil {
		t.Fatal(err)
	}
	f.file(ld, string(elf64("", 1)), 0o755)
	tool := filepath.Join(f.bin, "ldtool")
	f.file(tool, string(elf64(ld, 2)), 0o755)
	rt, _ := f.compile(f.load("version: 0\nname: a\ncommand: [python]\nfs:\n  deny_read: [tools/secret/]\nexec:\n  allow: [\"" + tools + "\", \"" + tool + "\"]\n"))
	deny := "fs.deny_read[tools/secret/]"
	for _, r := range rt.FS {
		if r.Kind == FSDenyRead && r.RuleName() == deny && !r.Unenforced {
			t.Fatalf("premise: %s is not marked unenforced under the exec.allow directory", deny)
		}
	}
	got := rt.Evaluate(Action{Kind: ActionExec, Path: tool}, backend.TierLandlock)
	if got.Verdict != VerdictRefused || got.Reason != record.ReasonReadDenied || got.Rule != deny {
		t.Errorf("landlock: exec of a binary whose loader lies under an unenforced deny_read = %+v, want refused/%s/%s (Prepare refuses the loader)", got, record.ReasonReadDenied, deny)
	}
}

// TestExecLoaderIsTheDeclaredFilesOnly: compile read one loader, the declared file's own. A binary
// tier 3 matches to a basename entry by name is a different inode whose loader this package never
// read (I6), so it must not inherit the entry's loader and the refusal that loader carries.
func TestExecLoaderIsTheDeclaredFilesOnly(t *testing.T) {
	f := newFixture(t)
	ld := filepath.Join(f.home, ".ssh", "ld.so")
	f.file(ld, string(elf64("", 1)), 0o755)
	f.file(filepath.Join(f.bin, "ldtool"), string(elf64(ld, 2)), 0o755)
	rt, _ := f.compile(f.load("version: 0\nname: a\ncommand: [python]\nexec:\n  allow: [ldtool]\n"))
	elsewhere := "/tmp/work/ldtool"
	if got := rt.Evaluate(Action{Kind: ActionExec, Path: elsewhere}, backend.TierBPFLSM); got.Verdict != VerdictAllow || got.Rule != "exec[ldtool]" {
		t.Errorf("tier 3: a same-named binary matched by name = %+v, want allow/exec[ldtool] with no loader of its own modelled", got)
	}
	// The declared file itself does carry that loader.
	if got := rt.Evaluate(Action{Kind: ActionExec, Path: filepath.Join(f.bin, "ldtool")}, backend.TierBPFLSM); got.Verdict != VerdictRefused {
		t.Errorf("tier 3: the declared file whose loader is under ~/.ssh = %+v, want refused", got)
	}
}

// TestCompileWarnsAboutARefusedLoader: Prepare refuses a loader at or below an fs.write, fs.ask or
// fs.deny_read entry and the landlock and cgroup runs exit 125 before the agent starts (enforce-landlock
// R5, E29). Evaluate can only show the deny_read case, so Compile says it for every one.
func TestCompileWarnsAboutARefusedLoader(t *testing.T) {
	f := newFixture(t)
	for _, c := range []struct{ name, dir, fs string }{
		{"deny_read", filepath.Join(f.home, ".ssh"), ""},
		{"write", filepath.Join(f.project, "out"), "fs:\n  write: [out/]\n"},
	} {
		ld := filepath.Join(c.dir, "ld-"+c.name+".so")
		f.file(ld, string(elf64("", 1)), 0o755)
		tool := filepath.Join(f.bin, "tool-"+c.name)
		f.file(tool, string(elf64(ld, 2)), 0o755)
		_, ds := f.compile(f.load("version: 0\nname: a\ncommand: [python]\n" + c.fs + "exec:\n  allow: [\"" + tool + "\"]\n"))
		if !hasCode(ds, CodeLoaderRefused) {
			t.Errorf("%s: a loader under the %s entry produced no %s warning:\n%s", c.name, c.name, CodeLoaderRefused, render(ds))
		}
	}
	// The control: python's loader lies outside every entry.
	_, ds := f.compile(f.load("version: 0\nname: a\ncommand: [python]\nfs:\n  write: [out/]\n"))
	if hasCode(ds, CodeLoaderRefused) {
		t.Errorf("a clean loader was warned about:\n%s", render(ds))
	}
}

// TestCompileWarnsAboutANamespaceSandbox: a Landlock domain refuses mount(2) and pivot_root, so a
// sandbox the agent starts fails in both P0 tiers (SEMANTICS §10); ARCHITECTURE §4.1 (6) has compile
// say so when the contract names one.
func TestCompileWarnsAboutANamespaceSandbox(t *testing.T) {
	f := newFixture(t)
	f.file(filepath.Join(f.bin, "bwrap"), string(elf64("", 2)), 0o755)
	_, ds := f.compile(f.load("version: 0\nname: a\ncommand: [python]\nexec:\n  allow: [bwrap]\n"))
	if !hasCode(ds, CodeLandlockTopology) {
		t.Errorf("exec.allow: [bwrap] produced no %s warning:\n%s", CodeLandlockTopology, render(ds))
	}
	_, ds = f.compile(f.load("version: 0\nname: a\ncommand: [python]\nexec:\n  allow: [static-tool]\n"))
	if hasCode(ds, CodeLandlockTopology) {
		t.Errorf("an ordinary binary was warned about:\n%s", render(ds))
	}
}

// TestEvaluateRunBoundSocketWithNoNetSection is ADR 0070's admit: in the unix-only state a socket a process of the run
// bound is reachable. Compile --test answers the run's own case where the run can bind one, beneath a write entry
// (Landlock grants MAKE_SOCK only there), as the run's implicit admit names it, by the write entry; the same name
// outside every write entry, and a relative or abstract one, is refused host-sockets; and tego's own endpoint, a
// runtime unix: grant the DNS broker adds, stays reachable by its rule.
func TestEvaluateRunBoundSocketWithNoNetSection(t *testing.T) {
	f := newFixture(t)
	rt, _ := f.compile(f.load("version: 0\nname: a\ncommand: [python]\nfs:\n  write: [\"./out/\"]\n"))
	if !rt.HostSocketsRefused() {
		t.Fatal("a contract with no net: section is in the unix-only state")
	}
	sock := filepath.Join(f.project, "out", "app.sock")
	for _, a := range []Action{{Kind: ActionNetConnect, Path: sock}, {Kind: ActionNetSend, Path: sock}} {
		for _, tier := range enforcingTiers() {
			if got := rt.Evaluate(a, tier); got.Verdict != VerdictAllow || !strings.HasPrefix(got.Rule, "fs.write[") {
				t.Errorf("tier %s: %+v = %+v, want allowed by the write entry", tier, a, got)
			}
		}
	}
	for _, p := range []string{filepath.Join(f.project, "app.sock"), "app.sock", "@app"} {
		got := rt.Evaluate(Action{Kind: ActionNetConnect, Path: p}, backend.TierLandlock)
		if got.Verdict != VerdictRefused || got.Rule != HostSocketsRule {
			t.Errorf("%q = %+v, want refused/%s", p, got, HostSocketsRule)
		}
	}
	broker := "/run/user/1000/tego-dns/dns.sock"
	granted := *rt
	granted.Net = append(slices.Clone(rt.Net), NetRule{Raw: "unix:" + broker, Proto: ProtoUnix, UnixPath: broker,
		Static: true, Verdict: VerdictAllow, Runtime: DNSBrokerGrant})
	if got := granted.Evaluate(Action{Kind: ActionNetConnect, Path: broker}, backend.TierLandlock); got.Verdict != VerdictAllow ||
		got.Rule != granted.Net[len(granted.Net)-1].RuleName() {
		t.Errorf("tego's DNS broker endpoint = %+v, want allowed by its runtime grant", got)
	}
}
