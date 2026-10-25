// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// heldContract is a contract pinned to tier landlock with the given fs section body.
func heldContract(fs string) string {
	return "version: 0\nname: held\ncommand: [python]\ntier: landlock\nfs:\n" + fs
}

// nestedPaths are the paths of a table's nested targets.
func nestedPaths(rt *RuleTable) []string {
	var out []string
	for _, n := range rt.Reads.Nested {
		out = append(out, n.Path)
	}
	return out
}

// TestHeldReadsTriggerPerTargetKind holds ADR 0069 D1's trigger to each kind of deny_read target: a declared entry,
// a file a declared glob expanded to, a built-in entry and a .env file the scan found are nested when a write entry
// covers them and not otherwise, and auto holds reads at tier landlock exactly when one is nested.
func TestHeldReadsTriggerPerTargetKind(t *testing.T) {
	f := newFixture(t)
	gcloud := filepath.Join(f.home, ".config", "gcloud")
	if err := os.MkdirAll(gcloud, 0o700); err != nil {
		t.Fatal(err)
	}
	// The contract lies in f.project, which no write entry may cover (ADR 0059): the scanned .env is app/'s.
	key, env := filepath.Join(f.project, "secrets", "key.pem"), filepath.Join(f.project, "app", ".env")
	if err := os.MkdirAll(filepath.Dir(env), 0o755); err != nil {
		t.Fatal(err)
	}
	f.file(env, "SECRET=1", 0o600)
	for _, tc := range []struct {
		name, fs string
		nested   []string // paths that must be nested
		not      []string // paths that must not be
	}{
		{"declared entry nested", "  write: [\"secrets/\"]\n  deny_read: [\"secrets/key.pem\"]\n", []string{key}, []string{env}},
		{"declared entry outside", "  write: [\"out/\"]\n  deny_read: [\"secrets/key.pem\"]\n", nil, []string{key, env}},
		{"glob expansion nested", "  write: [\"secrets/\"]\n  deny_read: [\"secrets/*.pem\"]\n", []string{key}, nil},
		{"glob expansion outside", "  write: [\"out/\"]\n  deny_read: [\"secrets/*.pem\"]\n", nil, []string{key}},
		{"built-in entry nested", "  write: [\"~/.config\"]\n", []string{gcloud}, nil},
		{"built-in entry outside", "  write: [\"out/\"]\n", nil, []string{gcloud}},
		{"scanned .env nested", "  write: [\"app/\"]\n", []string{env}, nil},
		{"scanned .env outside", "  write: [\"config/\"]\n", nil, []string{env}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rt, _ := f.compile(f.load(heldContract(tc.fs)))
			got := nestedPaths(rt)
			for _, p := range tc.nested {
				if !slices.Contains(got, p) {
					t.Errorf("%s not nested: %q", p, got)
				}
			}
			for _, p := range tc.not {
				if slices.Contains(got, p) {
					t.Errorf("%s nested: %q", p, got)
				}
			}
			if want := len(got) > 0; rt.ReadsHeldAt(backend.TierLandlock) != want {
				t.Errorf("auto with nested %q: held at landlock %v", got, !want)
			}
			if rt.ReadsHeldAt(backend.TierCgroup) || rt.ReadsHeldAt(backend.TierBPFLSM) {
				t.Error("auto holds reads at a root tier, whose kernel refuses a nested target itself")
			}
		})
	}
}

// TestHeldReadsValues holds the three values of fs.reads at each tier (ADR 0069 D1): held at every enforcing tier,
// auto at tier landlock while a target is nested, direct never, and no records-only run.
func TestHeldReadsValues(t *testing.T) {
	f := newFixture(t)
	for _, tc := range []struct {
		reads                   string
		landlock, cgroup, bpf   bool
		whyLandlock, whyRoot    string
		warns                   string
		unenforcedWarnsAtTarget bool
	}{
		{"", true, false, false, ReadsWhyNested, ReadsWhyKernel, CodeHeldReads, false},
		{"auto", true, false, false, ReadsWhyNested, ReadsWhyKernel, CodeHeldReads, false},
		{"held", true, true, true, ReadsWhyContract, ReadsWhyContract, CodeHeldReads, false},
		{"direct", false, false, false, ReadsWhyDirect, ReadsWhyDirect, CodeUnenforced, true},
	} {
		t.Run("reads="+tc.reads, func(t *testing.T) {
			fs := "  write: [\"secrets/\"]\n  deny_read: [\"secrets/key.pem\"]\n"
			if tc.reads != "" {
				fs = "  reads: " + tc.reads + "\n" + fs
			}
			rt, ds := f.compile(f.load(heldContract(fs)))
			if got := [3]bool{rt.ReadsHeldAt(backend.TierLandlock), rt.ReadsHeldAt(backend.TierCgroup), rt.ReadsHeldAt(backend.TierBPFLSM)}; got != [3]bool{tc.landlock, tc.cgroup, tc.bpf} {
				t.Errorf("held at landlock, cgroup, bpflsm = %v", got)
			}
			if rt.ReadsHeldAt(backend.TierObserve) || rt.ReadsWhy(backend.TierObserve) != ReadsWhyRecordsOnly {
				t.Error("a records-only run holds its reads")
			}
			if got := rt.ReadsWhy(backend.TierLandlock); got != tc.whyLandlock {
				t.Errorf("why at landlock %q, want %q", got, tc.whyLandlock)
			}
			if got := rt.ReadsWhy(backend.TierCgroup); got != tc.whyRoot {
				t.Errorf("why at cgroup %q, want %q", got, tc.whyRoot)
			}
			if !slices.ContainsFunc(ds, func(d Diagnostic) bool { return d.Code == tc.warns }) {
				t.Errorf("no %s diagnostic:\n%s", tc.warns, render(ds))
			}
			unenforced := slices.ContainsFunc(ds, func(d Diagnostic) bool {
				return d.Code == CodeUnenforced && strings.Contains(d.Message, "key.pem is unenforced")
			})
			if unenforced != tc.unenforcedWarnsAtTarget {
				t.Errorf("unenforced warning at the target %v, want %v:\n%s", unenforced, tc.unenforcedWarnsAtTarget, render(ds))
			}
			if rt.NeedsOpenDeputy() != rt.ReadsHeld() {
				t.Errorf("NeedsOpenDeputy %v with reads held %v", rt.NeedsOpenDeputy(), rt.ReadsHeld())
			}
		})
	}
}

// TestHeldReadsNoNestedTargetHoldsNothing: auto with nothing nested reads direct, prints no reads line and needs no
// deputy, so a contract that keeps its secrets outside its write entries pays nothing.
func TestHeldReadsNoNestedTargetHoldsNothing(t *testing.T) {
	f := newFixture(t)
	rt, ds := f.compile(f.load(heldContract("  write: [\"out/\"]\n  deny_read: [\"secrets/key.pem\"]\n")))
	if rt.ReadsHeld() || rt.NeedsOpenDeputy() || rt.ReadsWhy(backend.TierLandlock) != ReadsWhyNoneNested {
		t.Fatalf("held %v, deputy %v, why %q", rt.ReadsHeld(), rt.NeedsOpenDeputy(), rt.ReadsWhy(backend.TierLandlock))
	}
	if slices.ContainsFunc(ds, func(d Diagnostic) bool { return d.Code == CodeHeldReads }) {
		t.Errorf("held-reads diagnostic for a table that holds nothing:\n%s", render(ds))
	}
	var b bytes.Buffer
	if err := PrintRuleTable(&b, rt); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(b.String(), "reads     ") {
		t.Errorf("reads line printed for a table that holds nothing:\n%s", b.String())
	}
}

// TestHeldReadsMergeOrder holds fs.reads' merge row (ADR 0065, ADR 0069 D1): held over auto over direct, direct
// counting only from the top-level contract; a profile's direct is ignored with profile-cannot-loosen.
func TestHeldReadsMergeOrder(t *testing.T) {
	f := newFixture(t)
	for _, tc := range []struct {
		profile, contract string
		want              ReadsMode
		loosenWarned      bool
	}{
		{"held", "auto", ReadsHeld, false},
		{"held", "", ReadsHeld, false},
		{"auto", "held", ReadsHeld, false},
		{"held", "direct", ReadsDirect, false},
		{"direct", "", ReadsAuto, true},
		{"direct", "auto", ReadsAuto, true},
	} {
		t.Run(tc.profile+"/"+tc.contract, func(t *testing.T) {
			name := "reads-" + tc.profile + "-" + tc.contract
			src := writeProfile(t, f, name, "version: 0\nfs:\n  reads: "+tc.profile+"\n")
			body := "version: 0\nname: held\nextends: " + name + "\ncommand: [python]\ntier: landlock\nfs:\n  write: [\"secrets/\"]\n"
			if tc.contract != "" {
				body += "  reads: " + tc.contract + "\n"
			}
			path := filepath.Join(f.project, "agent.yaml")
			f.file(path, body, 0o644)
			c, lds, err := Load(path, src)
			if err != nil {
				t.Fatalf("load: %v\n%s", err, render(lds))
			}
			rt, _ := f.compile(c)
			if rt.Reads.Mode != tc.want {
				t.Errorf("merged fs.reads %q, want %q", rt.Reads.Mode, tc.want)
			}
			warned := slices.ContainsFunc(lds, func(d Diagnostic) bool { return d.Code == CodeProfileCannotLoosen })
			if warned != tc.loosenWarned {
				t.Errorf("profile-cannot-loosen %v, want %v:\n%s", warned, tc.loosenWarned, render(lds))
			}
		})
	}
}

// TestHeldReadsSchema: fs.reads takes auto, held or direct, and nothing else.
func TestHeldReadsSchema(t *testing.T) {
	f := newFixture(t)
	path := filepath.Join(f.project, "agent.yaml")
	f.file(path, heldContract("  reads: always\n  write: [\"out/\"]\n"), 0o644)
	if _, ds, err := Load(path, f.profiles()); err == nil && !slices.ContainsFunc(ds, func(d Diagnostic) bool { return d.Code == CodeSchema }) {
		t.Fatalf("fs.reads: always loaded:\n%s", render(ds))
	}
}

// TestHeldReadsRefuseIOUringAndSetuid: fs.reads: held is refused together with io_uring: true or setuid: true (ADR
// 0069 D2, HR-2 and R2-1), as gate and ask are. A ring's IORING_OP_OPENAT never reaches the filter,
// so the held floor would never see the open a root tier's plane admits, and the run's fs.deny_read.created_later row
// would claim a refusal no mechanism makes. setuid: true leaves no_new_privs unset at a root tier, so a task may hold
// other credentials than the ones the open deputy was exec'd with, and the deputy would complete its reads as someone
// else (sudo reading the 0440 /etc/sudoers answered EACCES, a lower euid's open answered as the agent's). auto, which
// holds reads only at tier landlock where io_uring stays ENOSYS and no_new_privs is mandatory, is not refused.
func TestHeldReadsRefuseIOUringAndSetuid(t *testing.T) {
	f := newFixture(t)
	path := filepath.Join(f.project, "agent.yaml")
	const ioUring, setuid = "fs.reads: held requires io_uring disabled", "fs.reads: held requires setuid disabled"
	for _, tc := range []struct {
		body string
		want string // the refusal's message, or "" for none
	}{
		{"tier: bpflsm\nio_uring: true\nfs:\n  reads: held\n  write: [\"out/\"]\n", ioUring},
		{"tier: cgroup\nio_uring: true\nfs:\n  reads: held\n  write: [\"out/\"]\n", ioUring},
		{"io_uring: true\nfs:\n  reads: held\n  write: [\"out/\"]\n", ioUring},
		{"tier: bpflsm\nio_uring: true\nfs:\n  reads: auto\n  write: [\"secrets/\"]\n  deny_read: [\"secrets/key.pem\"]\n", ""},
		{"tier: bpflsm\nio_uring: true\nfs:\n  write: [\"out/\"]\n", ""},
		{"tier: bpflsm\nfs:\n  reads: held\n  write: [\"out/\"]\n", ""},
		{"tier: bpflsm\nsetuid: true\nfs:\n  reads: held\n  write: [\"out/\"]\n", setuid},
		{"tier: cgroup\nsetuid: true\nfs:\n  reads: held\n  write: [\"out/\"]\n", setuid},
		{"setuid: true\nfs:\n  reads: held\n  write: [\"out/\"]\n", setuid},
		{"tier: bpflsm\nsetuid: true\nfs:\n  reads: auto\n  write: [\"secrets/\"]\n  deny_read: [\"secrets/key.pem\"]\n", ""},
		{"setuid: true\nfs:\n  reads: auto\n  write: [\"secrets/\"]\n  deny_read: [\"secrets/key.pem\"]\n", ""},
		{"tier: cgroup\nsetuid: true\nfs:\n  reads: direct\n  write: [\"out/\"]\n", ""},
	} {
		f.file(path, "version: 0\nname: held\ncommand: [python]\n"+tc.body, 0o644)
		_, ds, err := Load(path, f.profiles())
		for _, msg := range []string{ioUring, setuid} {
			got := err != nil && slices.ContainsFunc(ds, func(d Diagnostic) bool {
				return d.Code == CodeSchema && strings.Contains(d.Message, msg)
			})
			if got != (msg == tc.want) {
				t.Errorf("%q: refused with %q %v, want %v (err %v):\n%s", tc.body, msg, got, msg == tc.want, err, render(ds))
			}
		}
	}
}

// TestHeldReadsPrint holds compile's print of held reads (ADR 0069 D1): which targets are held and why, the cost, the
// residual, and the nested entry's note.
func TestHeldReadsPrint(t *testing.T) {
	f := newFixture(t)
	for _, tc := range []struct {
		reads string
		want  []string
	}{
		{"auto", []string{"reads     held at tier landlock (fs.reads: auto: " + filepath.Join(f.project, "secrets", "key.pem") + " in ",
			HeldReadCost, "landlock_* answer ENOSYS", "moved or hard-linked", "held(landlock: parent writable)"}},
		{"held", []string{"reads     held at every tier (fs.reads: held); " + HeldReadCost, "held(landlock: parent writable)"}},
		{"direct", []string{"reads     direct (fs.reads: direct): ", "unenforced(landlock: parent writable)"}},
	} {
		t.Run(tc.reads, func(t *testing.T) {
			rt, _ := f.compile(f.load(heldContract("  reads: " + tc.reads + "\n  write: [\"secrets/\"]\n  deny_read: [\"secrets/key.pem\"]\n")))
			var b bytes.Buffer
			if err := PrintRuleTable(&b, rt); err != nil {
				t.Fatal(err)
			}
			for _, w := range tc.want {
				if !strings.Contains(b.String(), w) {
					t.Errorf("print lacks %q:\n%s", w, b.String())
				}
			}
		})
	}
}

// TestHeldReadsPrintTheNamesTheyApply: the name entries (ADR 0043) apply at tiers cgroup and bpflsm in every build;
// a table whose runs hold their reads at tier landlock prints them as applied there by held reads, never "tier landlock
// keeps the expansion" beside a reads line that says a file a name rule covers is refused whenever it was made; a
// table that holds nothing there says the expansion decides at tier landlock.
func TestHeldReadsPrintTheNamesTheyApply(t *testing.T) {
	f := newFixture(t)
	for _, tc := range []struct {
		name, body string
		want, not  []string
	}{
		{"held at bpflsm", "tier: bpflsm\nfs:\n  reads: held\n  write: [\"out/\"]\n  deny_read: [\"config/.env*\"]\n",
			[]string{"names     3 entries, beneath their scopes at tiers cgroup and bpflsm, files created later included; tier landlock keeps the expansion"},
			[]string{"no tier applies them yet", "not enforced"}},
		{"held at landlock alone", "fs:\n  write: [\"secrets/\"]\n  deny_read: [\"secrets/key.pem\", \"config/.env*\"]\n",
			[]string{"files created later included; at tier landlock held reads (fs.reads: auto) refuse", "made during the run included"},
			[]string{"no tier applies them yet", "not enforced"}},
		{"held nowhere", "fs:\n  write: [\"out/\"]\n  deny_read: [\"config/.env*\"]\n",
			[]string{"files created later included; tier landlock keeps the expansion"}, []string{"held reads (fs.reads", "not enforced"}},
		{"held everywhere", "fs:\n  reads: held\n  write: [\"out/\"]\n  deny_read: [\"config/.env*\"]\n",
			[]string{"at tier landlock held reads (fs.reads: held) refuse"}, []string{"not enforced"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := os.MkdirAll(filepath.Join(f.project, "config"), 0o755); err != nil {
				t.Fatal(err)
			}
			// Every tier built, so an auto table can land at landlock and at the root tiers alike.
			rt, _ := f.compile(f.load("version: 0\nname: held\ncommand: [python]\n"+tc.body),
				WithTiers(backend.TierLandlock, backend.TierCgroup, backend.TierBPFLSM))
			var b bytes.Buffer
			if err := PrintRuleTable(&b, rt); err != nil {
				t.Fatal(err)
			}
			for _, w := range tc.want {
				if !strings.Contains(b.String(), w) {
					t.Errorf("print lacks %q:\n%s", w, b.String())
				}
			}
			for _, w := range tc.not {
				if strings.Contains(b.String(), w) {
					t.Errorf("print says %q:\n%s", w, b.String())
				}
			}
		})
	}
}

// TestHeldReadsGlobWarningSaysWhereLaterFilesAreRefused: a deny_read glob's warning said "files created later are not
// covered" beside a reads line saying such a file is refused whenever it was made. Where the run holds its reads the
// warning now says a matching file made during the run is refused there, and where it does not, not covered (the
// class of review RCHR-2).
func TestHeldReadsGlobWarningSaysWhereLaterFilesAreRefused(t *testing.T) {
	f := newFixture(t)
	if err := os.MkdirAll(filepath.Join(f.project, "config"), 0o755); err != nil {
		t.Fatal(err)
	}
	f.file(filepath.Join(f.project, "config", "a.pem"), "k", 0o600)
	for _, tc := range []struct {
		name, body, want string
	}{
		{"held at bpflsm", "tier: bpflsm\nfs:\n  reads: held\n  write: [\"out/\"]\n  deny_read: [\"config/*.pem\"]\n",
			"fs.deny_read \"config/*.pem\" covers the 1 file(s) that exist now; a matching file made during the run is refused at tier bpflsm, where the run holds its reads (fs.reads: held)"},
		{"held at landlock alone", "fs:\n  write: [\"secrets/\"]\n  deny_read: [\"secrets/key.pem\", \"config/*.key\"]\n",
			"fs.deny_read \"config/*.key\" matches nothing now; a matching file made during the run is refused at tier landlock, where the run holds its reads (fs.reads: auto), and not covered at tiers cgroup, bpflsm"},
		{"held nowhere", "fs:\n  write: [\"out/\"]\n  deny_read: [\"config/*.pem\"]\n",
			"fs.deny_read \"config/*.pem\" covers the 1 file(s) that exist now; files created later are not covered"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, ds := f.compile(f.load("version: 0\nname: held\ncommand: [python]\n"+tc.body),
				WithTiers(backend.TierLandlock, backend.TierCgroup, backend.TierBPFLSM))
			if !slices.ContainsFunc(ds, func(d Diagnostic) bool { return d.Code == CodeGlobNoMatch && d.Message == tc.want }) {
				t.Errorf("no %s warning %q:\n%s", CodeGlobNoMatch, tc.want, render(ds))
			}
		})
	}
}

// TestHeldReadsGlobWarningKeepsTheNameEntry: a glob whose name entry the caps kept says its later files are covered at
// tiers cgroup and bpflsm (ADR 0043); where held reads hold at tier landlock as well (ADR 0069) the warning adds tier
// landlock rather than saying "not at tier landlock", and where they do not it keeps the name entry's sentence.
func TestHeldReadsGlobWarningKeepsTheNameEntry(t *testing.T) {
	f := newFixture(t)
	if err := os.MkdirAll(filepath.Join(f.project, "config", "a"), 0o755); err != nil {
		t.Fatal(err)
	}
	f.file(filepath.Join(f.project, "config", "a", "token.json"), "t", 0o600)
	for _, tc := range []struct {
		name, body, want string
	}{
		{"held at landlock", "fs:\n  write: [\"secrets/\"]\n  deny_read: [\"secrets/key.pem\", \"config/*/token.json\"]\n",
			"fs.deny_read \"config/*/token.json\" covers the 1 file(s) that exist now; files created later are covered at tiers cgroup and bpflsm by its name entry, and at tier landlock, where the run holds its reads (fs.reads: auto)"},
		{"held nowhere", "fs:\n  write: [\"out/\"]\n  deny_read: [\"config/*/token.json\"]\n",
			"fs.deny_read \"config/*/token.json\" covers the 1 file(s) that exist now; files created later are covered at tiers cgroup and bpflsm by its name entry, not at tier landlock"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, ds := f.compile(f.load("version: 0\nname: held\ncommand: [python]\n"+tc.body),
				WithTiers(backend.TierLandlock, backend.TierCgroup, backend.TierBPFLSM))
			if !slices.ContainsFunc(ds, func(d Diagnostic) bool { return d.Code == CodeGlobNoMatch && d.Message == tc.want }) {
				t.Errorf("no %s warning %q:\n%s", CodeGlobNoMatch, tc.want, render(ds))
			}
		})
	}
}

// TestHeldReadsNameRules holds what a held read is refused by beyond the table's rows (ADR 0069 D3 (c)): the built-in
// .env names over the scan's roots, outside the dependency directories, and D3's exemption; and none of the built-in
// rules once the built-in list is off.
func TestHeldReadsNameRules(t *testing.T) {
	f := newFixture(t)
	rt, _ := f.compile(f.load(heldContract("  reads: held\n  write: [\"out/\"]\n")))
	if len(rt.Reads.Names) != 2 || len(rt.Reads.Names[0].Scopes) == 0 || rt.Reads.Names[0].Scopes[0].Canonical != f.project {
		t.Fatalf("built-in .env names %+v", rt.Reads.Names)
	}
	if !slices.ContainsFunc(rt.Reads.Patterns, func(p DenyReadPattern) bool { return strings.HasSuffix(p.Rule, "/.ssh]") }) {
		t.Errorf("no built-in home pattern among %+v", rt.Reads.Patterns)
	}
	off, _ := f.compile(f.load(heldContract("  reads: held\n  write: [\"out/\"]\n  deny_read: []\n")))
	if len(off.Reads.Names) != 0 || slices.ContainsFunc(off.Reads.Patterns, func(p DenyReadPattern) bool { return strings.HasSuffix(p.Rule, "/.ssh]") }) {
		t.Errorf("deny_read: [] keeps built-in rules: names %+v patterns %+v", off.Reads.Names, off.Reads.Patterns)
	}
}
