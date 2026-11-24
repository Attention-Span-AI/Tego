// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

func baselineTopologyMachine(t *testing.T, f *fixture, key config.BaselineKey, path string) *config.Machine {
	t.Helper()
	d := filepath.Join(f.root, "machine")
	if err := os.Mkdir(d, 0o700); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(d, "config.yaml")
	section, field, _ := strings.Cut(string(key), ".")
	f.file(p, "baseline:\n  "+section+":\n    "+field+": ["+strconvQuote(path)+"]\n", 0o600)
	m, ds, err := config.LoadSources(config.Sources{User: p}, f.home, os.Getuid(), config.TrustAbort)
	if err != nil {
		t.Fatalf("load machine: %v %v", err, ds)
	}
	m.LedgerRoot = f.machine.LedgerRoot
	return m
}

func strconvQuote(s string) string { return strconv.Quote(s) }

func TestBaselineTopologyHardLinks(t *testing.T) {
	for _, dir := range []bool{false, true} {
		t.Run(map[bool]string{false: "file", true: "directory"}[dir], func(t *testing.T) {
			f := newFixture(t)
			secret := filepath.Join(f.root, "secret")
			if err := os.Mkdir(secret, 0o700); err != nil {
				t.Fatal(err)
			}
			p := filepath.Join(secret, "token")
			f.file(p, "fixture", 0o600)
			if err := os.Link(p, filepath.Join(f.root, "alias")); err != nil {
				t.Fatal(err)
			}
			target := p
			if dir {
				target = secret
			}
			m := baselineTopologyMachine(t, f, config.BaselineDenyRead, target)
			c := f.load("version: 0\nname: topology\ncommand: [static-tool]\ntier: cgroup\n")
			rt, ds, err := Compile(c, m, f.opts()...)
			if err != nil {
				t.Fatalf("plane-capable compile: %v\n%s", err, render(ds))
			}
			for _, plane := range []string{"lsm", "fmod_ret"} {
				if err := rt.BaselineAt(backend.TierCgroup, plane); err != nil {
					t.Error(err)
				}
			}
			for _, cell := range []struct {
				tier  backend.Tier
				plane string
			}{{backend.TierLandlock, ""}, {backend.TierCgroup, "fanotify"}} {
				if err := rt.BaselineAt(cell.tier, cell.plane); err == nil {
					t.Errorf("%s/%s accepted outside hard link", cell.tier, cell.plane)
				}
			}
			if dir {
				found := false
				for _, r := range rt.FS {
					if r.Kind == FSDenyRead && r.Canonical() == p {
						found = true
					}
				}
				if !found {
					t.Fatal("linked descendant has no inode-pinned deny row")
				}
			}
			if err := rt.RecheckBaseline(); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(p); err != nil {
				t.Fatal(err)
			}
			f.file(p, "replacement", 0o600)
			if err := rt.RecheckBaseline(); err == nil {
				t.Fatal("replacement of target or linked descendant was accepted")
			}
		})
	}
}

func TestBaselineTopologyUnknownMountsAndCutInventory(t *testing.T) {
	f := newFixture(t)
	secret := filepath.Join(f.root, "secret")
	if err := os.Mkdir(secret, 0o700); err != nil {
		t.Fatal(err)
	}
	m := baselineTopologyMachine(t, f, config.BaselineDenyRead, secret)
	c := f.load("version: 0\nname: topology\ncommand: [static-tool]\ntier: landlock\n")
	_, ds, err := Compile(c, m, f.opts(WithMountInfo(""))...)
	if err == nil || !strings.Contains(render(ds), "baseline") {
		t.Fatalf("unknown topology accepted: %v %s", err, render(ds))
	}
	structured := false
	for _, d := range ds {
		if p := d.BaselinePlacement; p != nil {
			structured = true
			if p.Owner.Home != f.home || p.Entry == nil || len(p.Entry.Coverage) != 5 {
				t.Fatalf("placement diagnostic lost owner/coverage: %+v", p)
			}
			for _, row := range p.Entry.Coverage {
				if row.Held != "refuse-launch" {
					t.Fatalf("unknown topology received coverage %+v", row)
				}
			}
		}
	}
	if !structured {
		t.Fatal("failed compile lost per-entry refuse-launch coverage")
	}
	deep := secret
	for range maxDenyWriteLinkDepth + 2 {
		deep = filepath.Join(deep, "d")
		if err := os.Mkdir(deep, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if _, ds, err := Compile(c, m, f.opts()...); err == nil || !strings.Contains(render(ds), "inventory") {
		t.Fatalf("cut inventory accepted: %v %s", err, render(ds))
	}
}

func TestBaselineR10ProtectsDifferentOwnerLayer(t *testing.T) {
	for _, present := range []bool{false, true} {
		t.Run(map[bool]string{false: "absent", true: "present"}[present], func(t *testing.T) {
			f := newFixture(t)
			owner := filepath.Join(f.root, "owner")
			if err := os.MkdirAll(filepath.Join(owner, ".tego"), 0o700); err != nil {
				t.Fatal(err)
			}
			layer := filepath.Join(owner, ".tego", "config.yaml")
			if present {
				f.file(layer, "version: 0\n", 0o600)
			}
			m := *f.machine
			m.Home = f.home
			for _, grant := range []string{owner, layer} {
				c := f.load("version: 0\nname: owner-layer\ncommand: [static-tool]\nfs:\n  write: [" + strconvQuote(grant) + "]\n")
				if _, ds, err := Compile(c, &m, f.opts(WithHome(owner), WithChainAnchor(filepath.Join(f.home, ".tego", "chain.log")))...); err == nil || !strings.Contains(render(ds), "machine config") {
					t.Fatalf("owner layer grant %s accepted: %v\n%s", grant, err, render(ds))
				}
			}
			beside := filepath.Join(owner, "project")
			if err := os.Mkdir(beside, 0o700); err != nil {
				t.Fatal(err)
			}
			c := f.load("version: 0\nname: owner-layer\ncommand: [static-tool]\nfs:\n  write: [" + strconvQuote(beside) + "]\n")
			if _, ds, err := Compile(c, &m, f.opts(WithHome(owner), WithChainAnchor(filepath.Join(f.home, ".tego", "chain.log")))...); err != nil {
				t.Fatalf("ordinary owner project: %v\n%s", err, render(ds))
			}
		})
	}
}

func TestBaselineTopologyOrdinaryMountLayouts(t *testing.T) {
	var cases []struct{ Name, Home, HomeTarget, Project string }
	data, err := os.ReadFile("testdata/mountcompat/cases.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &cases); err != nil {
		t.Fatal(err)
	}
	wantRefused := map[string]int{"desktop": 0, "atomic": 4, "snap-ubuntu": 0, "docker": 2, "toolbox": 4, "wsl2": 2}
	checked, refused := 0, 0
	for _, tc := range cases {
		t.Run(tc.Name, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join("testdata/mountcompat", tc.Name+".mountinfo"))
			if err != nil {
				t.Fatal(err)
			}
			mt, err := ParseMountTableStrict([]byte(strings.ReplaceAll(string(data), "{{ROOT}}", "/fixture")))
			if err != nil {
				t.Fatal(err)
			}
			home := tc.Home
			if tc.HomeTarget != "" {
				home = tc.HomeTarget
			}
			got := 0
			for _, raw := range []string{filepath.Join(home, ".ssh"), filepath.Join(tc.Project, ".env")} {
				p := filepath.Join("/fixture", raw)
				aliases, ok := mt.TreeAliases(p)
				if !ok {
					t.Fatal("unplaced modeled target", p)
				}
				parts, ok := mt.DetachedParts(p)
				if !ok {
					t.Fatal("unplaced modeled detached parts", p)
				}
				m, _, ok := mt.t.lookup(p)
				if !ok {
					t.Fatal("missing mount", p)
				}
				for _, key := range []config.BaselineKey{config.BaselineDenyRead, config.BaselineDenyWrite} {
					e := BaselineRule{ResolvedBaselineEntry: config.ResolvedBaselineEntry{BaselineEntry: config.BaselineEntry{Key: key, Value: raw}, Target: p, State: config.LayerPresent}, topology: baselineTopologyFacts{aliases: aliases, detached: parts, caseExact: m.fstype != "9p"}}
					rt := &RuleTable{Contract: &Contract{}, Baseline: &BaselineTable{Applied: true, Entries: []BaselineRule{e}}}
					for _, cell := range []struct {
						tier  backend.Tier
						plane string
					}{{backend.TierLandlock, ""}, {backend.TierCgroup, "lsm"}, {backend.TierCgroup, "fmod_ret"}, {backend.TierCgroup, "fanotify"}, {backend.TierBPFLSM, "lsm"}} {
						checked++
						if err := rt.BaselineAt(cell.tier, cell.plane); err != nil {
							got++
							refused++
						}
					}
				}
			}
			if got != wantRefused[tc.Name] {
				t.Fatalf("%d refused modeled cells, want %d", got, wantRefused[tc.Name])
			}
			t.Logf("%s: 2 targets x 2 filesystem keys x 5 mechanism cells: %d held, %d refused; known read aliases and Windows-drive case uncertainty are explicit; outside-all-grant writes remain refused by default", tc.Name, 20-got, got)
		})
	}
	if checked != 120 || refused != 12 {
		t.Fatalf("checked=%d refused=%d; want120/12", checked, refused)
	}
}

func TestBaselineDenyWriteOutsideGrantRetainsMetadataIdentity(t *testing.T) {
	f := newFixture(t)
	secret := filepath.Join(f.root, "write-secret")
	f.file(secret, "fixture", 0o600)
	m := baselineTopologyMachine(t, f, config.BaselineDenyWrite, secret)
	c := f.load("version: 0\nname: baseline-write\ncommand: [static-tool]\ntier: cgroup\nfs: {assurance: kernel}\n")
	rt, ds, err := Compile(c, m, f.opts()...)
	if err != nil {
		t.Fatalf("compile: %v\n%s", err, render(ds))
	}
	if !rt.HasBaselineDenyWriteAt(secret) || !slices.ContainsFunc(rt.DenyWrite, func(r FSRule) bool { return r.Kind == FSDenyWrite && r.Canonical() == secret && !r.Unenforced }) {
		t.Fatalf("missing protected metadata row: %+v", rt.DenyWrite)
	}
	if rt.DenyWriteNeedsPlane() {
		t.Fatal("outside-grant write row falsely forces plane")
	}
	if err := rt.BaselineAt(backend.TierLandlock, ""); err != nil {
		t.Fatal(err)
	}
	e := rt.Baseline.Entries[0]
	if err := rt.CheckBaselineIdentity(secret, e.Device, e.Inode); err != nil {
		t.Fatal(err)
	}
	if err := rt.CheckBaselineIdentity(secret, e.Device, e.Inode+1); err == nil {
		t.Fatal("descriptor for replacement target accepted")
	}
}

func TestBaselineSupervisorCannotInheritPlaneCoverage(t *testing.T) {
	f := newFixture(t)
	work := filepath.Join(f.root, "work")
	if err := os.Mkdir(work, 0o700); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(work, "secret")
	f.file(secret, "fixture", 0o600)
	m := baselineTopologyMachine(t, f, config.BaselineDenyRead, secret)
	c := f.load("version: 0\nname: baseline-supervised\ncommand: [static-tool]\ntier: cgroup\nfs:\n  write: [" + strconv.Quote(work) + "]\n")
	rt, ds, err := Compile(c, m, f.opts()...)
	if err != nil {
		t.Fatalf("compile: %v\n%s", err, render(ds))
	}
	if err := rt.BaselineAt(backend.TierCgroup, "lsm"); err != nil {
		t.Fatal(err)
	}
	rt.FSAsk = append(rt.FSAsk, FSRule{Kind: FSAsk, Path: filepath.Join(f.root, "unrelated")})
	if err := rt.BaselineAt(backend.TierCgroup, "lsm"); err == nil {
		t.Fatal("supervisor path reused plane read guarantee")
	}
}

func TestBaselineActualCoverageNeedsExecPinClaim(t *testing.T) {
	for _, restricted := range []bool{false, true} {
		c := &Contract{}
		if restricted {
			c.Exec = &ExecSection{Allow: []string{}}
		}
		rt := &RuleTable{Contract: c, Baseline: &BaselineTable{Applied: true, Entries: []BaselineRule{{ResolvedBaselineEntry: config.ResolvedBaselineEntry{BaselineEntry: config.BaselineEntry{Key: config.BaselineDenyExec, Value: "git push"}}}}}}
		for _, pinned := range []bool{false, true} {
			rows, err := rt.BaselineCoverageAt(backend.TierCgroup, "lsm", pinned)
			if err != nil || len(rows) != 1 {
				t.Fatalf("coverage: %v %v", rows, err)
			}
			want := "best-effort"
			if pinned {
				want = "conditional"
			}
			mode := "unrestricted"
			if restricted {
				mode = "restricted"
			}
			if rows[0].Held != want || rows[0].ImageMode != mode {
				t.Fatalf("pinned=%t restricted=%t: %+v", pinned, restricted, rows[0])
			}
		}
	}
}

func TestBaselineTopologyPreservesKernelWalk(t *testing.T) {
	for _, key := range []config.BaselineKey{config.BaselineDenyRead, config.BaselineDenyWrite} {
		t.Run(string(key), func(t *testing.T) {
			f := newFixture(t)
			real := filepath.Join(f.root, "real")
			if err := os.MkdirAll(filepath.Join(real, "sub"), 0o700); err != nil {
				t.Fatal(err)
			}
			f.file(filepath.Join(real, "secret"), "actual", 0o600)
			f.file(filepath.Join(f.root, "secret"), "decoy", 0o600)
			link := filepath.Join(f.root, "link")
			if err := os.Symlink(filepath.Join(real, "sub"), link); err != nil {
				t.Fatal(err)
			}
			raw := link + "/../secret"
			m := baselineTopologyMachine(t, f, key, raw)
			c := f.load("version: 0\nname: baseline-walk\ncommand: [static-tool]\ntier: cgroup\n")
			rt, ds, err := Compile(c, m, f.opts()...)
			if err != nil {
				t.Fatalf("compile: %v\n%s", err, render(ds))
			}
			found := false
			for _, r := range slices.Concat(rt.FS, rt.DenyWrite) {
				if r.Raw == raw {
					found = true
					if r.Canonical() != filepath.Join(real, "secret") {
						t.Fatalf("walk was lexically cleaned: %+v", r)
					}
				}
			}
			if !found {
				t.Fatal("baseline row was discarded")
			}
			if rt.Baseline.Entries[0].Expanded != raw {
				t.Fatal("declared walk spelling changed")
			}
			if err := rt.RecheckBaseline(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestBaselineAbsentSystemPlacementContexts(t *testing.T) {
	for _, tier := range []backend.Tier{backend.TierLandlock, backend.TierCgroup, backend.TierBPFLSM} {
		for _, covered := range []bool{false, true} {
			t.Run(string(tier)+"/write="+strconv.FormatBool(covered), func(t *testing.T) {
				f := newFixture(t)
				work := filepath.Join(f.root, "absent-parent")
				if err := os.Mkdir(work, 0o700); err != nil {
					t.Fatal(err)
				}
				fi, err := os.Stat(work)
				if err != nil {
					t.Fatal(err)
				}
				key, ok := fileKeyOf(fi)
				if !ok {
					t.Fatal("missing fixture identity")
				}
				c := f.load("version: 0\nname: absent-baseline\ncommand: [static-tool]\n")
				entry := BaselineRule{ResolvedBaselineEntry: config.ResolvedBaselineEntry{BaselineEntry: config.BaselineEntry{Key: config.BaselineDenyWrite, Value: work + "/missing", Sources: []config.Provenance{{Layer: config.LayerEtc, File: "/modeled/system.yaml", Line: 4}}}, Expanded: work + "/missing", State: config.LayerAbsent, Ancestor: work, Missing: "missing", Device: key.dev, Inode: key.ino}}
				rt := &RuleTable{Contract: c, EffectiveContract: c, Tier: tier, Reach: []backend.Tier{tier}, Baseline: &BaselineTable{Applied: true, Owner: config.BaselineOwner{UID: 4242, Home: f.home}, MountInfo: DefaultMountInfo, Entries: []BaselineRule{entry}}}
				if covered {
					rt.FS = []FSRule{{Kind: FSWrite, Path: work, Resolved: work}}
				}
				k := &compiler{c: c, m: f.machine, rt: rt, top: c.file, cpos: Pos{File: c.file, Line: 1}, o: compileOptions{mountInfo: DefaultMountInfo, home: f.home}}
				k.baselineTopology()
				if got := firstError(k.ds.list) != nil; got != covered {
					t.Fatalf("covered=%t: %v\n%s", covered, got, render(k.ds.list))
				}
				if !covered {
					for _, row := range rt.Baseline.Entries[0].Coverage {
						if row.Held != "conditional" || len(row.Operations) != 3 || strings.Contains(strings.Join(row.Operations, "; "), "metadata") {
							t.Fatalf("absent default-write refusal claimed present-inode metadata coverage: %+v", row)
						}
						if !strings.Contains(strings.Join(row.Limits, "; "), "no present inode") {
							t.Fatalf("absent write row lost its inode/metadata residual: %+v", row)
						}
					}
				}
				if covered {
					found := false
					for _, d := range k.ds.list {
						if p := d.BaselinePlacement; p != nil {
							found = true
							for _, row := range p.Entry.Coverage {
								if row.Held != "refuse-launch" {
									t.Fatalf("absent writable target got %+v", row)
								}
							}
						}
					}
					if !found {
						t.Fatal("all-refused compile lost placement rows")
					}
				}
			})
		}
	}
}

func TestBaselineAbsentSystemReadUsesAncestorGuard(t *testing.T) {
	f := newFixture(t)
	fi, err := os.Stat(f.root)
	if err != nil {
		t.Fatal(err)
	}
	id, ok := fileKeyOf(fi)
	if !ok {
		t.Fatal("missing fixture identity")
	}
	c := f.load("version: 0\nname: absent-system-read\ncommand: [static-tool]\n")
	missing := f.root + "/absent/secret"
	e := BaselineRule{ResolvedBaselineEntry: config.ResolvedBaselineEntry{BaselineEntry: config.BaselineEntry{Key: config.BaselineDenyRead, Value: missing, Sources: []config.Provenance{{Layer: config.LayerEtc, File: "/modeled/system.yaml", Line: 4}}}, Expanded: missing, State: config.LayerAbsent, Ancestor: f.root, Missing: "absent/secret", Device: id.dev, Inode: id.ino}}
	rt := &RuleTable{Contract: c, EffectiveContract: c, Tier: backend.TierCgroup, Reach: []backend.Tier{backend.TierCgroup}, Baseline: &BaselineTable{Applied: true, Owner: config.BaselineOwner{UID: 4242, Home: f.home}, MountInfo: DefaultMountInfo, Entries: []BaselineRule{e}}}
	k := &compiler{c: c, m: f.machine, rt: rt, top: c.file, cpos: Pos{File: c.file, Line: 1}, o: compileOptions{mountInfo: DefaultMountInfo, home: f.home, cwd: f.project}}
	b := &fsBuilder{k: k}
	b.declared([]string{missing}, "fs.deny_read", FSDenyRead, nil)
	k.baselineTopology()
	if err := firstError(k.ds.list); err != nil {
		t.Fatalf("supported absent read: %v\n%s", err, render(k.ds.list))
	}
	if len(rt.AbsentDenyRead) != 1 || rt.AbsentDenyRead[0].At != f.root+"/absent" {
		t.Fatalf("absent baseline row lost ancestor/name guard: %+v", rt.AbsentDenyRead)
	}
	for _, row := range rt.Baseline.Entries[0].Coverage {
		if row.Held != "conditional" {
			t.Fatalf("absent read got %+v", row)
		}
	}
	if err := rt.RecheckBaseline(); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(f.root+"/absent", 0o700); err != nil {
		t.Fatal(err)
	}
	if err := rt.RecheckBaseline(); err != nil {
		t.Fatalf("original ancestor/name guard still holds after partial parent appears: %v", err)
	}
	if err := os.WriteFile(missing, []byte("new target"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := rt.RecheckBaseline(); err == nil {
		t.Fatal("newly present target accepted before preparation")
	}
}

func TestBaselineRuntimeGrantsCannotReopen(t *testing.T) {
	f := newFixture(t)
	secret := filepath.Join(f.root, "runtime-secret")
	if err := os.Mkdir(secret, 0o700); err != nil {
		t.Fatal(err)
	}
	program := filepath.Join(secret, "program")
	f.file(program, "fixture", 0o700)
	m := baselineTopologyMachine(t, f, config.BaselineDenyRead, secret)
	c := f.load("version: 0\nname: runtime-baseline\ncommand: [static-tool]\ntier: cgroup\n")
	rt, ds, err := Compile(c, m, f.opts()...)
	if err != nil {
		t.Fatalf("compile: %v\n%s", err, render(ds))
	}
	oldFS := slices.Clone(rt.FS)
	rt.FS = append(rt.FS, FSRule{Path: program, Resolved: program, Kind: FSWrite, Runtime: HarnessStateGrant})
	if err := rt.ValidateBaselineFS(); err == nil || !strings.Contains(err.Error(), "baseline-conflict") {
		t.Fatalf("runtime grant reopened read refusal: %v", err)
	}
	rt.FS = oldFS
	rt.Exec = append(rt.Exec, ExecRule{Path: program, Resolved: program, Runtime: HarnessHookGrant, Verdict: VerdictAllow})
	if err := rt.BaselineAt(backend.TierLandlock, ""); err == nil {
		t.Fatal("runtime exec read grant reopened Landlock refusal")
	}
	if err := rt.BaselineAt(backend.TierCgroup, "lsm"); err != nil {
		t.Fatalf("active read-denying plane lost supported exec image: %v", err)
	}
	pins := rt.BaselineFiles()
	if len(pins) != 1 || pins[0].Path != secret || pins[0].Inode != rt.Baseline.Entries[0].Inode {
		t.Fatalf("adoption pin requirements lost target identity: %+v", pins)
	}
}

func TestBaselineDenyWriteOutsideGrantKeysLinkedDescendants(t *testing.T) {
	f := newFixture(t)
	secret := filepath.Join(f.root, "metadata-tree")
	if err := os.Mkdir(secret, 0o700); err != nil {
		t.Fatal(err)
	}
	child := filepath.Join(secret, "token")
	f.file(child, "fixture", 0o600)
	if err := os.Link(child, filepath.Join(f.root, "metadata-alias")); err != nil {
		t.Fatal(err)
	}
	m := baselineTopologyMachine(t, f, config.BaselineDenyWrite, secret)
	c := f.load("version: 0\nname: linked-metadata\ncommand: [static-tool]\ntier: cgroup\n")
	rt, ds, err := Compile(c, m, f.opts()...)
	if err != nil {
		t.Fatalf("compile: %v\n%s", err, render(ds))
	}
	if !slices.Contains(rt.DenyWriteLinked, child) {
		t.Fatalf("outside-grant linked descendant has no protected inode row: got %v, want %s", rt.DenyWriteLinked, child)
	}
	if err := rt.BaselineAt(backend.TierCgroup, "lsm"); err != nil {
		t.Fatalf("complete linked metadata placement: %v", err)
	}
	if err := rt.BaselineAt(backend.TierLandlock, ""); err != nil {
		t.Fatalf("redundant write-open refusal needs no metadata claim at Landlock: %v", err)
	}
}

func TestBaselineTopologyTargetKinds(t *testing.T) {
	f := newFixture(t)
	file := filepath.Join(f.root, "regular")
	f.file(file, "fixture", 0o600)
	dir := filepath.Join(f.root, "directory")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, link := range []struct{ path, target string }{{filepath.Join(f.root, "file-link"), file}, {filepath.Join(f.root, "dir-link"), dir}} {
		if err := os.Symlink(link.target, link.path); err != nil {
			t.Fatal(err)
		}
	}
	fifo := filepath.Join(f.root, "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	mkSocket(t, f.root, "/socket")
	mt, err := ParseMountTableStrict([]byte("1 0 0:1 / / rw - ext4 /dev/modeled rw\n"))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, path string
		refused    bool
	}{{"regular", file, false}, {"directory", dir, false}, {"symlink-file", filepath.Join(f.root, "file-link"), false}, {"symlink-directory", filepath.Join(f.root, "dir-link"), false}, {"fifo", fifo, true}, {"socket", filepath.Join(f.root, "socket"), true}} {
		t.Run(tc.name, func(t *testing.T) {
			// Config placement follows links before inventory; retain the original
			// spelling separately, as a real resolved baseline entry does.
			target, err := filepath.EvalSymlinks(tc.path)
			if err != nil {
				t.Fatal(err)
			}
			for _, key := range []config.BaselineKey{config.BaselineDenyRead, config.BaselineDenyWrite} {
				e := BaselineRule{ResolvedBaselineEntry: config.ResolvedBaselineEntry{BaselineEntry: config.BaselineEntry{Key: key, Value: tc.path}, Expanded: tc.path, Target: target, State: config.LayerPresent}}
				facts := inspectBaselineTopology(&e, mt, nil)
				if got := facts.problem != ""; got != tc.refused {
					t.Fatalf("%s %s refused=%t want=%t: %s", key, tc.name, got, tc.refused, facts.problem)
				}
			}
			t.Logf("%s: both filesystem keys refused=%t", tc.name, tc.refused)
		})
	}
}
