// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// All source forms reach the same final table. No conflict checker may expand
// or place a grant independently of the grant compiler.
func TestBaselineCompiledGrantConflicts(t *testing.T) {
	for _, key := range []config.BaselineKey{config.BaselineDenyRead, config.BaselineDenyWrite} {
		for _, grant := range []string{"write", "ask", "ask_read"} {
			if key == config.BaselineDenyWrite && grant == "ask_read" {
				continue
			}
			for _, spelling := range []string{"home", "relative", "trailing", "link", "absolute"} {
				for _, source := range []string{"direct", "profile", "extends"} {
					t.Run(fmt.Sprintf("%s/%s/%s/%s", key, grant, spelling, source), func(t *testing.T) {
						f := newFixture(t)
						target := filepath.Join(f.home, "data")
						nested := filepath.Join(target, "out")
						if err := os.MkdirAll(nested, 0o700); err != nil {
							t.Fatal(err)
						}
						alias := filepath.Join(f.project, "alias")
						if err := os.Symlink(target, alias); err != nil {
							t.Fatal(err)
						}
						relative, err := filepath.Rel(f.project, nested)
						if err != nil {
							t.Fatal(err)
						}
						raw := map[string]string{"home": "~/data/out", "relative": relative, "trailing": nested + "/", "link": alias + "/out", "absolute": nested}[spelling]
						fs := fmt.Sprintf("fs: {%s: [%q]}\n", grant, raw)
						body := "version: 0\nname: grant-conflict\ncommand: [static-tool]\ntier: landlock\n"
						profiles := mapSource{}
						switch source {
						case "direct":
							body += fs
						case "profile":
							profiles["grant"] = fs
							body += "extends: grant\n"
						case "extends":
							profiles["grant"] = fs
							profiles["child"] = "extends: grant\n"
							body += "extends: child\n"
						}
						c, ds, err := LoadBytes(filepath.Join(f.project, "agent.yaml"), []byte(body), profiles)
						if err != nil {
							t.Fatalf("load: %v %s", err, render(ds))
						}
						m := baselineTopologyMachine(t, f, key, target)
						_, ds, err = Compile(c, m, f.opts()...)
						if err == nil || !(hasCode(ds, CodeBaselineConflict) || grant == "ask_read" && hasCode(ds, CodeContradiction)) {
							t.Fatalf("compiled grant reopened baseline: %v\n%s", err, render(ds))
						}
						found := false
						for _, d := range ds {
							if d.Baseline != nil && (d.Baseline.GrantKey == "fs."+grant || strings.HasPrefix(d.Baseline.GrantKey, "fs."+grant+".")) && d.Baseline.Grant.File != "" {
								found = true
							}
						}
						if !found && grant != "ask_read" {
							t.Fatalf("missing compiled grant provenance: %s", render(ds))
						}
					})
				}
			}
		}
	}
}

func TestBaselineGrantGlobsStayRefused(t *testing.T) {
	for _, key := range []config.BaselineKey{config.BaselineDenyRead, config.BaselineDenyWrite} {
		for _, grant := range []string{"write", "ask", "ask_read"} {
			t.Run(string(key)+"/"+grant, func(t *testing.T) {
				f := newFixture(t)
				target := filepath.Join(f.home, "data")
				if err := os.MkdirAll(filepath.Join(target, "out"), 0o700); err != nil {
					t.Fatal(err)
				}
				c, ds, err := LoadBytes(filepath.Join(f.project, "agent.yaml"), []byte(fmt.Sprintf("version: 0\nname: glob\ncommand: [static-tool]\ntier: landlock\nfs: {%s: [%q]}\n", grant, target+"/*")), nil)
				if err == nil {
					_, ds, err = Compile(c, baselineTopologyMachine(t, f, key, target), f.opts()...)
				}
				if err == nil || !strings.Contains(render(ds), "glob") && !strings.Contains(render(ds), "literal") {
					t.Fatalf("unsupported glob was accepted: %v %s", err, render(ds))
				}
			})
		}
	}
}

func TestBaselineCompiledGrantDirections(t *testing.T) {
	for _, key := range []config.BaselineKey{config.BaselineDenyRead, config.BaselineDenyWrite} {
		for _, grant := range []string{"write", "ask", "ask_read"} {
			if key == config.BaselineDenyWrite && grant == "ask_read" {
				continue
			}
			for _, direction := range []string{"equal", "nested", "enclosing"} {
				t.Run(string(key)+"/"+grant+"/"+direction, func(t *testing.T) {
					f := newFixture(t)
					target := filepath.Join(f.home, "data", "target")
					if err := os.MkdirAll(filepath.Join(target, "out"), 0o700); err != nil {
						t.Fatal(err)
					}
					p := map[string]string{"equal": target, "nested": target + "/out", "enclosing": filepath.Dir(target)}[direction]
					c := f.load(fmt.Sprintf("version: 0\nname: directions\ncommand: [static-tool]\ntier: landlock\nfs: {reads: direct, %s: [%q]}\n", grant, p))
					_, ds, err := Compile(c, baselineTopologyMachine(t, f, key, target), f.opts()...)
					if err == nil {
						t.Fatalf("%s grant %s reopened %s", direction, grant, key)
					}
					if !hasCode(ds, CodeBaselineConflict) && !hasCode(ds, CodeBaselinePlacement) && !(grant == "ask_read" && hasCode(ds, CodeContradiction)) {
						t.Fatalf("wrong refusal: %s", render(ds))
					}
				})
			}
		}
	}
}

func TestBaselineExecGrantGlobStaysRefused(t *testing.T) {
	f := newFixture(t)
	target := filepath.Join(f.home, "data")
	if err := os.MkdirAll(target, 0o700); err != nil {
		t.Fatal(err)
	}
	image, err := os.ReadFile(filepath.Join(f.bin, "static-tool"))
	if err != nil {
		t.Fatal(err)
	}
	f.file(filepath.Join(target, "tool"), string(image), 0o700)
	m := baselineTopologyMachine(t, f, config.BaselineDenyRead, target)
	c := f.load(fmt.Sprintf("version: 0\nname: glob-exec\ncommand: [static-tool]\ntier: landlock\nexec: {allow: [static-tool, %q]}\n", target+"/to*"))
	_, ds, err := Compile(c, m, f.opts()...)
	if err == nil || !hasCode(ds, CodePathMissing) {
		t.Fatalf("unsupported exec grant glob was accepted: %v %s", err, render(ds))
	}
}

func TestBaselineCompiledLiveReadConflicts(t *testing.T) {
	for _, spelling := range []string{"home", "relative", "trailing", "link", "glob"} {
		t.Run(spelling, func(t *testing.T) {
			f := newFixture(t)
			target := filepath.Join(f.home, "data")
			if err := os.MkdirAll(target, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, filepath.Join(f.project, "alias")); err != nil {
				t.Fatal(err)
			}
			relative, err := filepath.Rel(f.project, target)
			if err != nil {
				t.Fatal(err)
			}
			raw := map[string]string{"home": "~/data", "relative": relative, "trailing": target + "/", "link": filepath.Join(f.project, "alias"), "glob": target + "/*"}[spelling]
			c := f.load(fmt.Sprintf("version: 0\nname: fence\ncommand: [static-tool]\ntier: landlock\nexec: {allow: [static-tool]}\nlive: {mode: adjustable, fence: {read: [%q]}}\n", raw))
			_, ds, err := Compile(c, baselineTopologyMachine(t, f, config.BaselineDenyRead, target), f.opts()...)
			if err == nil {
				t.Fatalf("live fence reopened baseline: %s", render(ds))
			}
			if spelling != "link" && spelling != "glob" && !hasCode(ds, CodeBaselineConflict) {
				t.Fatalf("missing baseline refusal: %s", render(ds))
			}
		})
	}
}

func TestBaselineAbsentWalkRetargetRefuses(t *testing.T) {
	for _, key := range []config.BaselineKey{config.BaselineDenyRead, config.BaselineDenyWrite} {
		t.Run(string(key), func(t *testing.T) {
			f := newFixture(t)
			first, second := filepath.Join(f.root, "first"), filepath.Join(f.root, "second")
			for _, p := range []string{first, second} {
				if err := os.Mkdir(p, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			link := filepath.Join(f.root, "link")
			if err := os.Symlink(first, link); err != nil {
				t.Fatal(err)
			}
			fi, err := os.Stat(first)
			if err != nil {
				t.Fatal(err)
			}
			id, ok := fileKeyOf(fi)
			if !ok {
				t.Fatal("missing fixture identity")
			}
			raw := link + "/new/secret"
			entry := BaselineRule{ResolvedBaselineEntry: config.ResolvedBaselineEntry{BaselineEntry: config.BaselineEntry{Key: key, Value: raw, Sources: []config.Provenance{{Layer: config.LayerEtc, File: "/modeled/system.yaml", Line: 4}}}, Expanded: raw, State: config.LayerAbsent, Ancestor: first, Missing: "new/secret", Device: id.dev, Inode: id.ino}}
			c := f.load("version: 0\nname: absent-walk\ncommand: [static-tool]\n")
			rt := &RuleTable{Contract: c, EffectiveContract: c, Tier: "cgroup", Reach: []backend.Tier{backend.TierCgroup}, Baseline: &BaselineTable{Applied: true, Owner: config.BaselineOwner{UID: os.Getuid(), Home: f.home}, MountInfo: DefaultMountInfo, Entries: []BaselineRule{entry}}}
			k := compiler{c: c, m: f.machine, rt: rt, top: c.file, o: compileOptions{home: f.home, cwd: f.project}}
			k.baselineTopology()
			if err := rt.RecheckBaseline(); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(filepath.Join(first, "new"), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := rt.RecheckBaseline(); err != nil {
				t.Fatalf("ordinary partial creation: %v", err)
			}
			if err := os.Remove(link); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(second, link); err != nil {
				t.Fatal(err)
			}
			if err := rt.RecheckBaseline(); err == nil || !strings.Contains(err.Error(), "walk changed") {
				t.Fatalf("retargeted absent baseline accepted: %v", err)
			}
		})
	}
}

func TestBaselineAbsentAliasesUseTargetScope(t *testing.T) {
	f := newFixture(t)
	ancestor, alias := filepath.Join(f.root, "store"), filepath.Join(f.root, "view")
	for _, p := range []string{ancestor, alias} {
		if err := os.Mkdir(p, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	mountInfo := filepath.Join(f.root, "mountinfo")
	f.file(mountInfo, fmt.Sprintf("1 0 8:1 / / rw - ext4 /dev/root rw\n2 1 8:1 %s %s rw - ext4 /dev/root rw\n", ancestor, alias), 0o600)
	mt, _, err := ReadMountSnapshot(mountInfo)
	if err != nil {
		t.Fatal(err)
	}
	entry := BaselineRule{ResolvedBaselineEntry: config.ResolvedBaselineEntry{BaselineEntry: config.BaselineEntry{Key: config.BaselineDenyWrite}, Expanded: ancestor + "/missing", State: config.LayerAbsent, Ancestor: ancestor, Missing: "missing"}}
	entry.topology = inspectBaselineTopology(&entry, mt, nil)
	if entry.topology.problem != "" {
		t.Fatal(entry.topology.problem)
	}
	if !slices.Equal(entry.topology.aliases, []string{alias + "/missing"}) {
		t.Fatalf("absent aliases cover ancestor: %v", entry.topology.aliases)
	}
	for _, p := range []string{alias + "/missing", alias + "/missing/out"} {
		if inside, _ := baselineGrantRelation(&entry, p); !inside {
			t.Fatalf("target alias not checked: %s", p)
		}
	}
	if inside, enclosing := baselineGrantRelation(&entry, alias+"/ordinary"); inside || enclosing {
		t.Fatal("unrelated sibling conflicts with absent target")
	}
}
