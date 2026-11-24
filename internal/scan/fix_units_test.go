// SPDX-License-Identifier: Apache-2.0

package scan

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/scan/result"
)

func TestUnitAbsentDropinsDoNotSpendDirectoryBudget(t *testing.T) {
	roots := []string{unitFixtureRoot(t), unitFixtureRoot(t), unitFixtureRoot(t), unitFixtureRoot(t)}
	for i := range 120 {
		writeSettings(t, roots[3], fmt.Sprintf("stock-%03d.service", i), []byte("[Service]\nExecStart=/usr/bin/true\n"))
	}
	u := collectUnits(t.Context(), roots, uint32(os.Getuid()), &contentBudget{remaining: 6 << 20})
	files := 0
	for _, s := range u.Sources {
		if s.State != "read" && s.State != "missing" {
			t.Errorf("source %s: %s %s", s.Path, s.State, s.Reason)
		}
		if strings.HasSuffix(s.Path, ".service") && s.State == "read" {
			files++
		}
	}
	if files != 120 {
		t.Fatalf("read %d of 120 unit files", files)
	}
}

func TestUnitAliasUsesSearchPathAndAllDropins(t *testing.T) {
	high, low := unitFixtureRoot(t), unitFixtureRoot(t)
	writeSettings(t, high, "actual.service", []byte("[Service]\nExecStart=claude\n"))
	writeSettings(t, low, "alias.service.d/20-reset.conf", []byte("[Service]\nExecStart=\nExecStart=codex\n"))
	// The link's target path is deliberately dangling. systemd resolves its name
	// through the load path, where the higher priority actual.service exists.
	if e := os.Symlink(filepath.Join(low, "missing", "actual.service"), filepath.Join(high, "alias.service")); e != nil {
		t.Fatal(e)
	}
	u := collectUnits(t.Context(), []string{high, low}, uint32(os.Getuid()), &contentBudget{remaining: 6 << 20})
	for _, s := range u.Sources {
		if s.State != "read" {
			t.Errorf("source %s: %s %s", s.Path, s.State, s.Reason)
		}
	}
	if len(u.Items) != 1 || u.Items[0].Name != "actual.service" || u.Items[0].Exec.Program != "codex-native" {
		t.Fatalf("alias merge: %+v", u.Items)
	}
}

func TestUnitAliasesRefuseOutsideRootsAndCycles(t *testing.T) {
	for _, kind := range []string{"outside", "cycle", "self", "type", "instance", "parent-link"} {
		t.Run(kind, func(t *testing.T) {
			root, outside := unitFixtureRoot(t), unitFixtureRoot(t)
			writeSettings(t, outside, "hidden.service", []byte("[Service]\nExecStart=codex\n"))
			target := filepath.Join(outside, "hidden.service")
			switch kind {
			case "self":
				target = filepath.Join(root, "a.service")
			case "parent-link":
				target = filepath.Join(root, "sub", "hidden.service")
				if e := os.Symlink(outside, filepath.Join(root, "sub")); e != nil {
					t.Fatal(e)
				}
			case "cycle":
				target = "b.service"
				if e := os.Symlink("a.service", filepath.Join(root, "b.service")); e != nil {
					t.Fatal(e)
				}
			case "type":
				target = "b.timer"
				writeSettings(t, root, "b.timer", []byte("[Timer]\nOnCalendar=daily\n"))
			case "instance":
				target = "b@other.service"
			}
			name := "a.service"
			if kind == "instance" {
				name = "a@one.service"
			}
			if e := os.Symlink(target, filepath.Join(root, name)); e != nil {
				t.Fatal(e)
			}
			budget := &contentBudget{remaining: 6 << 20}
			u := collectUnits(t.Context(), []string{root}, uint32(os.Getuid()), budget)
			if len(u.Items) != 0 {
				t.Fatalf("unsafe alias supplied evidence: %+v", u.Items)
			}
			refused := false
			for _, s := range u.Sources {
				if strings.HasSuffix(s.Path, name) && s.State == "not-read" {
					refused = true
				}
			}
			if !refused {
				t.Fatal("unsafe alias not reported")
			}
			if kind == "outside" && budget.files != 0 {
				t.Fatalf("outside alias used content budget: %d", budget.files)
			}
		})
	}
}

func TestUnitSpecificDropinBeatsHigherRootTypeDropin(t *testing.T) {
	high, low := unitFixtureRoot(t), unitFixtureRoot(t)
	writeSettings(t, low, "a.service", []byte("[Service]\nExecStart=claude\n"))
	writeSettings(t, high, "service.d/20-reset.conf", []byte("[Service]\nExecStart=\nExecStart=gemini\n"))
	writeSettings(t, low, "a.service.d/20-reset.conf", []byte("[Service]\nExecStart=\nExecStart=codex\n"))
	u := collectUnits(t.Context(), []string{high, low}, uint32(os.Getuid()), &contentBudget{remaining: 6 << 20})
	if len(u.Items) != 1 || u.Items[0].Exec.Program != "codex-native" {
		t.Fatalf("specificity precedence: %+v", u.Items)
	}
}

func unitFixtureRoot(t *testing.T) string {
	t.Helper()
	p := t.TempDir()
	if e := os.Chmod(p, 0700); e != nil {
		t.Fatal(e)
	}
	return p
}

// systemd v257 src/shared/dropin.c unit_file_find_dropin_paths searches each
// load-path root's exact/template/dash directories before the next root.
func TestUnitHigherRootPrefixDropinBeatsLowerExactDropin(t *testing.T) {
	high, low := unitFixtureRoot(t), unitFixtureRoot(t)
	writeSettings(t, low, "a-b.service", []byte("[Service]\nExecStart=claude\n"))
	writeSettings(t, high, "a-.service.d/20-reset.conf", []byte("[Service]\nExecStart=\nExecStart=gemini\n"))
	writeSettings(t, low, "a-b.service.d/20-reset.conf", []byte("[Service]\nExecStart=\nExecStart=codex\n"))
	u := collectUnits(t.Context(), []string{high, low}, uint32(os.Getuid()), &contentBudget{remaining: 6 << 20})
	if len(u.Items) != 1 || u.Items[0].Exec.Program != "gemini-native" {
		t.Fatalf("root precedence: %+v", u.Items)
	}
}

func TestUnitAliasPropagatesEnabledInstance(t *testing.T) {
	root := unitFixtureRoot(t)
	writeSettings(t, root, "actual@.service", []byte("[Service]\nExecStart=codex\n"))
	writeSettings(t, root, "actual@one.service.d/20-reset.conf", []byte("[Service]\nExecStart=\nExecStart=gemini\n"))
	if e := os.Symlink("actual@.service", filepath.Join(root, "alias@.service")); e != nil {
		t.Fatal(e)
	}
	if e := os.MkdirAll(filepath.Join(root, "default.target.wants"), 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.Symlink("../alias@.service", filepath.Join(root, "default.target.wants/alias@one.service")); e != nil {
		t.Fatal(e)
	}
	u := collectUnits(t.Context(), []string{root}, uint32(os.Getuid()), &contentBudget{remaining: 6 << 20})
	for _, i := range u.Items {
		if i.Name == "actual@one.service" && i.Exec.Program == "gemini-native" && i.Enablement != nil && *i.Enablement {
			return
		}
	}
	t.Fatalf("instance alias missing: %+v", u.Items)
}

type measuredUnitLayout struct {
	Distribution string `json:"distribution"`
	Entries      []struct {
		Path   string `json:"path"`
		Kind   string `json:"kind"`
		Target string `json:"target"`
		Lines  []int  `json:"line_lengths"`
	} `json:"entries"`
	Roots map[string]struct {
		Names, Units, Aliases, Directories, Dropins, Entries int
	} `json:"roots"`
	Maxima struct {
		Line    int `json:"physical_line"`
		Logical int `json:"logical_line"`
		File    int `json:"file_bytes"`
		Tokens  int `json:"lines_plus_exec_words"`
		Words   int `json:"exec_words"`
		Execs   int `json:"exec_count"`
	} `json:"maxima"`
	Bytes       int `json:"total_bytes"`
	DropinFiles int `json:"dropin_files"`
}

// These are distribution-shaped synthetic trees. The inventories and physical
// line lengths were measured from public installation images, never HOME.
func TestMeasuredStockUnitLayouts(t *testing.T) {
	files, e := filepath.Glob("testdata/unit-layouts/*.json")
	if e != nil {
		t.Fatal(e)
	}
	if len(files) != 3 {
		t.Fatalf("want three distribution inventories, got%d", len(files))
	}
	for _, file := range files {
		t.Run(strings.TrimSuffix(filepath.Base(file), ".json"), func(t *testing.T) {
			raw, e := os.ReadFile(file)
			if e != nil {
				t.Fatal(e)
			}
			var layout measuredUnitLayout
			if e = json.Unmarshal(raw, &layout); e != nil {
				t.Fatal(e)
			}
			o := commandOptions(t)
			if e = os.Remove(filepath.Join(o.Directory, ".claude")); e != nil {
				t.Fatal(e)
			}
			o.Check = true
			if e = os.RemoveAll(filepath.Join(o.ProcRoot, "20")); e != nil {
				t.Fatal(e)
			}
			base := unitFixtureRoot(t)
			for _, entry := range layout.Entries {
				path := filepath.Join(base, entry.Path)
				if e = os.MkdirAll(filepath.Dir(path), 0700); e != nil {
					t.Fatal(e)
				}
				switch entry.Kind {
				case "directory":
					if e = os.MkdirAll(path, 0700); e != nil {
						t.Fatal(e)
					}
				case "symlink":
					target := entry.Target
					if strings.HasPrefix(target, "/") {
						target = filepath.Join(base, strings.TrimPrefix(target, "/"))
					}
					if e = os.Symlink(target, path); e != nil {
						t.Fatal(e)
					}
				case "file":
					var b strings.Builder
					for _, n := range entry.Lines {
						if n > 0 {
							b.WriteByte('#')
							b.WriteString(strings.Repeat("x", n-1))
						}
						b.WriteByte('\n')
					}
					switch {
					case strings.HasSuffix(path, ".service"):
						b.WriteString("[Service]\nExecStart=/usr/bin/true")
						if filepath.Base(path) == "gnome-keyring-daemon.service" {
							b.WriteString(` --components="pkcs11,secrets"`)
						}
						b.WriteString(strings.Repeat(" a", layout.Maxima.Words-1))
						b.WriteByte('\n')
					case strings.HasSuffix(path, ".timer"):
						b.WriteString("[Timer]\nOnCalendar=daily\n")
					}
					if e = os.WriteFile(path, []byte(b.String()), 0600); e != nil {
						t.Fatal(e)
					}
				default:
					t.Fatalf("unknown fixture kind %q", entry.Kind)
				}
			}
			high := filepath.Join(base, "etc/systemd/user")
			low := filepath.Join(base, "usr/lib/systemd/user")
			o.SystemUnitRoots = []string{high, low}
			roots := []string{filepath.Join(o.Directory, ".config/systemd/user"), high, filepath.Join(o.Directory, ".local/share/systemd/user"), low}
			for _, p := range roots {
				if e = os.MkdirAll(p, 0700); e != nil {
					t.Fatal(e)
				}
			}
			u := collectUnits(t.Context(), roots, o.Caller.UID, &contentBudget{remaining: 6 << 20})
			read := map[string]bool{}
			for _, source := range u.Sources {
				if source.State != "read" {
					t.Errorf("source %s: %s %s", source.Path, source.State, source.Reason)
				}
				read[source.Path] = source.State == "read"
			}
			// All main files selected by production load-path precedence must have a
			// source row, including alias inodes and the destination names they select.
			selected := map[string]string{}
			for _, root := range roots {
				entries, e := os.ReadDir(root)
				if e != nil {
					t.Fatal(e)
				}
				for _, entry := range entries {
					name := entry.Name()
					if !strings.HasSuffix(name, ".service") && !strings.HasSuffix(name, ".timer") {
						continue
					}
					if _, ok := selected[name]; !ok {
						selected[name] = filepath.Join(root, name)
					}
				}
			}
			for name, path := range selected {
				if !read[path] {
					t.Errorf("selected unit %s lacks read source %s", name, path)
				}
			}
			if len(u.Items) != 0 {
				t.Fatalf("fixture contains an agent: %+v", u.Items)
			}
			s := Collect(t.Context(), o).Snapshot
			for _, source := range s.Sources {
				if source.Kind == "E" && source.State != "read" {
					t.Errorf("collected source: %+v", source)
				}
			}
			if s.Check != "none-observed" || s.ExitCode() != 0 {
				t.Fatalf("stock fixture check=%s exit=%d", s.Check, s.ExitCode())
			}
			var out, errs bytes.Buffer
			if e = result.Render(&out, &errs, s, false, true, nil); e != nil {
				t.Fatal(e)
			}
			if strings.Contains(out.String()+errs.String(), "could not be read") {
				for _, line := range strings.Split(out.String()+errs.String(), "\n") {
					if strings.Contains(line, "could not be read") {
						t.Error(line)
					}
				}
				t.FailNow()
			}
			dirs, entries, units := 0, 0, 0
			for _, r := range layout.Roots {
				dirs += r.Directories
				entries += r.Entries
				units += r.Units
				if unitDirectoryEntries < 10*r.Names {
					t.Errorf("directory entry bound%d below10x%d", unitDirectoryEntries, r.Names)
				}
			}
			if unitAliasHops < 10 || unitDirectoryCount < 10*dirs || unitTotalEntries < 10*entries || contentFileCount < 10*(units+layout.DropinFiles+6) {
				t.Fatalf("bounds below10x measured layout: dirs%d entries%d units%d", dirs, entries, units)
			}
			if unitLineBytes < 10*layout.Maxima.Line || unitLineBytes < 10*layout.Maxima.Logical || unitTokenLimit < 10*layout.Maxima.Tokens || unitArgumentLimit < 10*(layout.Maxima.Words-1) || unitExecLimit < 10*layout.Maxima.Execs || 1<<20 < 10*layout.Maxima.File || 6<<20 < 10*layout.Bytes {
				t.Fatal("parser byte/count bounds below10x layout")
			}
			// Port the reviewer's second collector reproduction: an agent remains
			// visible when the machine roots are present beside the user's own unit.
			writeSettings(t, roots[0], "fixture-agent.service", []byte("[Service]\nExecStart=/usr/local/bin/codex\n"))
			withAgent := Collect(t.Context(), o).Snapshot
			if withAgent.Counts.Units != 1 {
				t.Fatalf("agent beside stock roots not found: %+v", withAgent.Counts)
			}
		})
	}
}

// systemd v257 and v260 unit-file.c unit_ids_map_get uses FOLLOW_MAX=8,
// counting the final regular file as one lookup.
func TestUnitAliasSystemdLookupBoundary(t *testing.T) {
	for _, hops := range []int{7, 8} {
		t.Run(fmt.Sprint(hops), func(t *testing.T) {
			root := unitFixtureRoot(t)
			writeSettings(t, root, "actual.service", []byte("[Service]\nExecStart=/usr/bin/true\n"))
			target := "actual.service"
			for i := hops - 1; i >= 0; i-- {
				name := fmt.Sprintf("alias%d.service", i)
				if e := os.Symlink(target, filepath.Join(root, name)); e != nil {
					t.Fatal(e)
				}
				target = name
			}
			u := collectUnits(t.Context(), []string{root}, uint32(os.Getuid()), &contentBudget{remaining: 6 << 20})
			read, unresolved := false, false
			for _, s := range u.Sources {
				if s.Path == filepath.Join(root, "alias0.service") {
					read = read || s.State == "read"
					unresolved = unresolved || s.State == "not-read"
				}
			}
			if hops == 7 && (!read || unresolved) {
				t.Fatal("systemd-loadable seven-link alias refused")
			}
			if hops == 8 && !unresolved {
				t.Fatal("systemd-unloadable eight-link alias accepted")
			}
		})
	}
}
