// SPDX-License-Identifier: Apache-2.0

package selfbin

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// producerWord reports whether lit, one whole string literal, is a word by which code makes something that runs
// later: a service manager's unit, a cron line, a desktop or autostart entry, a shell profile.
func producerWord(lit string) bool {
	switch lit {
	case "systemd-run", "systemctl", "crontab", ".bashrc", ".bash_profile", ".bash_login", ".profile", ".zshrc", ".zprofile":
		return true
	}
	return strings.HasPrefix(lit, "--unit=") || strings.HasSuffix(lit, ".desktop") || strings.HasSuffix(lit, ".service") ||
		strings.HasSuffix(lit, ".timer") || strings.Contains(lit, "/cron") || strings.Contains(lit, "autostart")
}

// Every production function that holds such a word is listed with its class, so a new producer of a unit, a cron
// line, a profile line or a desktop entry is reviewed before it ships (ADR 0142, amendments of 2026-11-18): one that
// root or another account will run is privileged and must name the program through Named, the checked path; one the
// person's own service manager or shell runs as that person adds no authority and is "same user". The other rows
// make nothing: they read, match or name such a thing. A function-valued variable is listed under its file's
// declarations. Text built at run time inside a listed function still needs a reader.
func TestRunLaterProducers(t *testing.T) {
	const (
		sameUserUnit    = "same user: guideDashboard's transient unit tego-dashboard in the person's own service manager"
		sameUserProfile = "same user: one line in the person's own shell profile, naming no program"
		reads           = "makes nothing: reads, matches or names such a thing"
		ownLock         = "makes nothing: a lock file of Tego's own state whose name ends .timer"
		sameUserTimer   = "same user: retain_timer.go's transient timer tego-gc in the person's own service manager, started with the running program's path as the dashboard's unit is"
		uninstallReads  = "makes nothing: tego uninstall names units and profile lines to find and remove them (user manager and own home only); a system-wide install is only reported"
	)
	want := map[string]string{
		"internal/cli/retain_timer.go:retentionTimerArgv":       sameUserTimer,
		"internal/cli/retain_timer.go:ensureRetentionTimer":     sameUserTimer,
		"internal/cli/uninstall.go:declarations":                uninstallReads,
		"internal/cli/uninstall_scan.go:declarations":           uninstallReads,
		"internal/cli/uninstall_scan.go:newRealUninstallEnv":    uninstallReads,
		"internal/cli/uninstall_scan.go:scanShellLines":         uninstallReads,
		"internal/cli/uninstall_scan.go:scanSystem":             uninstallReads,
		"internal/cli/uninstall_scan.go:scanUnits":              uninstallReads,
		"internal/cli/uninstall_scan.go:userSystemctl":          uninstallReads,
		"internal/cli/setup_guide.go:declarations":              sameUserUnit,
		"internal/cli/setup_guide.go:saveLogin":                 sameUserProfile,
		"internal/cli/scan.go:declarations":                     reads,
		"internal/control/ledgerview/severity.go:declarations":  reads,
		"internal/guide/here.go:inUserManager":                  reads,
		"internal/runscope/rule.go:ManagerCgroup":               reads,
		"internal/runtime/cgroup/detect.go:canonicalSubtreeIn":  reads,
		"internal/runtime/cgroup/detect.go:delegatedSubtreeIn":  reads,
		"internal/runtime/enforce/cgroup/linger.go:lockTimer":   ownLock,
		"internal/runtime/enforce/cgroup/linger.go:rearmTimers": ownLock,
		"internal/runtime/enforce/cgroup/proclocks.go:timerPID": ownLock,
		"internal/scan/execstart.go:parseUnit":                  reads,
		"internal/scan/parsers.go:parseCgroup":                  reads,
		"internal/scan/result/decode.go:valid":                  reads,
		"internal/scan/result/footerwords.go:declarations":      reads,
		"internal/scan/units.go:collectUnits":                   reads,
		"pkg/policy/execmatch/rows/more.go:Systemctl":           reads,
		"pkg/spec/agent/compile_denywrite.go:declarations":      reads,
	}
	got := map[string][]string{}
	root := filepath.Join("..", "..")
	for _, top := range []string{"internal", "cmd", "pkg"} {
		err := filepath.WalkDir(filepath.Join(root, top), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if d.Name() == "testdata" {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			rel, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.SkipObjectResolution)
			if err != nil {
				return err
			}
			for _, decl := range file.Decls {
				name := "declarations"
				if fn, ok := decl.(*ast.FuncDecl); ok {
					name = fn.Name.Name
				}
				ast.Inspect(decl, func(n ast.Node) bool {
					lit, ok := n.(*ast.BasicLit)
					if !ok || lit.Kind != token.STRING {
						return true
					}
					if s, err := strconv.Unquote(lit.Value); err == nil && producerWord(s) {
						key := rel + ":" + name
						if !slices.Contains(got[key], s) {
							got[key] = append(got[key], s)
						}
					}
					return true
				})
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	for key, words := range got {
		if _, ok := want[key]; !ok {
			t.Errorf("unreviewed: %s holds %q; class it here and in the ADR 0142 list (privileged producers name the program through Named)", key, words)
		}
	}
	for key := range want {
		if _, ok := got[key]; !ok {
			t.Errorf("stale row: %s holds no such word now", key)
		}
	}
}
