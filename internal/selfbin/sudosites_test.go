// SPDX-License-Identifier: Apache-2.0

package selfbin

import (
	"bufio"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// Valued sudo options must consume their value before the command word. Flags
// such as -E consume no value; quoted paths and split literals are checked too.
var sudoLiteral = regexp.MustCompile(`sudo(?:[ \t]+(?:(?:-[uUgGhHpPCTrtDR]|--(?:user|group|host|prompt|close-from|command-timeout|chroot|chdir|role|type))[ \t]+[^ \t]+|-[^ \t]+))*[ \t]+(?:tego\b|[/'"])`)

// This walks production source, including files outside the current build tags.
// A new literal sudo command or helper caller must be reviewed here. Nonempty
// table values require that helper; empty entries are prose or non-Tego commands.
// Bare tego is never allowed. Constant string concatenations are folded, but
// runtime-built text inside a reviewed function still needs manual review.
// The full audit is docs/sudo-commands.md.
func TestSudoSites(t *testing.T) {
	sites := map[string]string{
		"internal/check/compiledview/build.go:buildAlwaysOn": "",
		"internal/cli/adopt.go:cmdAdopt":                     "sudoSelf",
		"internal/cli/adopt.go:releaseRequester":             "",
		"internal/cli/agents.go:agentsPrivilegeMessage":      "sudoSelf",
		"internal/cli/agents.go:sudoSelf":                    "Sudo",
		"internal/cli/agents.go:agentsNext":                  "sudoSelf",
		"internal/cli/compile_unknown.go:explain":            "sudoSelf",
		"internal/cli/doctor.go:writeDoctorVerdict":          "sudoTego",
		"internal/cli/doctor.go:sudoTego":                    "sudoSelf",
		"internal/cli/hints.go:forReader":                    "ForReader",
		"internal/cli/hints.go:writeHint":                    "",
		"internal/cli/hints.go:outsideHint":                  "",
		"internal/cli/privpath.go:guardPrivilege":            "sudoSelf",
		"internal/cli/setup.go:refuseSetup":                  "sudoTego",
		"internal/cli/uninstall.go:runUninstall":             "", // prose: prints the lines the scan made, runs none
		"internal/cli/uninstall_scan.go:scanSystem":          "", // system tools only (rm, systemctl): no Tego program named
		"internal/cli/uninstall_scan.go:scanPrograms":        "", // sudo rm <path>: deletes the file, never runs it
		"internal/cli/userbus.go:classifyUserBus":            "", // prose: the apt line for a missing package; no Tego program named
		"internal/cli/userbus.go:writeUserBusProblem":        "", // prose: prints that line, runs none

		// prose: says what a sudo run does and names no command to run
		"internal/control/ledgerview/rootrun.go:RootLaunchedWords": "",

		"internal/control/web/insights.go:tierFacts":           "",
		"internal/doctor/derive.go:fixFor":                     "sudoDoctor",
		"internal/doctor/fanotify.go:probeFanotify":            "sudoDoctor",
		"internal/doctor/pidnamespace.go:rootTierNamespaceFix": "",
		"internal/doctor/plane.go:PlaneFor":                    "sudoDoctor",
		"internal/doctor/probe.go:sudoDoctor":                  "Sudo",
		"internal/doctor/programs.go:probeHooks":               "sudoDoctor",
		"internal/guide/guide.go:scopeAs":                      "",
		"internal/guide/guide.go:settleScopeAs":                "",
		"internal/guide/here.go:ForReader":                     "SelfPath",
		"internal/guide/here.go:scopeCommand":                  "",
		"internal/guide/here.go:managerUnder":                  "",
		"internal/guide/next.go:next":                          "ForReader",
		"internal/runtime/capture/forwarder/sockdiag.go:inode": "",
		"internal/runtime/cgroup/detect.go:PlacementFix":       "",
		"internal/runtime/cgroup/detect.go:placementRemedy":    "",
		"internal/runtime/cgroup/detect.go:NoManagerFix":       "",
		"internal/runtime/cgroup/detect.go:LingerCommand":      "",
		"internal/runtime/cgroup/detect.go:ScopeAsCommand":     "",
		"internal/runtime/run_child.go:privilegedTarget":       "Sudo",
		"internal/runtime/sweep_adopt.go:sweepAdoption":        "Sudo",
		"internal/cli/doctordashboard.go:dashboardFix":         "",
		"internal/selfbin/selfbin.go:NoPath":                   "",
		"internal/selfbin/selfbin.go:Unsafe":                   "",
		"internal/selfbin/selfbin.go:Sudo":                     "named",
	}
	seen := map[string]bool{}
	root := filepath.Join("..", "..", "internal")
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(filepath.Join("..", ".."), path)
		if err != nil {
			return err
		}
		nodes := map[string]ast.Node{}
		for _, decl := range f.Decls {
			switch decl := decl.(type) {
			case *ast.FuncDecl:
				nodes[decl.Name.Name] = decl
			case *ast.GenDecl:
				for _, spec := range decl.Specs {
					if v, ok := spec.(*ast.ValueSpec); ok {
						nodes[v.Names[0].Name] = v
					}
				}
			}
		}
		for name, node := range nodes {
			site := filepath.ToSlash(rel) + ":" + name
			relevant := false
			calls := map[string]bool{}
			ast.Inspect(node, func(n ast.Node) bool {
				if c, ok := n.(*ast.CallExpr); ok {
					name := ""
					switch f := c.Fun.(type) {
					case *ast.Ident:
						name = f.Name
					case *ast.SelectorExpr:
						name = f.Sel.Name
					}
					calls[name] = true
					switch name {
					case "sudoSelf", "sudoTego", "sudoDoctor", "Sudo", "ForReader", "ScopeAsCommand", "LingerCommand":
						relevant = true
					}
				}
				s, ok := literalCommandText(n)
				if !ok {
					return true
				}
				if strings.Contains(s, "sudo ") {
					relevant = true
				}
				if sudoLiteral.MatchString(s) {
					t.Errorf("%s: unchecked sudo command %q; use selfbin.Sudo or guide.ForReader", site, s)
				}
				return true
			})
			if !relevant {
				continue
			}
			seen[site] = true
			if helper, ok := sites[site]; !ok {
				t.Errorf("unreviewed sudo site: %q", site)
			} else if helper != "" && !calls[helper] {
				t.Errorf("%s must use %s", site, helper)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for site := range sites {
		source, _, _ := strings.Cut(site, ":")
		if _, err := os.Stat(filepath.Join("..", "..", source)); err == nil && !seen[site] {
			t.Errorf("stale sudo site: %s", site)
		}
	}
}

// literalCommandText also folds split literals so "sudo " + "tego" cannot hide
// inside a previously reviewed producer.
func literalCommandText(n ast.Node) (string, bool) {
	switch n := n.(type) {
	case *ast.BasicLit:
		if n.Kind == token.STRING {
			s, err := strconv.Unquote(n.Value)
			return s, err == nil
		}
	case *ast.BinaryExpr:
		if n.Op == token.ADD {
			left, lok := literalCommandText(n.X)
			right, rok := literalCommandText(n.Y)
			return left + right, lok && rok
		}
	case *ast.ParenExpr:
		return literalCommandText(n.X)
	}
	return "", false
}

// Walk the documentation and template folders, including public overlays, so a
// new page is checked without an inventory row or a count tied to other edits.
func TestDocumentedSudoSites(t *testing.T) {
	root := filepath.Join("..", "..")
	err := walkDocumentedCommands(root, func(path string, line int, text string) {
		t.Errorf("%s:%d: unsupported elevated Tego command %q; use the form in docs/site/install.md", path, line, text)
	})
	if err != nil {
		t.Fatal(err)
	}
}

func walkDocumentedCommands(root string, bad func(string, int, string)) error {
	return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			if rel == "." || strings.HasPrefix(rel, "docs") || strings.HasPrefix(rel, ".github") ||
				strings.HasPrefix(rel, "examples/systemd") || rel == "examples" || rel == "scripts" ||
				rel == "tools" || rel == "tools/oss" || rel == "tools/oss/testdata" ||
				strings.HasPrefix(rel, "tools/oss/testdata/overlay") {
				return nil
			}
			return filepath.SkipDir
		}
		if !strings.HasSuffix(rel, ".md") && !strings.HasSuffix(rel, ".yml") &&
			!strings.HasSuffix(rel, ".yaml") && !strings.Contains(rel, ".service") && rel != "scripts/install.sh" {
			return nil
		}
		// Workflows execute repository-built artifacts and are not user templates.
		if strings.HasPrefix(rel, ".github/workflows/") || strings.Contains(rel, "/.github/workflows/") {
			return nil
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		scan := bufio.NewScanner(f)
		line := 0
		for scan.Scan() {
			line++
			for _, command := range undocumentedElevatedTego(scan.Text()) {
				bad(rel, line, command)
			}
		}
		err = scan.Err()
		closeErr := f.Close()
		if err != nil {
			return err
		}
		return closeErr
	})
}

var elevationStart = regexp.MustCompile(`\b(?:sudo|runuser|systemd-run)[ \t]+|\bsu[ \t]+-`)
var commandWord = regexp.MustCompile(`"\$\(command -v tego\)"|'[^']*'|"[^"]*"|[^ \t` + "`" + `]+`)

// This recognizes command words after the elevation tool's options, rather than
// sudo prose, account setup commands or unrelated system tools on the same line.
func undocumentedElevatedTego(line string) []string {
	var bad []string
	for _, start := range elevationStart.FindAllStringIndex(line, -1) {
		fragment := strings.SplitN(line[start[0]:], "`", 2)[0]
		words := commandWord.FindAllString(fragment, -1)
		if len(words) == 0 {
			continue
		}
		command, script := elevatedCommand(words)
		if command == "" {
			continue
		}
		if script != "" {
			// Resolve in the target account's shell, never in the administrator's.
			if strings.HasPrefix(script, `exec "$(command -v tego)" `) && len(words) > 6 &&
				words[0] == "sudo" && words[1] == "-u" && words[3] == "-H" &&
				words[4] == "sh" && words[5] == "-lc" {
				continue
			}
		} else if command == `"$(command -v tego)"` && (words[0] == "systemd-run" || (words[0] == "sudo" && len(words) > 1 && words[1] == command)) {
			continue
		}
		bad = append(bad, fragment)
	}
	return bad
}

func elevatedCommand(words []string) (command, script string) {
	valueOption := map[string]bool{}
	var options []string
	switch words[0] {
	case "sudo":
		options = []string{"-u", "--user", "-g", "--group", "-h", "--host", "-p", "--prompt",
			"-C", "--close-from", "-T", "--command-timeout", "-R", "--chroot", "-D", "--chdir",
			"-r", "--role", "-t", "--type"}
	case "su", "runuser":
		options = []string{"-s", "--shell", "-g", "--group", "-G", "--supp-group", "-w", "--whitelist-environment"}
		if words[0] == "runuser" {
			options = append(options, "-u", "--user", "-l", "--login")
		}
	case "systemd-run":
		// In particular, --user is a flag here; sudo's --user takes a value.
		options = []string{"-p", "--property", "-u", "--unit", "-S", "--slice", "-H", "--host", "-M", "--machine",
			"--uid", "--gid", "--working-directory", "--description", "--on-active", "--on-boot", "--on-startup",
			"--on-unit-active", "--on-unit-inactive", "--on-calendar", "--timer-property", "-E", "--setenv",
			"--path-property", "--socket-property", "--nice", "--service-type"}
	}
	for _, option := range options {
		valueOption[option] = true
	}
	for i := 1; i < len(words); i++ {
		word := words[i]
		if (words[0] == "su" || words[0] == "runuser") && (word == "-c" || word == "--command") {
			if i+1 < len(words) {
				return scriptTego(words[i+1])
			}
			return "", ""
		}
		if valueOption[word] {
			i++
			continue
		}
		if strings.HasPrefix(word, "-") || strings.Contains(word, "=") {
			continue
		}
		if words[0] == "su" {
			// The first non-option word names the account; -c may follow it.
			continue
		}
		if word == "env" {
			return elevatedCommand(append([]string{words[0]}, words[i+1:]...))
		}
		if filepath.Base(word) == "sh" || filepath.Base(word) == "bash" {
			if i+2 < len(words) && (words[i+1] == "-c" || words[i+1] == "-lc") {
				return scriptTego(words[i+2])
			}
			return "", ""
		}
		if tegoCommandWord(word) {
			return word, ""
		}
		return "", ""
	}
	return "", ""
}

func scriptTego(word string) (command, script string) {
	script = strings.Trim(word, `"'`)
	for _, token := range commandWord.FindAllString(script, -1) {
		if tegoCommandWord(token) {
			return token, script
		}
	}
	return "", ""
}

func tegoCommandWord(word string) bool {
	word = strings.Trim(word, `"'`)
	if word != "$(command -v tego)" {
		word = strings.TrimRight(word, ").,;:")
	}
	return word == "tego" || strings.HasSuffix(word, "/tego") || word == "$tego_bin" ||
		word == "$(command -v tego)" || word == "<tego>"
}

func TestDocumentedSudoRule(t *testing.T) {
	for _, text := range []string{
		`sudo "$(command -v tego)" doctor`,
		`Use sudo "$(command -v tego)" run for root tiers.`,
		`sudo -u svc -H sh -lc 'exec "$(command -v tego)" setup'`,
		`systemd-run --user --wait -p Delegate=yes "$(command -v tego)" doctor`,
		`sudo loginctl enable-linger tego`,
		"A user manager reached through `sudo -u svc` runs `tego setup`.",
	} {
		if got := undocumentedElevatedTego(text); len(got) != 0 {
			t.Errorf("allowed line %q: %v", text, got)
		}
	}
	for _, text := range []string{
		`sudo tego doctor`, `sudo -E tego doctor`, `sudo -u svc tego setup`,
		`sudo --chdir /tmp tego doctor`,
		`sudo "$HOME/.local/bin/tego" doctor`, `sudo /usr/local/bin/tego doctor`,
		`sudo -u svc "$(command -v tego)" setup`,
		`sudo -u svc sh -c 'exec /home/svc/.local/bin/tego setup'`,
		`su - svc -c 'tego setup'`, `runuser -u svc -- tego setup`,
		`systemd-run --user --scope tego doctor`, `systemd-run --user tego doctor`,
		`runuser -u svc -c 'tego setup'`, `runuser -l svc -c 'tego setup'`,
		`su -c 'tego setup' svc`, `su -p -c 'tego setup' svc`,
		`systemd-run --user --uid svc tego doctor`,
		`sudo env tego doctor`, `sudo env PATH=/usr/bin tego doctor`,
		`sudo -u svc sh -c 'exec "$(command -v tego)" setup'`,
	} {
		if got := undocumentedElevatedTego(text); len(got) == 0 {
			t.Errorf("unchecked line %q", text)
		}
	}
}

// These spellings must fail even inside a function already in the site table.
func TestSudoLiteralRule(t *testing.T) {
	for _, expr := range []string{
		`"sudo -E tego doctor"`, `"sudo --user svc tego setup"`,
		`"sudo --group wheel /opt/tego doctor"`, `"sudo --chdir /var/tmp tego doctor"`,
		`"sudo " + "tego doctor"`, `("sudo " + "/opt/x/tego") + " doctor"`,
	} {
		node, err := parser.ParseExpr(expr)
		if err != nil {
			t.Fatal(err)
		}
		text, ok := literalCommandText(node)
		if !ok || !sudoLiteral.MatchString(text) {
			t.Errorf("unchecked literal expression %s", expr)
		}
	}
}
