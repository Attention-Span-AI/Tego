// SPDX-License-Identifier: Apache-2.0

// Command deadcodereport formats the raw, configuration-specific deadcode report and applies the
// classification ratchet (ADR 0029 (4) as amended 2026-10-19): every function deadcode finds unreachable
// from ./cmd/tego in any analyzed build profile must be classified by exact function in
// tools/deadcode-allow.txt, every classification must still match a finding, and a profile the tool could
// not analyze is a failure, never zero findings. The number of findings is not gated: a classified
// function may stay; an unclassified one is deleted, moved into tests, or classified with its reason.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

type position struct {
	File string
	Line int
	Col  int
}
type function struct {
	Name     string
	Position position
}
type pkg struct {
	Path  string
	Funcs []function
}

// profiles are the analyzed builds of ./cmd/tego: the four production tag sets (plain, integration,
// tegobpf, both) on both Linux architectures. scripts/deadcode-report.sh writes one raw result per
// profile.
var profiles = [...]string{
	"linux-amd64-plain", "linux-amd64-integration", "linux-amd64-tegobpf", "linux-amd64-integration-tegobpf",
	"linux-arm64-plain", "linux-arm64-integration", "linux-arm64-tegobpf", "linux-arm64-integration-tegobpf",
}

// classes are the reasons an unreachable function may stay in production code.
var classes = map[string]string{
	// public-api: exported from pkg/ for consumers other than the binary.
	"public-api": "exported from pkg/ for other consumers; the binary does not call it",
	// placeholder: an ADR 0015 deferred surface.
	"placeholder": "ADR 0015 deferred surface",
	// pending: built ahead of an accepted ADR's migration, whose work package will call it.
	"pending": "built ahead of an accepted migration that will call it",
	// tag-only: reached only from a build the profiles do not analyze (tegotesthooks), or a bridge that
	// exists only under the integration tag for another package's integration tests.
	"tag-only": "reached only under a build tag the binary is not built with",
	// test-api: exported for another package's tests, which a _test.go file of its own package cannot
	// serve; the reason names those tests.
	"test-api": "exported for another package's tests",
	// tool-only: called by a repository tool (tools/...) that shares the package with the binary so the
	// two share one format; the reason names the tool.
	"tool-only": "called by a repository tool, not by the binary",
	// control-only: called by cmd/tego-control from a package the two binaries share. The profiles analyze
	// ./cmd/tego alone, so this function is live but unreachable from there; the reason names the caller, or
	// the function that reaches it.
	"control-only": "called by cmd/tego-control, not by cmd/tego",
	// reflection: reached by a call the analysis does not follow (encoding/json calling a decoder
	// method); the reason names the reachable call that reaches it.
	"reflection": "reached through reflection the analysis does not follow",
}

// publicAPIPrefix is the only place public-api may be claimed: no other module can import internal/.
const publicAPIPrefix = modulePrefix + "pkg/"

const modulePrefix = "github.com/attention-span-ai/tego/"

type classification struct {
	class, reason string
}

func main() {
	os.Exit(run(os.Args[1:], os.Stderr))
}

// run is the command: it writes report.md into -dir, prints each ratchet problem on stderr and returns
// the exit status: 2 for bad usage, 1 when the report cannot be written or when -gate is given and the
// ratchet fails, 0 otherwise (without -gate the ratchet only reports).
func run(args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("deadcodereport", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dir := fs.String("dir", "", "raw report directory")
	allow := fs.String("allow", "", "function classifications")
	gate := fs.Bool("gate", false, "exit 1 when the ratchet fails")
	if err := fs.Parse(args); err != nil || *dir == "" || *allow == "" || fs.NArg() != 0 {
		fmt.Fprintln(stderr, "usage: deadcodereport -dir DIR -allow FILE [-gate]")
		return 2
	}
	report, problems, err := render(*dir, *allow)
	if err == nil {
		err = os.WriteFile(filepath.Join(*dir, "report.md"), report, 0o600)
	}
	if err != nil {
		fmt.Fprintln(stderr, "deadcode report:", err)
		return 1
	}
	for _, p := range problems {
		fmt.Fprintln(stderr, "deadcode ratchet:", p)
	}
	if *gate && len(problems) != 0 {
		return 1
	}
	return 0
}

// classifications reads lines "<import path>.<function>\t<class>\t<reason>", where <function> is the name
// deadcode prints (Name, Type.Method). Blank lines and # comments are ignored.
func classifications(path string) (map[string]classification, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	out := make(map[string]classification)
	for i, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) != 3 {
			return nil, fmt.Errorf("line %d: want <function>\\t<class>\\t<reason>", i+1)
		}
		name, class, reason := fields[0], fields[1], strings.TrimSpace(fields[2])
		slash := strings.LastIndex(name, "/")
		if !strings.HasPrefix(name, modulePrefix) || strings.ContainsAny(name, " *") || slash < 0 ||
			!strings.Contains(name[slash:], ".") || strings.HasSuffix(name, ".") {
			return nil, fmt.Errorf("line %d: %q is not an exact function of this module", i+1, name)
		}
		if _, ok := classes[class]; !ok {
			return nil, fmt.Errorf("line %d: unknown class %q", i+1, class)
		}
		if reason == "" {
			return nil, fmt.Errorf("line %d: %s has no reason", i+1, name)
		}
		if class == "public-api" && !strings.HasPrefix(name, publicAPIPrefix) {
			return nil, fmt.Errorf("line %d: %s is not under pkg/, so it is no public API", i+1, name)
		}
		if _, duplicate := out[name]; duplicate {
			return nil, fmt.Errorf("line %d: duplicate classification %s", i+1, name)
		}
		out[name] = classification{class: class, reason: reason}
	}
	return out, nil
}

// render returns the report and the ratchet's problems: unavailable profiles, unclassified findings and
// stale classifications. An error means the raw input itself is unusable.
func render(dir, allowPath string) ([]byte, []string, error) {
	allow, err := classifications(allowPath)
	if err != nil {
		return nil, nil, err
	}
	var out bytes.Buffer
	var problems []string
	unavailable := false
	seen := make(map[string]bool)
	unclassified := make(map[string][]string)
	out.WriteString("# Production reachability report\n\nTool: `golang.org/x/tools/cmd/deadcode@v0.50.0`; entrypoint: `./cmd/tego`; Linux, CGO off, tests excluded.\n\nEach row describes one build configuration. Every unreachable function must be classified by exact function in `tools/deadcode-allow.txt` (ADR 0029 (4)); an unclassified one is deleted, moved into tests or classified. Classifications retain every finding. Tool failures are unavailable, never zero findings, and fail the ratchet.\n")
	for _, profile := range profiles {
		statusBytes, err := os.ReadFile(filepath.Join(dir, profile+".status"))
		if err != nil {
			return nil, nil, fmt.Errorf("%s status: %w", profile, err)
		}
		status, err := strconv.Atoi(strings.TrimSpace(string(statusBytes)))
		if err != nil || status < 0 || status > 255 {
			return nil, nil, fmt.Errorf("%s invalid status", profile)
		}
		fmt.Fprintf(&out, "\n## %s\n\n", profile)
		if status != 0 {
			fmt.Fprintf(&out, "Unavailable (tool exit %d). See `%s.stderr` and the preserved raw output.\n", status, profile)
			problems = append(problems, fmt.Sprintf("%s unavailable (tool exit %d)", profile, status))
			unavailable = true
			continue
		}
		packages, err := readRaw(dir, profile)
		if err != nil {
			return nil, nil, err
		}
		var lines bytes.Buffer
		count, open := 0, 0
		for _, p := range packages {
			sort.Slice(p.Funcs, func(i, j int) bool { return p.Funcs[i].Name < p.Funcs[j].Name })
			for _, f := range p.Funcs {
				if f.Name == "" || f.Position.File == "" || f.Position.Line <= 0 {
					return nil, nil, fmt.Errorf("%s incomplete function in %s", profile, p.Path)
				}
				count++
				name := p.Path + "." + f.Name
				label := "UNCLASSIFIED"
				if c, ok := allow[name]; ok {
					label = c.class + ": " + c.reason
					seen[name] = true
				} else {
					open++
					unclassified[name] = append(unclassified[name], profile)
				}
				fmt.Fprintf(&lines, "\n- `%s` — `%s:%d` (%s)\n", name, f.Position.File, f.Position.Line, label)
			}
		}
		fmt.Fprintf(&out, "%d unreachable functions (%d classified, %d unclassified). Raw results: `%s.json`.\n", count, count-open, open, profile)
		out.Write(lines.Bytes())
	}
	names := make([]string, 0, len(unclassified))
	for name := range unclassified {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		problems = append(problems, fmt.Sprintf("unclassified %s (%s)", name, strings.Join(unclassified[name], ", ")))
	}
	if !unavailable {
		// A stale entry is judged only when every profile was analyzed: an unavailable profile may hold it.
		var stale []string
		for name := range allow {
			if !seen[name] {
				stale = append(stale, name)
			}
		}
		sort.Strings(stale)
		for _, name := range stale {
			problems = append(problems, fmt.Sprintf("stale %s: no profile finds it unreachable; remove its classification", name))
		}
	}
	out.WriteString("\n## Ratchet\n\n")
	if len(problems) == 0 {
		out.WriteString("Ratchet: PASS. Every unreachable function in every profile is classified, and every classification matches one.\n")
	} else {
		out.WriteString("Ratchet: FAIL.\n\n")
		for _, p := range problems {
			fmt.Fprintf(&out, "- %s\n", p)
		}
	}
	return out.Bytes(), problems, nil
}

func readRaw(dir, profile string) ([]pkg, error) {
	data, err := os.ReadFile(filepath.Join(dir, profile+".json"))
	if err != nil {
		return nil, err
	}
	var packages []pkg
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(&packages); err != nil {
		return nil, fmt.Errorf("%s raw JSON: %w", profile, err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return nil, fmt.Errorf("%s has trailing JSON", profile)
	}
	sort.Slice(packages, func(i, j int) bool { return packages[i].Path < packages[j].Path })
	for _, p := range packages {
		if p.Path == "" {
			return nil, fmt.Errorf("%s missing package path", profile)
		}
	}
	return packages, nil
}
