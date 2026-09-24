// SPDX-License-Identifier: Apache-2.0

package enforce

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// repoRoot is the module root, three levels above this package.
var repoRoot = filepath.Join("..", "..", "..")

// TestShippedBuildsCarryTheObjects: Buildable(TierCgroup) is true only in a binary built with -tags tegobpf, so
// a build without the tag can never run tier 2, however capable the machine. Static linking is no longer the
// tier's need (ADR 0021 (4)); the shipped binaries keep it (docs/VERSIONING.md), and this test holds them to it. `make build` and the goreleaser build are the two
// a user gets tego from, and both left the tag out, so every shipped binary reported tier cgroup as not built.
// The bpf2go output is committed, which is what makes the tag free: it needs no clang and no `make gen`. Both
// must also say CGO_ENABLED=0 and -buildmode=exe: cgo on links tego dynamically wherever a C compiler is
// installed, and -buildmode=pie, which GOFLAGS can carry into either build, links a cgo-free one against the
// loader too; only a command-line -buildmode overrides GOFLAGS. Of several -buildmode or -tags flags go build
// keeps the last, so each is read that way (staticBuildProblems). The recipe is read as make runs it, with
// backslash-continued lines joined into one command, so a flag on a continuation line counts and a command
// split over lines cannot hide from the check.
func TestShippedBuildsCarryTheObjects(t *testing.T) {
	t.Run("make build", func(t *testing.T) {
		data, err := os.ReadFile(filepath.Join(repoRoot, "Makefile"))
		if err != nil {
			t.Skipf("no Makefile beside this module: %v", err)
		}
		cmds := buildRecipe(string(data))
		if len(cmds) == 0 {
			t.Fatal("no recipe for the build target")
		}
		var found bool
		for _, cmd := range cmds {
			if !goBuildOf(cmd, "./cmd/tego") {
				continue
			}
			found = true
			for _, problem := range staticBuildProblems(cmd) {
				t.Errorf("`make build` runs %q: %s", strings.Join(cmd, " "), problem)
			}
		}
		if !found {
			t.Fatalf("`make build` runs %q, and none of it is a go build of ./cmd/tego", cmds)
		}
	})

	t.Run("goreleaser", func(t *testing.T) {
		data, err := os.ReadFile(filepath.Join(repoRoot, ".goreleaser.yaml"))
		if err != nil {
			t.Skipf("no .goreleaser.yaml beside this module: %v", err)
		}
		var cfg struct {
			Builds []struct {
				ID    string   `yaml:"id"`
				Main  string   `yaml:"main"`
				Env   []string `yaml:"env"`
				Flags []string `yaml:"flags"`
			} `yaml:"builds"`
		}
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			t.Fatalf("parse .goreleaser.yaml: %v", err)
		}
		var found bool
		for _, b := range cfg.Builds {
			if b.Main != "./cmd/tego" {
				continue
			}
			found = true
			// goreleaser runs `go build <flags> <main>` with env set, as a make recipe's leading assignments do.
			cmd := append(append(slices.Clone(b.Env), "go", "build"), b.Flags...)
			for _, problem := range staticBuildProblems(append(cmd, b.Main)) {
				t.Errorf("goreleaser build %q (env %v, flags %v): %s", b.ID, b.Env, b.Flags, problem)
			}
		}
		if !found {
			t.Fatal(".goreleaser.yaml has no build of ./cmd/tego")
		}
	})
}

// buildRecipe returns the commands of the Makefile's build target, each as its words, with a line that ends in a
// backslash joined to the next as make joins it before handing the command to the shell.
func buildRecipe(makefile string) [][]string {
	var cmds [][]string
	var cur strings.Builder
	in, cont := false, false
	target := regexp.MustCompile(`^[A-Za-z0-9_.-]+:`)
	for _, line := range strings.Split(makefile, "\n") {
		switch {
		case cont:
		case strings.HasPrefix(line, "build:"):
			in = true
			continue
		case in && target.MatchString(line):
			in = false
		}
		if !in || (!cont && !strings.HasPrefix(line, "\t")) {
			continue
		}
		body := strings.TrimSuffix(line, "\\")
		cont = body != line
		cur.WriteString(body)
		cur.WriteString(" ")
		if !cont {
			cmds = append(cmds, strings.Fields(cur.String()))
			cur.Reset()
		}
	}
	if cur.Len() > 0 {
		cmds = append(cmds, strings.Fields(cur.String()))
	}
	return cmds
}

// goBuildOf reports whether the words are a go build (go or $(GO), then build) naming pkg.
func goBuildOf(cmd []string, pkg string) bool {
	for i := 0; i+1 < len(cmd); i++ {
		if (cmd[i] == "go" || cmd[i] == "$(GO)") && cmd[i+1] == "build" {
			return slices.Contains(cmd[i+2:], pkg)
		}
	}
	return false
}

// staticBuildProblems lists what, in a go build command's words, would let the binary be linked against the
// loader or built without the BPF objects: the last CGO_ENABLED assignment before go is not 0, the last
// -buildmode is not exe, or the last -tags does not name tegobpf. go build keeps only the last value of a flag
// it is given twice, -tags as much as -buildmode (`-tags tegobpf -tags netgo` builds without tegobpf), so an
// earlier -tags tegobpf that a later one replaces is no tag at all.
func staticBuildProblems(cmd []string) []string {
	cgo, mode, tags := "", "", ""
	seenGo := false
	for i, w := range cmd {
		// The flag package takes -flag and --flag alike.
		f := w
		if strings.HasPrefix(f, "--") {
			f = f[1:]
		}
		switch {
		case !seenGo && (w == "go" || w == "$(GO)"):
			seenGo = true
		case !seenGo && strings.HasPrefix(w, "CGO_ENABLED="):
			cgo = strings.TrimPrefix(w, "CGO_ENABLED=")
		case !seenGo:
		case strings.HasPrefix(f, "-buildmode="):
			mode = strings.TrimPrefix(f, "-buildmode=")
		case f == "-buildmode" && i+1 < len(cmd):
			mode = cmd[i+1]
		case strings.HasPrefix(f, "-tags="):
			tags = strings.TrimPrefix(f, "-tags=")
		case f == "-tags" && i+1 < len(cmd):
			tags = cmd[i+1]
		}
	}
	var problems []string
	// A tag list is comma-separated; go build still reads the older space-separated form, which a quoted
	// Makefile word or a YAML string can carry whole.
	sep := func(r rune) bool { return r == ',' || r == ' ' }
	if !slices.Contains(strings.FieldsFunc(strings.Trim(tags, `'"`), sep), "tegobpf") {
		problems = append(problems, fmt.Sprintf("the last -tags is %q, which does not name tegobpf, so the binary "+
			"cannot run tier 2", tags))
	}
	if cgo != "0" {
		problems = append(problems, "CGO_ENABLED is not 0 on the command, so the binary can be dynamically linked, "+
			"against the shipped builds' static, portable linking (docs/VERSIONING.md §5)")
	}
	if mode != "exe" {
		problems = append(problems, fmt.Sprintf("the last -buildmode is %q, not exe, so a GOFLAGS=-buildmode=pie "+
			"or a later flag makes the binary a PIE, against the shipped builds' non-PIE, portable linking "+
			"(docs/VERSIONING.md §5; the guest run of a PIE build is ADR 0021's open condition)", mode))
	}
	return problems
}

// TestStaticBuildProblemsReadsTheLastFlag pins staticBuildProblems itself, since TestShippedBuildsCarryTheObjects
// passes whenever the helper finds nothing: go build keeps the last of a repeated -tags or -buildmode, so a later
// -tags that leaves tegobpf out, or a later -buildmode=pie, undoes an earlier correct one, and either shipped
// binary would then report tier cgroup as not built, or lose the static, non-PIE linking the release keeps for
// portability (docs/VERSIONING.md §5; tier 2 has no linking check since ADR 0021 (4)).
func TestStaticBuildProblemsReadsTheLastFlag(t *testing.T) {
	cases := []struct {
		cmd  string
		want []string // a word each problem must contain; none means no problem
	}{
		{"CGO_ENABLED=0 go build -buildmode=exe -tags tegobpf ./cmd/tego", nil},
		{"CGO_ENABLED=0 go build -buildmode=exe -tags=tegobpf,netgo ./cmd/tego", nil},
		{"CGO_ENABLED=0 go build -buildmode=exe --tags tegobpf ./cmd/tego", nil},
		{"CGO_ENABLED=0 go build -buildmode=exe -tags netgo -tags tegobpf,netgo ./cmd/tego", nil},
		{"CGO_ENABLED=0 go build -buildmode=exe -tags tegobpf -tags netgo ./cmd/tego", []string{"-tags"}},
		{"CGO_ENABLED=0 go build -buildmode=exe -tags=tegobpf -tags=netgo ./cmd/tego", []string{"-tags"}},
		{"CGO_ENABLED=0 go build -buildmode=exe -tags=tegobpf --tags= ./cmd/tego", []string{"-tags"}},
		{"CGO_ENABLED=0 go build -buildmode=exe ./cmd/tego", []string{"-tags"}},
		{"CGO_ENABLED=0 go build -buildmode=exe -tags tegobpfx ./cmd/tego", []string{"-tags"}},
		{"CGO_ENABLED=0 go build -buildmode=pie -buildmode=exe -tags tegobpf ./cmd/tego", nil},
		{"CGO_ENABLED=0 go build -buildmode=exe -buildmode=pie -tags tegobpf ./cmd/tego", []string{"-buildmode"}},
		{"CGO_ENABLED=0 go build -buildmode exe -buildmode pie -tags tegobpf ./cmd/tego", []string{"-buildmode"}},
		{"CGO_ENABLED=0 go build -tags tegobpf ./cmd/tego", []string{"-buildmode"}},
		{"CGO_ENABLED=1 CGO_ENABLED=0 go build -buildmode=exe -tags tegobpf ./cmd/tego", nil},
		{"CGO_ENABLED=0 CGO_ENABLED=1 go build -buildmode=exe -tags tegobpf ./cmd/tego", []string{"CGO_ENABLED"}},
		{"go build -buildmode=exe -tags tegobpf CGO_ENABLED=0 ./cmd/tego", []string{"CGO_ENABLED"}},
		{"CGO_ENABLED=0 go build -buildmode=exe -tags tegobpf -tags netgo -buildmode=pie ./cmd/tego",
			[]string{"-tags", "-buildmode"}},
	}
	for _, tc := range cases {
		got := staticBuildProblems(strings.Fields(tc.cmd))
		if len(got) != len(tc.want) {
			t.Errorf("%s: problems %q, want %d naming %q", tc.cmd, got, len(tc.want), tc.want)
			continue
		}
		for i, w := range tc.want {
			if !strings.Contains(got[i], w) {
				t.Errorf("%s: problem %d is %q, want one naming %s", tc.cmd, i, got[i], w)
			}
			// Tier 2 has no linking check since ADR 0021 (4): a linking problem gives the release's reason
			// (static and non-PIE for portability) and never says the tier refuses the binary.
			if w != "-tags" && (strings.Contains(got[i], "refuse") || !strings.Contains(got[i], "VERSIONING")) {
				t.Errorf("%s: problem %d is %q, want the release's portability reason (docs/VERSIONING.md "+
					"§5), not a tier 2 refusal", tc.cmd, i, got[i])
			}
		}
	}
}
