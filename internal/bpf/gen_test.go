// SPDX-License-Identifier: Apache-2.0

package bpf

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// generateLine is one bpf2go invocation in gen.go: its -target list, its identifier and its C source.
type generateLine struct {
	targets []string
	ident   string
	source  string
}

// generateLines parses gen.go's live //go:generate directives, skipping the commented-out tier-3 examples.
func generateLines(t *testing.T) []generateLine {
	t.Helper()
	b, err := os.ReadFile("gen.go")
	if err != nil {
		t.Fatalf("read gen.go: %v", err)
	}
	lineRe := regexp.MustCompile(`(?m)^//go:generate go run github\.com/cilium/ebpf/cmd/bpf2go (.*)$`)
	targetRe := regexp.MustCompile(`-target (\S+)`)
	var out []generateLine
	for _, m := range lineRe.FindAllStringSubmatch(string(b), -1) {
		args := m[1]
		tm := targetRe.FindStringSubmatch(args)
		if tm == nil {
			t.Fatalf("a bpf2go line names no -target: %s", args)
		}
		// The identifier and the source are the two words before " -- ", once the flags and their values are
		// removed: cflags is quoted, every other flag takes one word.
		head := strings.SplitN(args, " -- ", 2)[0]
		head = regexp.MustCompile(`-cflags "[^"]*"`).ReplaceAllString(head, "")
		head = regexp.MustCompile(`-(cc|target|type|tags) \S+`).ReplaceAllString(head, "")
		words := strings.Fields(head)
		if len(words) != 2 {
			t.Fatalf("cannot find the identifier and source in %q (left %v)", args, words)
		}
		out = append(out, generateLine{targets: strings.Split(tm[1], ","), ident: words[0], source: words[1]})
	}
	if len(out) == 0 {
		t.Fatal("gen.go has no bpf2go lines")
	}
	return out
}

// TestUprobeObjectsNameAnArchitecture pins the rule `make gen` broke on. libbpf's PT_REGS_* macros, and the
// BPF_KPROBE/BPF_UPROBE wrappers built on them, read a probed function's arguments out of struct pt_regs,
// whose layout is per architecture; bpf_tracing.h refuses them at compile time unless __TARGET_ARCH_<arch>
// is defined, and bpf2go defines it only for an architecture target, never for bpf, bpfel or bpfeb. gen.go
// compiled uprobe_ssl.bpf.c with -target bpfel,bpfeb, so clang stopped with twelve "please provide -target
// that is not bpf, bpfel or bpfeb" errors and the tree could not be regenerated at all.
func TestUprobeObjectsNameAnArchitecture(t *testing.T) {
	generic := map[string]bool{"bpf": true, "bpfel": true, "bpfeb": true}
	archRe := regexp.MustCompile(`\b(PT_REGS_[A-Z0-9_]+|BPF_[UK](RET)?PROBE)\b`)
	for _, g := range generateLines(t) {
		src, err := os.ReadFile(filepath.Clean(g.source))
		if err != nil {
			t.Fatalf("%s: read %s: %v", g.ident, g.source, err)
		}
		uses := archRe.FindString(string(src))
		for _, target := range g.targets {
			if uses != "" && generic[target] {
				t.Errorf("%s reads registers with %s but gen.go compiles it for %q; name architectures "+
					"(amd64,arm64) so bpf2go defines __TARGET_ARCH", g.ident, uses, target)
			}
		}
	}
}
