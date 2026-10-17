// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestADRIndexCarriesImplementationState: docs/adr/README.md gives each ADR's Status "as its Status line gives
// it". A Status line that says part of the ADR is implemented or built must not be a row that says neither,
// or says the work is still in progress.
func TestADRIndexCarriesImplementationState(t *testing.T) {
	dir := filepath.Join("..", "..", "docs", "adr")
	index, err := os.ReadFile(filepath.Join(dir, "README.md"))
	if err != nil {
		t.Skip("no docs/adr here")
	}
	rows := map[string]string{}
	rowRe := regexp.MustCompile(`^\| \[(\d{4})\]\([^)]*\) \| .*? \| (.*?) \| .*? \|$`)
	for _, line := range strings.Split(string(index), "\n") {
		if m := rowRe.FindStringSubmatch(line); m != nil {
			rows[m[1]] = m[2]
		}
	}
	files, _ := filepath.Glob(filepath.Join(dir, "0[0-9][0-9][0-9]-*.md"))
	if len(files) == 0 || len(rows) == 0 {
		t.Fatalf("read %d ADRs and %d index rows", len(files), len(rows))
	}
	for _, f := range files {
		id := filepath.Base(f)[:4]
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var status string
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "Status:") {
				status = line
				break
			}
		}
		row, ok := rows[id]
		if !ok {
			t.Errorf("ADR %s has no index row", id)
			continue
		}
		says := func(x string) bool { return strings.Contains(x, "implemented") || strings.Contains(x, "built") }
		if says(status) && !says(row) {
			t.Errorf("ADR %s: the Status line gives implementation state, the index row %q gives none", id, row)
		}
		if strings.Contains(row, "not built") && !strings.Contains(status, "not built") {
			t.Errorf("ADR %s: the index row says %q, the Status line lists nothing as not built", id, row)
		}
		if a, b := notBuiltTickets(row), notBuiltTickets(status); a != "" || b != "" {
			for _, tk := range regexp.MustCompile(`T\d+b?`).FindAllString(a, -1) {
				if !regexp.MustCompile(`\b` + tk + `\b`).MatchString(b) {
					t.Errorf("ADR %s: the index row lists %s as not built, the Status line does not", id, tk)
				}
			}
		}
		if strings.Contains(status, "implemented") && strings.Contains(row, "in progress") {
			t.Errorf("ADR %s: the index row says %q, the Status line says implemented", id, row)
		}
	}
}

// notBuiltTickets is the text after "not built" up to the end of that clause.
func notBuiltTickets(x string) string {
	i := strings.Index(x, "not built")
	if i < 0 {
		return ""
	}
	rest := x[i:]
	if j := strings.IndexAny(rest, ";."); j >= 0 {
		rest = rest[:j]
	}
	return rest
}

// TestNoProposedLinkToAcceptedADR: a doc that calls an ADR "proposed" while that ADR's Status line says accepted
// tells the reader the older decision still stands.
func TestNoProposedLinkToAcceptedADR(t *testing.T) {
	root := filepath.Join("..", "..")
	status := map[string]string{}
	files, _ := filepath.Glob(filepath.Join(root, "docs", "adr", "0[0-9][0-9][0-9]-*.md"))
	if len(files) == 0 {
		t.Skip("no docs/adr here")
	}
	for _, f := range files {
		data, _ := os.ReadFile(f)
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "Status:") {
				status[filepath.Base(f)[:4]] = line
				break
			}
		}
	}
	re := regexp.MustCompile(`ADRs? (\d{4})(?: and (\d{4}))?(?: as amended[^()]*)?,? \((?:\w+ )?proposed`)
	var docs []string
	for _, g := range []string{"docs/*.md", "docs/adr/*.md", "docs/p0/*.md", "spec/*/*.md", "*.md"} {
		m, _ := filepath.Glob(filepath.Join(root, g))
		docs = append(docs, m...)
	}
	for _, f := range docs {
		data, _ := os.ReadFile(f)
		for i, line := range strings.Split(string(data), "\n") {
			for _, m := range re.FindAllStringSubmatch(line, -1) {
				for _, id := range m[1:] {
					if id != "" && strings.HasPrefix(status[id], "Status: accepted") {
						t.Errorf("%s:%d: calls ADR %s proposed; its Status line says accepted", f, i+1, id)
					}
				}
			}
		}
	}
}

// TestSpecsDoNotNameSymbolsThatNeverExisted: names once written into a spec sketch that no Go source declares.
func TestSpecsDoNotNameSymbolsThatNeverExisted(t *testing.T) {
	root := filepath.Join("..", "..", "docs", "p0")
	stale := map[string][]string{
		"runtime-launch.md":         {"func AcquireLock", "type RunLock", "// clock.Clock (internal/platform/clock"},
		"supervisor.md":             {"`handleUnixConnect`/", "`handleSendAddr` (", "`handleOpenWrite`/"},
		"enforce-cgroup-observe.md": {"func allocSlot"},
	}
	for f, names := range stale {
		data, err := os.ReadFile(filepath.Join(root, f))
		if err != nil {
			t.Skip("no docs/p0 here")
		}
		for _, n := range names {
			if strings.Contains(string(data), n) {
				t.Errorf("%s still names %q, which the code does not have", f, n)
			}
		}
	}
	// Exact strings miss a stale name in another sentence ("`handleSendAddr`'s"): every backticked
	// handle*/relay* name in the supervisor spec's sections 1-11, outside a Changes list that records a
	// name's removal, must be an identifier the supervisor package's sources have. The Corrections sections
	// after them are a dated history, which names what was removed.
	spec, err := os.ReadFile(filepath.Join(root, "supervisor.md"))
	if err != nil {
		t.Skip("no docs/p0 here")
	}
	srcs, _ := filepath.Glob(filepath.Join("..", "..", "internal", "runtime", "supervisor", "*.go"))
	declared := map[string]bool{}
	identRe := regexp.MustCompile(`\b(?:handle|relay)[A-Z]\w*`)
	for _, s := range srcs {
		if strings.HasSuffix(s, "_test.go") {
			continue
		}
		b, _ := os.ReadFile(s)
		for _, m := range identRe.FindAllString(string(b), -1) {
			declared[m] = true
		}
	}
	if !declared["handleConnect"] {
		t.Fatal("no supervisor sources read")
	}
	nameRe := regexp.MustCompile("`((?:handle|relay)[A-Z]\\w*)`")
	inChanges := false
	for i, line := range strings.Split(string(spec), "\n") {
		if strings.HasPrefix(line, "## Resolved conflicts") { // the end of sections 1-11
			break
		}
		switch {
		case strings.HasPrefix(line, "## "):
			inChanges = false
		case strings.HasPrefix(line, "**Changes.**"):
			inChanges = true
		}
		if inChanges && (strings.HasPrefix(line, "- ") || strings.HasPrefix(line, "  ")) {
			continue
		}
		for _, m := range nameRe.FindAllStringSubmatch(line, -1) {
			if !declared[m[1]] {
				t.Errorf("supervisor.md:%d names `%s`, which internal/runtime/supervisor does not declare", i+1, m[1])
			}
		}
	}
}

// TestADRNotBuiltClaimsAgreeWithTier3Plan: a tier-3 ADR's Status may not list as "not built" a ticket that
// docs/p0/TIER3-PLAN.md marks Done or Built.
func TestADRNotBuiltClaimsAgreeWithTier3Plan(t *testing.T) {
	plan, err := os.ReadFile(filepath.Join("..", "..", "docs", "p0", "TIER3-PLAN.md"))
	if err != nil {
		t.Skip("no plan here")
	}
	done := map[string]bool{}
	rowRe := regexp.MustCompile(`(?m)^\| (T\d+b?) \|(.*)$`)
	for _, m := range rowRe.FindAllStringSubmatch(string(plan), -1) {
		if strings.Contains(m[2], "**Done") || strings.Contains(m[2], "**Built") {
			done[m[1]] = true
		}
	}
	if len(done) == 0 {
		t.Fatal("no finished ticket found in TIER3-PLAN")
	}
	for _, f := range []string{"0024-kernel-decision-plane-tier3-built-now.md", "0025-inode-identity-pinned-by-the-domain.md"} {
		b, err := os.ReadFile(filepath.Join("..", "..", "docs", "adr", f))
		if err != nil {
			t.Skip("no docs/adr here")
		}
		status := ""
		for _, l := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(l, "Status:") {
				status = l
				break
			}
		}
		i := strings.Index(status, "not built")
		if i < 0 {
			continue
		}
		rest := status[i:]
		if j := strings.Index(rest, "TIER3-PLAN"); j >= 0 {
			rest = rest[:j]
		}
		for _, tk := range regexp.MustCompile(`T\d+b?`).FindAllString(rest, -1) {
			if done[tk] {
				t.Errorf("%s: Status says %s is not built, TIER3-PLAN marks it done", f, tk)
			}
		}
	}
}
