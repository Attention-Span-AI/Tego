// SPDX-License-Identifier: Apache-2.0

package linewords

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/check/gaps"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// recordConsts is every string constant of pkg/spec/record (its non-test source files) whose name starts with one of
// prefixes, by name. It reads the source, so a constant added there is checked here without anyone listing it.
func recordConsts(t *testing.T, prefixes ...string) map[string]string {
	t.Helper()
	files, err := filepath.Glob(filepath.Join("..", "..", "..", "pkg", "spec", "record", "*.go"))
	if err != nil || len(files) == 0 {
		t.Fatalf("pkg/spec/record source: %v (%d files)", err, len(files))
	}
	out := map[string]string{}
	fset := token.NewFileSet()
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		af, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range af.Decls {
			gd, ok := d.(*ast.GenDecl)
			if !ok || gd.Tok != token.CONST {
				continue
			}
			for _, s := range gd.Specs {
				vs := s.(*ast.ValueSpec)
				for i, n := range vs.Names {
					if i >= len(vs.Values) {
						continue
					}
					lit, ok := vs.Values[i].(*ast.BasicLit)
					if !ok || lit.Kind != token.STRING {
						continue
					}
					for _, p := range prefixes {
						if strings.HasPrefix(n.Name, p) {
							v, err := strconv.Unquote(lit.Value)
							if err != nil {
								t.Fatal(err)
							}
							out[n.Name] = v
						}
					}
				}
			}
		}
	}
	return out
}

// TestGlossaryCoversRecordConstants: every record Gap*, Reason*, Source*, Mechanism*, PlaneReason*,
// ReadsNotifiedWhy* and FSReadsWhy* constant (and every Kind) has words, so a code added to the record without
// words fails here instead of reaching the line page as a bare code.
func TestGlossaryCoversRecordConstants(t *testing.T) {
	type check struct {
		prefix string
		words  func(string) (string, bool)
	}
	gap := func(v string) (string, bool) {
		if w, ok := GapWhat(v); ok {
			return w, ok
		}
		return GapWhy(v)
	}
	checks := []check{
		// The longer prefixes first: ReadsNotifiedWhy is not a Reason, PlaneReason is not a Reason either.
		{"ReadsNotifiedWhy", ReadsNotifiedWhy}, {"FSReadsWhy", FSReadsWhy}, {"PlaneReason", PlaneReason},
		{"Mechanism", Mechanism}, {"Reason", Reason}, {"Source", Source}, {"Gap", gap}, {"Kind", Kind},
	}
	var prefixes []string
	for _, c := range checks {
		prefixes = append(prefixes, c.prefix)
	}
	consts := recordConsts(t, prefixes...)
	seen := map[string]int{}
	for name, v := range consts {
		for _, c := range checks {
			if !strings.HasPrefix(name, c.prefix) {
				continue
			}
			seen[c.prefix]++
			if w, ok := c.words(v); !ok || w == "" || w == v {
				t.Errorf("record.%s = %q has no words (%s)", name, v, c.prefix)
			}
			break
		}
	}
	// The record names at least these many of each, so a parse that finds none fails rather than passes empty.
	for prefix, least := range map[string]int{"Reason": 20, "Source": 10, "Gap": 15, "Mechanism": 3, "PlaneReason": 9,
		"ReadsNotifiedWhy": 9, "FSReadsWhy": 6, "Kind": 15} {
		if seen[prefix] < least {
			t.Errorf("%s: found %d constants, want at least %d", prefix, seen[prefix], least)
		}
	}
}

// TestLabels: a known key, a nested key by its full path and by its last part, a capability under a map key, and an
// unknown key, which is returned as is and reported unknown.
func TestLabels(t *testing.T) {
	for _, tc := range []struct {
		key, want string
		ok        bool
	}{
		{"argv_truncated", "Command line cut", true},
		{"resources.memory_peak", "Peak memory", true},
		{"live_block.by", "By", true},
		{"capabilities.fs.deny_read", "What this protection level can do: fs.deny_read", true},
		{"headers.user-agent", "Headers: user-agent", true},
		{"gate_rule", "Gate rule", true},
		{"zz_never_written", "zz_never_written", false},
		{"resources.zz_new", "resources.zz_new", false},
	} {
		got, ok := Label(tc.key)
		if got != tc.want || ok != tc.ok {
			t.Errorf("Label(%q) = %q, %v; want %q, %v", tc.key, got, ok, tc.want, tc.ok)
		}
	}
}

// TestValues: the words for values a person cannot read as written, and the value as written where there are none.
func TestValues(t *testing.T) {
	for _, tc := range []struct {
		key, raw, want string
		ok             bool
	}{
		{"reason", `"read-denied"`, "a read the rules refuse", true},
		{"reason", `"zz-new-code"`, "zz-new-code", false},
		{"source", `"seccomp"`, "Tego's system-call supervisor", true},
		{"verdict", `"observed"`, "recorded only, not decided", true},
		{"hold", `"first_write"`, "the first data sent on a connection", true},
		{"why", `"live-block-added"`, "a live block was added", true},
		{"mechanism", `"landlock"`, "the kernel's Landlock rules", true},
		{"plane_reason", `"pin-mismatch"`, "the program does not match its pinned fingerprint", true},
		{"reads_notified.why", `"reason"`, "the contract asks for refused reads to be recorded", true},
		{"fs_reads.why", `"nested"`, "a secret file sits inside a folder the agent may change", true},
		{"errno", `13`, "EACCES (permission denied)", true},
		{"errno", `4095`, "4095", false},
		{"syscall_ret", `3`, "3 (succeeded)", true},
		{"syscall_ret", `-13`, "failed: EACCES (permission denied)", true},
		{"flags", `577`, "write, create, empty it first (577)", true},
		{"flags", `524288`, "read (524288)", true},
		{"resources.memory_peak", `6606848`, "6.3 MiB", true},
		{"resources.cpu_usage_usec", `429432`, "429 ms", true},
		{"after_s", `41.709378648`, "41.7 s", true},
		{"argv", `["git","status"]`, "git status", false},
		{"best_effort", `["fs.deny_write","net.unix"]`, "fs.deny_write, net.unix", false},
		{"approved", `true`, "yes", true},
		{"bpf_hash", `""`, "empty", true},
		{"zz_unknown", `{"a":1}`, `{"a":1}`, false},
	} {
		got, ok := Value(tc.key, []byte(tc.raw))
		if got != tc.want || ok != tc.ok {
			t.Errorf("Value(%s, %s) = %q, %v; want %q, %v", tc.key, tc.raw, got, ok, tc.want, tc.ok)
		}
	}
}

// TestWho names a person from a principal, with the caller's lookup, and never invents a name.
func TestWho(t *testing.T) {
	names := func(uid string) string { return map[string]string{"1000": "alice"}[uid] }
	for by, want := range map[string]string{
		"uid:1000 pid:4035742":           "alice",
		"uid:1000 pid:51234 dashboard":   "alice, from the dashboard",
		"uid:1001 pid:1 cli":             "user 1001, from the command line",
		"service:deploy-nightly-triage":  "the service deploy-nightly-triage",
		"standing:q-1":                   "an earlier answer for the rest of this run",
		"human":                          "human",
		"uid:1000 pid:4035742 always":    "alice",
		"uid:1000 pid:4035742 somewhere": "alice (somewhere)",
	} {
		if got := Who(by, names); got != want {
			t.Errorf("Who(%q) = %q, want %q", by, got, want)
		}
	}
}

// TestDurationAndBytes: the units a person reads.
func TestDurationAndBytes(t *testing.T) {
	for d, want := range map[time.Duration]string{0: "0 s", 850 * time.Microsecond: "850 µs", 12 * time.Millisecond: "12 ms",
		41700 * time.Millisecond: "41.7 s", 125 * time.Second: "2 m 5 s", 63 * time.Minute: "1 h 3 m"} {
		if got := Duration(d); got != want {
			t.Errorf("Duration(%v) = %q, want %q", d, got, want)
		}
	}
	for n, want := range map[int64]string{12: "12 bytes", 2048: "2.0 KiB", 17315: "16.9 KiB", 6606848: "6.3 MiB"} {
		if got := Bytes(n); got != want {
			t.Errorf("Bytes(%d) = %q, want %q", n, got, want)
		}
	}
}

// TestMask hides a credential and leaves ordinary words, with and without the memo.
func TestMask(t *testing.T) {
	in := "curl -H 'Authorization: Bearer abcdef123456' https://u:pw1234@example.com --token=s3cr3tvalue"
	got := Mask(in)
	for _, leak := range []string{"abcdef123456", "pw1234", "s3cr3tvalue"} {
		if strings.Contains(got, leak) {
			t.Errorf("Mask left %q: %s", leak, got)
		}
	}
	if Mask("pip install basic requests") != "pip install basic requests" {
		t.Error("Mask changed ordinary words")
	}
	long := in + strings.Repeat(" x", MaskMemoMin)
	want := MaskNow(long)
	for i := range 2 { // the first call fills the memo, the second reads it
		if Mask(long) != want {
			t.Errorf("Mask (call %d) differs from MaskNow", i+1)
		}
	}
}

// TestLiveWordsMatchTegoStatus: tego status says a live change in the glossary's words. gaps sits below this package
// and the two cannot share a table (this one imports nothing of the module), so this holds them equal.
func TestLiveWordsMatchTegoStatus(t *testing.T) {
	for _, why := range []string{
		record.GapLiveBlockAdded, record.GapLiveBlockRemoved, record.GapLiveBlockExpired, record.GapLiveUnblockExpired,
		record.GapLiveRuleLifted, record.GapLiveRuleRestored, record.GapLiveLiftExpired, record.GapLiveLiftRefused,
		record.GapRunPaused, record.GapRunResumed, record.GapPauseFailed, record.GapResumeFailed,
		record.GapMCPToolChanged, record.GapModelRouteChanged,
	} {
		status, ok := gaps.LiveWords(why)
		if !ok {
			t.Errorf("%s: tego status has no words", why)
			continue
		}
		if page, _ := GapWhy(why); page != status {
			t.Errorf("%s: the page says %q, tego status %q", why, page, status)
		}
	}
}
