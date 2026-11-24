// SPDX-License-Identifier: Apache-2.0

//go:build integration

package cgroup

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestConcurrentFailureDiagnostics(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "r-test")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	ledger := `{"kind":"run_start"}
{"kind":"fs","path":"unrelated-file"}
{"kind":"gap","why":"bpf-trampoline-miss/shared-build","count":7}
{"kind":"gap","why":"capture-read-failed"}
{"kind":"run_end","reason":"error","detail":"capture: usage unreadable"}
`
	if err := os.WriteFile(filepath.Join(dir, "events.jsonl"), []byte(ledger), 0o600); err != nil {
		t.Fatal(err)
	}
	stderr := "discard-this-prefix\n" + strings.Repeat("phase\n", 3000) + "stderr-last\n"
	got := concurrentFailureDiagnostics(root, stderr)
	for _, want := range []string{`"detail":"capture: usage unreadable"`, `"reason":"error"`, `"why":"bpf-trampoline-miss/shared-build"`, `"count":7`, `"why":"capture-read-failed"`, "stderr-last", "8192 of"} {
		if !strings.Contains(got, want) {
			t.Errorf("diagnostics lack %q: %s", want, got)
		}
	}
	for _, unwanted := range []string{"unrelated-file", "discard-this-prefix"} {
		if strings.Contains(got, unwanted) {
			t.Errorf("diagnostics contain %q", unwanted)
		}
	}
}

func TestConcurrentFailureDiagnosticsIncompleteLedger(t *testing.T) {
	for _, tc := range []struct{ name, content, want string }{
		{"missing", "", "ledger lookup"},
		{"truncated", `{"kind":"gap","why":"ring-buffer-drop"}` + "\n" + `{"kind":`, "decode ledger"},
		{"no end", `{"kind":"run_start"}` + "\n", "run_end: absent"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			if tc.content != "" {
				dir := filepath.Join(root, "r-test")
				if err := os.Mkdir(dir, 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, "events.jsonl"), []byte(tc.content), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			got := concurrentFailureDiagnostics(root, "short stderr")
			if !strings.Contains(got, tc.want) || !strings.Contains(got, "short stderr") || !strings.Contains(got, "run_end: absent") {
				t.Fatalf("missing diagnostic or stderr: %s", got)
			}
			if tc.name == "truncated" && !strings.Contains(got, "ring-buffer-drop") {
				t.Fatal("a truncated final line hid an earlier gap")
			}
		})
	}
}

func TestConcurrentFailureDiagnosticsBoundedLedger(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "r-test")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	var ledger strings.Builder
	for range 200 {
		ledger.WriteString(`{"kind":"gap","why":"bpf-trampoline-miss/shared-build","detail":"` + strings.Repeat("x", 5000) + `"}` + "\n")
	}
	ledger.WriteString(`{"kind":"run_end","reason":"error","detail":"important-end-detail-` + strings.Repeat("y", 5000) + `"}` + "\n")
	if err := os.WriteFile(filepath.Join(dir, "events.jsonl"), []byte(ledger.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	got := concurrentFailureDiagnostics(root, "short stderr")
	if count := strings.Count(got, "gap: "); count != 64 {
		t.Errorf("printed %d gap lines, want 64", count)
	}
	for _, line := range strings.Split(got, "\n") {
		if (strings.HasPrefix(line, "gap: ") || strings.HasPrefix(line, "run_end: ")) && len(line) > 4096 {
			t.Errorf("printed ledger line of %d bytes, want at most 4096", len(line))
			break
		}
	}
	for _, want := range []string{"136 more gap lines omitted", `run_end: {"kind":"run_end","reason":"error","detail":"important-end-detail-`, "ledger line truncated", "short stderr"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q", want)
		}
	}
	if strings.Contains(got, "run_end: absent") {
		t.Error("omitted run_end reported as absent")
	}
	if len(got) > 65*4096+4096 {
		t.Errorf("diagnostics contain %d bytes, want a bounded ledger and stderr", len(got))
	}
}

func TestConcurrentDiagnosticTail(t *testing.T) {
	for _, name := range []string{"stdout", "stderr"} {
		t.Run(name, func(t *testing.T) {
			got := concurrentDiagnosticTail(name, "discard-prefix"+strings.Repeat("x", 8192-8)+"lastdata")
			if strings.Contains(got, "discard-prefix") || !strings.HasSuffix(got, "lastdata") {
				t.Fatalf("tail does not retain only the last 8 KiB: %d bytes", len(got))
			}
			if !strings.Contains(got, name+" truncated: 14 earlier bytes omitted") || !strings.Contains(got, "8192 of 8206 bytes") {
				t.Errorf("missing explicit truncation size")
			}
			if len(got) > 8192+128 {
				t.Errorf("tail has %d bytes, want 8 KiB plus its bounded header", len(got))
			}
			short := concurrentDiagnosticTail(name, "short output")
			if strings.Contains(short, "truncated") || !strings.HasSuffix(short, "short output") {
				t.Errorf("short output incorrectly truncated: %s", short)
			}
		})
	}
}

func TestConcurrentLauncherMemory(t *testing.T) {
	for _, tc := range []struct {
		name    string
		usage   any
		want    uint64
		wantErr string
	}{
		{"absent", nil, 0, "unavailable"},
		{"unexpected type", 72, 0, "unavailable"},
		{"nil rusage", (*syscall.Rusage)(nil), 0, "unavailable"},
		{"empty", &syscall.Rusage{}, 0, "unavailable"},
		{"negative", &syscall.Rusage{Maxrss: -1}, 0, "unavailable"},
		{"sample", &syscall.Rusage{Maxrss: 72 << 10}, 72 << 20, ""},
		{"at bound", &syscall.Rusage{Maxrss: 256 << 10}, 256 << 20, ""},
		{"above bound", &syscall.Rusage{Maxrss: (256 << 10) + 1}, (256 << 20) + 1024, "exceeds"},
		{"overflow", &syscall.Rusage{Maxrss: 1 << 54}, 0, "overflows"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := concurrentLauncherMemory(tc.usage)
			if got != tc.want {
				t.Errorf("peak RSS %d, want %d bytes", got, tc.want)
			}
			if tc.wantErr == "" && err != nil || tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
				t.Errorf("memory error %v, want %q", err, tc.wantErr)
			}
		})
	}
}

func TestConcurrentFailureDiagnosticsLastRunEnd(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "r-test")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	ledger := `{"kind":"run_end","detail":"earlier-end"}` + "\n" + `{"kind":"run_end","detail":"last-end"}` + "\n"
	if err := os.WriteFile(filepath.Join(dir, "events.jsonl"), []byte(ledger), 0o600); err != nil {
		t.Fatal(err)
	}
	got := concurrentFailureDiagnostics(root, "")
	if strings.Contains(got, "earlier-end") || !strings.Contains(got, "last-end") || strings.Count(got, "run_end: ") != 1 {
		t.Errorf("want one final run_end, got: %s", got)
	}
}

// TestConcurrentKernelFaults holds the round's kernel evidence to what a fault looks like: the 7.0.14 oops of
// docs/GAPS.md C76 is kept with the lines that place it, and a round whose log has only context or ordinary lines
// reports nothing, so a benign uprobe message never fails a round.
func TestConcurrentKernelFaults(t *testing.T) {
	oops := []string{
		"BUG: kernel NULL pointer dereference, address: 0000000000000038",
		"CPU: 0 UID: 1000 PID: 2983 Comm: python3 Not tainted 7.0.14-201.fc44.x86_64 #1 PREEMPT(lazy)",
		"RIP: 0010:__bpf_ringbuf_reserve+0x1e/0x390",
		"Call Trace:",
		" bpf_prog_91017e82eed846f9_tego_ssl_multi_return+0x5d3/0x1cee",
		" uprobe_multi_link_ret_handler+0x15/0x20",
		"loop0: detected capacity change from 0 to 8192",
	}
	got := kernelFaults(oops)
	for _, want := range []string{"BUG: kernel NULL pointer dereference", "Comm: python3", "__bpf_ringbuf_reserve", "tego_ssl_multi_return", "uprobe_multi_link_ret_handler"} {
		if !strings.Contains(got, want) {
			t.Errorf("kernel faults lack %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "capacity change") {
		t.Errorf("kernel faults keep an ordinary line:\n%s", got)
	}
	for _, quiet := range [][]string{
		{"uprobe: test[123] failed to register", "loop0: detected capacity change from 0 to 8192"},
		{"audit: type=1334 audit(1.2:3): prog-id=12 op=LOAD", "level=DEBUG msg=\"uprobe: placed\""},
	} {
		if got := kernelFaults(quiet); got != "" {
			t.Errorf("kernelFaults(%q) = %q, want none", quiet, got)
		}
	}
	if got := kmsgText([]byte("1,455,287231235,-;BUG: kernel NULL pointer dereference\n")); got != "BUG: kernel NULL pointer dereference" {
		t.Errorf("kmsgText = %q", got)
	}
}

// TestConcurrentOwnLogLines holds the own-log evidence to the failed run's capture lines: another run's lines and
// this run's unrelated ones stay out, and the run is named by its closing summary.
func TestConcurrentOwnLogLines(t *testing.T) {
	dir := t.TempDir()
	log := `time=1 level=DEBUG msg="uprobe: gap malformed: 1 requests with no response at close" pid=9 run=r-aa-1
time=2 level=DEBUG msg="uprobe: gap ring-buffer-drop : the kernel's lost-chunk counter went from 0 to 1" pid=9 run=r-aa-1
time=3 level=DEBUG msg="uprobe: gap malformed: other" pid=8 run=r-bb-2
time=4 level=INFO msg="run: started" pid=9 run=r-aa-1
`
	if err := os.WriteFile(filepath.Join(dir, "tego.log"), []byte(log), 0o600); err != nil {
		t.Fatal(err)
	}
	got := concurrentOwnLogLines(dir, "note: x\ntego run: r-aa-1 ended (ended: error) · tier cgroup\n")
	for _, want := range []string{"no response at close", "lost-chunk counter went from 0 to 1", "(2 matched, last 2 shown)"} {
		if !strings.Contains(got, want) {
			t.Errorf("own log lines lack %q:\n%s", want, got)
		}
	}
	for _, unwanted := range []string{"r-bb-2", "run: started"} {
		if strings.Contains(got, unwanted) {
			t.Errorf("own log lines keep %q:\n%s", unwanted, got)
		}
	}
	if got := concurrentOwnLogLines(dir, "no summary"); !strings.Contains(got, "no run id") {
		t.Errorf("without a summary: %q", got)
	}
}
