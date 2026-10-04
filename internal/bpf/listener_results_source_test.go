// SPDX-License-Identifier: Apache-2.0

package bpf

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The tracepoints are global: eligibility must precede ring/lost-counter work,
// but must not bypass clearing a task's stale marker at syscall exit. This
// source contract also runs without generated objects or a privileged kernel.
func TestListenerResultsRequireCurrentExplicitSlot(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "bpf", "trace_proc.bpf.c"))
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)
	start := strings.Index(src, "static __always_inline int tego_listener_results_on(")
	end := strings.Index(src, "static __always_inline int tego_listener_result_emit(")
	if start < 0 || end <= start {
		t.Fatal("global listener result producer has no explicit-slot eligibility helper")
	}
	eligibility := src[start:end]
	for _, contract := range []string{
		`run\s*&&\s*run->gen\s*&&\s*run->plane\s*!=\s*TEGO_RUN_PLANE_NONE`,
		`run->flags\s*&\s*TEGO_RUN_LISTENER_RESULTS`,
	} {
		if !regexp.MustCompile(contract).MatchString(eligibility) {
			t.Errorf("listener eligibility lacks %s", contract)
		}
	}
	bindEntry := strings.Index(src[end:], `SEC("tracepoint/syscalls/sys_exit_bind")`)
	if bindEntry < 0 {
		t.Fatal("listener result producer has no bind tracepoint entry")
	}
	producer := src[end : bindEntry+end]
	// An io_uring op's producer writes only a plane-marked operation's line (enforce-plane §2.20).
	guard := strings.Index(producer, "if (tego_listener_results_on(run) && (marked || !uring))")
	ring := strings.Index(producer, "ring = tego_ring_of(")
	cleanup := strings.Index(producer, "sc->listen_sock = 0;")
	if guard < 0 || ring <= guard || cleanup <= ring {
		t.Fatal("eligibility must gate ring work, before unconditional marker cleanup")
	}
	// No early ineligible return may leave a task marker alive for a later
	// bind/listen. The only return before cleanup is the absent-scratch case.
	beforeCleanup := producer[:cleanup]
	if strings.Count(beforeCleanup, "return 0;") != 1 ||
		!strings.Contains(beforeCleanup, "if (!sc)\n        return 0;") {
		t.Fatal("listener eligibility exits before clearing an existing marker")
	}
	// IORING_OP_BIND and IORING_OP_LISTEN exit no bind or listen syscall: their ops' fexits are producers too,
	// with the op's result, so a marker never outlives an io_uring op.
	for _, entry := range []string{
		`SEC("fexit/io_bind")`, `tego_listener_result_emit(ret < 0 ? ret : TEGO_READ(req, cqe.res), TEGO_EV_BIND_RESULT, 1);`,
		`SEC("fexit/io_listen")`, `tego_listener_result_emit(ret < 0 ? ret : TEGO_READ(req, cqe.res), TEGO_EV_LISTEN_RESULT, 1);`,
	} {
		if !strings.Contains(src, entry) {
			t.Errorf("trace_proc.bpf.c lacks the io_uring listener producer %s", entry)
		}
	}
}
