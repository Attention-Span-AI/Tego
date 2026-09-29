// SPDX-License-Identifier: Apache-2.0

package bpftests

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestTraceProcWakesItsReaderOnlyWhereItMust pins trace_proc's submit flags (enforce-cgroup-observe §9). Its
// open, file-operation and connect records submit with tego_quiet's flags, which leave the reader asleep unless
// the ring is filling: with the kernel's default flag every one of them woke the reader, whose wakeup the process
// that submitted it paid, one an open. Exec and exit force the wakeup, because the process cache and the uprobe
// source's attach at exec are built from them and, behind a quiet record, the default would not wake the reader
// at all. The open of a libssl forces it too (tego_libssl_named), since the uprobe source attaches the library
// at that open. The two truncate programs submit through tego_truncate, and a record a task held
// (struct tego_held) is submitted quiet by tego_held_flush, whichever program ends the hold (ADR 0016 (3)).
func TestTraceProcWakesItsReaderOnlyWhereItMust(t *testing.T) {
	t.Parallel()
	want := map[string]string{
		"tracepoint/syscalls/sys_exit_execve":   "tego_exec_result_emit(",
		"tracepoint/syscalls/sys_exit_execveat": "tego_exec_result_emit(",
		"tracepoint/syscalls/sys_exit_bind":     "tego_listener_result_emit(",
		"tracepoint/syscalls/sys_exit_listen":   "tego_listener_result_emit(",
		"fexit/io_bind":                         "tego_listener_result_emit(",
		"fexit/io_listen":                       "tego_listener_result_emit(",
		"tp_btf/sched_process_exec":             "bpf_ringbuf_submit(e, BPF_RB_FORCE_WAKEUP)",
		"tp_btf/sched_process_exit":             "bpf_ringbuf_submit(e, BPF_RB_FORCE_WAKEUP)",
		"fexit/security_file_open":              "bpf_ringbuf_submit(e, tego_quiet(ring, tego_libssl_named(file)))",
		"fexit/security_path_unlink":            "bpf_ringbuf_submit(e, tego_quiet(ring, 0))",
		"fexit/security_path_rename":            "bpf_ringbuf_submit(e, tego_quiet(ring, 0))",
		"fexit/security_path_mkdir":             "bpf_ringbuf_submit(e, tego_quiet(ring, 0))",
		"fexit/security_path_mknod":             "bpf_ringbuf_submit(e, tego_quiet(ring, 0))",
		"fexit/security_path_rmdir":             "bpf_ringbuf_submit(e, tego_quiet(ring, 0))",
		"fexit/security_path_link":              "bpf_ringbuf_submit(e, tego_quiet(ring, 0))",
		"fexit/security_path_symlink":           "bpf_ringbuf_submit(e, tego_quiet(ring, 0))",
		"fexit/security_path_truncate":          "tego_truncate(",
		"fexit/security_file_truncate":          "tego_truncate(",
		"fentry/security_socket_connect":        "bpf_ringbuf_submit(e, tego_quiet(ring, 0))",
	}
	seen := map[string]bool{}
	for _, p := range programs(t, filepath.Join(sourceDir, "trace_proc.bpf.c")) {
		call, ok := want[p.section]
		if !ok {
			t.Errorf("SEC(%q) in trace_proc.bpf.c has no wakeup rule here: say which flags it submits with", p.section)
			continue
		}
		seen[p.section] = true
		if call == "tego_truncate(" || call == "tego_exec_result_emit(" || call == "tego_listener_result_emit(" {
			if strings.Contains(p.body, "bpf_ringbuf_submit(") || !strings.Contains(p.body, call) {
				t.Errorf("SEC(%q) should submit only through %s", p.section, call)
			}
			continue
		}
		if n := strings.Count(p.body, "bpf_ringbuf_submit("); n != 1 || !strings.Contains(p.body, call) {
			t.Errorf("SEC(%q) submits %d time(s), want exactly once as %s", p.section, n, call)
		}
	}
	for section := range want {
		if !seen[section] {
			t.Errorf("trace_proc.bpf.c has no SEC(%q) program", section)
		}
	}
	src := read(t, filepath.Join(sourceDir, "trace_proc.bpf.c"))
	result := helperBody(t, src, "tego_exec_result_emit")
	if strings.Count(result, "bpf_ringbuf_submit(") != 1 ||
		!strings.Contains(result, "bpf_ringbuf_submit(e, BPF_RB_FORCE_WAKEUP)") {
		t.Error("a failed exec's terminal result must wake its waiting attempt reader")
	}
	listenerResult := helperBody(t, src, "tego_listener_result_emit")
	if strings.Count(listenerResult, "bpf_ringbuf_submit(") != 1 || !strings.Contains(squash(listenerResult), "bpf_ringbuf_submit(e,BPF_RB_FORCE_WAKEUP)") {
		t.Error("a bind/listen terminal result must wake its waiting attempt reader exactly once")
	}
	for _, helper := range []string{"tego_truncate", "tego_held_flush"} {
		body := helperBody(t, src, helper)
		n, q := strings.Count(body, "bpf_ringbuf_submit("), strings.Count(body, "bpf_ringbuf_submit(e, tego_quiet(ring, 0))")
		if n == 0 || n != q {
			t.Errorf("%s submits %d time(s), %d of them quiet; every one is tego_quiet(ring, 0)", helper, n, q)
		}
	}
	for _, flag := range []string{"BPF_RB_NO_WAKEUP", "bpf_ringbuf_query(ring, BPF_RB_AVAIL_DATA)"} {
		if !strings.Contains(src, flag) {
			t.Errorf("trace_proc.bpf.c no longer uses %s: tego_quiet leaves the reader asleep only while the ring "+
				"is not filling", flag)
		}
	}
}

// helperBody is the body of a static function of src, by brace counting from the brace after its name.
func helperBody(t *testing.T, src, name string) string {
	t.Helper()
	i := strings.Index(src, " "+name+"(")
	if i < 0 {
		t.Fatalf("no function %s", name)
	}
	open := strings.Index(src[i:], "{")
	if open < 0 {
		t.Fatalf("%s has no body", name)
	}
	depth := 0
	for j := i + open; j < len(src); j++ {
		switch src[j] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return src[i+open : j+1]
			}
		}
	}
	t.Fatalf("%s's body is unbalanced", name)
	return ""
}
