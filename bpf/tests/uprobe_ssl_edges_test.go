// SPDX-License-Identifier: Apache-2.0

package bpftests

import (
	"strings"
	"testing"
)

// The edge cases of docs/p0/capture-derive.md §6 that are a property of bpf/uprobe_ssl.bpf.c alone. Like the
// rest of this directory they read the source: the file needs clang to build and root to load, so what they
// pin is the shape of the code the spec's reasoning depends on.

// TestReadExReturnReadsAZeroedSlot is capture-derive.md E13: OpenSSL may return 1 from SSL_read_ex without
// ever writing *readbytes, so the return probe reads it into a slot it zeroed first. An unwritten value is "no
// data", never stack garbage read as a length.
func TestReadExReturnReadsAZeroedSlot(t *testing.T) {
	t.Parallel()
	body := functionBody(t, uprobeSSL(t), "tego_ssl_read_return")
	for _, want := range []struct{ frag, why string }{
		{"length = 0, readbytes = 0;", "the slot the length is read into starts at zero"},
		{"if (ret != 1 || val.len_ptr == 0)", "SSL_read_ex's length counts only when it returned 1, with a place to read it"},
	} {
		if !strings.Contains(body, want.frag) {
			t.Errorf("tego_ssl_read_return no longer has %q: %s", want.frag, want.why)
		}
	}
}

// TestUnreadableReadExLengthIsAHole is the other half of E13: a *readbytes the return probe cannot read (a page
// the non-sleepable uretprobe cannot fault in, or a slot another thread of the agent unmapped) belongs to a
// call that returned 1 and so moved bytes. It used to read as length 0, which tego_ssl_capture emits nothing
// for: no number, no record, no counter, and the next response on a keep-alive connection paired with this
// one's request. The failed read must emit a hole of unknown length, which takes the connection's next number.
func TestUnreadableReadExLengthIsAHole(t *testing.T) {
	t.Parallel()
	body := functionBody(t, uprobeSSL(t), "tego_ssl_read_return")
	at := strings.Index(body, "sizeof(readbytes), (const void *)val.len_ptr) != 0")
	if at < 0 {
		t.Fatalf("tego_ssl_read_return no longer reads *readbytes the way this test expects")
	}
	failed := body[at:]
	if end := strings.Index(failed, "length = readbytes;"); end >= 0 {
		failed = failed[:end]
	}
	for _, frag := range []string{"tego_ssl_hole(", "TEGO_SSL_HOLE_NOLENGTH", "return 0;"} {
		if !strings.Contains(failed, frag) {
			t.Errorf("the failed *readbytes read does not %q: a read that moved bytes vanishes without a "+
				"number, and the connection's next response pairs with this one's request", frag)
		}
	}
}

// TestNothingIsEmittedForAZeroLengthCall is capture-derive.md E14: renegotiation and KeyUpdate make
// zero-length application-data calls, and no chunk leaves the kernel for one, so httpstream never sees it. A
// write of no bytes returns before the capture, a read that moved none does too, and the split itself emits
// nothing for a call of length 0.
func TestNothingIsEmittedForAZeroLengthCall(t *testing.T) {
	t.Parallel()
	path := uprobeSSL(t)
	if w := functionBody(t, path, "tego_ssl_write"); !strings.Contains(w, "if (num <= 0)\n        return 0;") {
		t.Errorf("tego_ssl_write no longer returns before the capture for a non-positive length")
	}
	if r := functionBody(t, path, "tego_ssl_read_return"); !strings.Contains(r, "if (ret <= 0)\n            return 0;") {
		t.Errorf("tego_ssl_read_return no longer returns before the capture for a read that moved no bytes")
	}
	if c := functionBody(t, path, "tego_ssl_capture"); !strings.Contains(c, "total == 0") {
		t.Errorf("tego_ssl_capture no longer emits nothing for a call of length 0")
	}
}

// TestCaptureIsKeyedByThreadAndFilteredByCgroup is capture-derive.md E10: a child that forks after SSL_new and
// writes on the inherited SSL* is a new pid_tgid, correctly attributed while it stays in the run's cgroup and
// filtered once it does not. The write probe decides by the cgroup's row in the run set and by nothing about
// process ancestry, and its scratch rows are keyed by pid_tgid.
func TestCaptureIsKeyedByThreadAndFilteredByCgroup(t *testing.T) {
	t.Parallel()
	path := uprobeSSL(t)
	w := functionBody(t, path, "tego_ssl_write")
	if !strings.Contains(w, "bpf_get_current_cgroup_id()") || !strings.Contains(w, "tego_run_lookup(&tego_run_set, cgroup_id)") ||
		!strings.Contains(w, "if (!run") {
		t.Errorf("tego_ssl_write no longer filters by the cgroup's row in the run set")
	}
	for _, ancestry := range []string{"real_parent", "task_struct", "bpf_get_current_task"} {
		if strings.Contains(w, ancestry) {
			t.Errorf("tego_ssl_write consults %s: a forked child's attribution would depend on ancestry, not its cgroup", ancestry)
		}
	}
	if !strings.Contains(read(t, path), "key.pid_tgid = id;") {
		t.Errorf("the scratch rows are no longer keyed by pid_tgid")
	}
}

// TestWriteLengthIsKnownAtEntry is the write half of capture-derive.md E12 (a SIGKILL between an SSL_write's
// entry and return loses nothing, because the length is the call's argument): the write probes capture from
// their entry, and only the read path waits for its return, where its length is known.
func TestWriteLengthIsKnownAtEntry(t *testing.T) {
	t.Parallel()
	path := uprobeSSL(t)
	if w := functionBody(t, path, "tego_ssl_write"); !strings.Contains(w, "tego_ssl_capture(") ||
		!strings.Contains(w, "PT_REGS_PARM3(ctx)") {
		t.Errorf("tego_ssl_write no longer captures at entry from its length argument")
	}
	if r := functionBody(t, path, "tego_ssl_read_return"); !strings.Contains(r, "PT_REGS_RC(ctx)") {
		t.Errorf("a read's length is no longer taken at its return")
	}
}
