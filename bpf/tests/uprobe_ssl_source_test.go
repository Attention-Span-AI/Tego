// SPDX-License-Identifier: Apache-2.0

package bpftests

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// uprobeSSLSource is the one file these checks are about. Everything here is a property of
// bpf/uprobe_ssl.bpf.c that no compiler and no kernel on a CI runner can check for us: the file needs clang
// to build and root to load, so the shape of its capture paths is pinned the way bpf/tests pins every other
// C invariant (see doc.go).
const uprobeSSLSource = "uprobe_ssl.bpf.c"

// uprobeSSL returns the source path, skipping when another ticket has not landed the file yet.
func uprobeSSL(t *testing.T) string {
	t.Helper()
	path := filepath.Join(sourceDir, uprobeSSLSource)
	if _, err := os.Stat(path); err != nil {
		t.Skipf("%s not present: %v", uprobeSSLSource, err)
	}
	return path
}

// TestLostChunkMarksTheRestOfTheCall covers §8 I2, which claims "Seq lets the reader detect (never silently
// accept) a gap". On its own it cannot: userspace assigns Seq on arrival (uprobe.go's u.seq[sk]++), so Seq
// is monotonic by construction and a chunk the kernel never wrote leaves no hole in it. A body spliced
// across the loss is then recorded as a complete body — the audit consequence Pixie's HTTP/2 tracing work
// describes for any tracer that misses bytes mid-stream and cannot resynchronise.
//
// Two of the three loss paths can be marked from the kernel and must be. A failed bpf_probe_read_user still
// holds its reserved record, so it is submitted as a zero-length chunk whose skipped is the bytes it could not
// read, naming the connection that lost bytes and how many rather than discarded, and it is not counted as a
// ring-buffer drop, which it is not; and a part of a call that was lost marks the parts that
// follow it in that call, which reaches Message.Truncated. A failed bpf_ringbuf_reserve has no record to mark
// and stays the limitation the file header states.
func TestLostChunkMarksTheRestOfTheCall(t *testing.T) {
	t.Parallel()
	path := uprobeSSL(t)
	src := read(t, path)
	if !strings.Contains(src, "__u8 tego_ssl_emit(") {
		t.Errorf("tego_ssl_emit returns nothing: a caller that cannot learn a chunk was lost cannot mark " +
			"the rest of the call")
	}

	// tego_ssl_emit picks the record's size class; tego_ssl_emit_class reserves, copies and submits it.
	emit := functionBody(t, path, "tego_ssl_emit_class")
	if strings.Contains(emit, "bpf_ringbuf_discard(") {
		t.Errorf("tego_ssl_emit discards the record whose user copy failed; submitting it as a zero-length " +
			"truncated chunk costs the same ring space and is the only in-band signal of which connection " +
			"lost bytes (I2)")
	}
	copyAt := strings.Index(emit, "bpf_probe_read_user(")
	if copyAt < 0 {
		t.Fatalf("tego_ssl_emit_class no longer copies the plaintext")
	}
	failed := emit[copyAt:]
	if end := strings.Index(failed, "return 0;"); end >= 0 {
		failed = failed[:end]
	}
	for _, frag := range []string{"meta.len = 0", "meta.hole = TEGO_SSL_HOLE_UNREADABLE", "meta.skipped = skipped + n",
		"bpf_ringbuf_submit("} {
		if !strings.Contains(failed, frag) {
			t.Errorf("the failed-copy path does not %q: the loss stays invisible to the reader", frag)
		}
	}
	if strings.Contains(failed, "tego_lost_inc(") {
		t.Errorf("the failed-copy path counts a lost sample: its record reached the ring, carrying the hole, " +
			"and the counter is read as ring-buffer drops")
	}

	// R6's tail is named on the call's last possible part, so the reader knows where the hole ends.
	part := functionBody(t, path, "tego_ssl_part")
	if !strings.Contains(part, "skipped = total - off - left") {
		t.Errorf("tego_ssl_part does not carry the length of the tail R6 drops")
	}

	capture := functionBody(t, path, "tego_ssl_capture")
	if n := strings.Count(capture, ", lost)"); n != 4 {
		t.Errorf("%d of tego_ssl_capture's 4 chunk emissions carry the call's loss state; a chunk lost in "+
			"the middle of a call must mark the chunks after it (I2)", n)
	}
	if n := strings.Count(capture, "lost = tego_ssl_part("); n != 3 {
		t.Errorf("tego_ssl_capture threads the loss state out of %d of its first 3 parts; each part's "+
			"result must reach the next", n)
	}
	// The loss must be carried, not short-circuited: `||` would skip the emit of every chunk after the
	// first loss and turn a marked hole into a dropped tail.
	if strings.Contains(functionBody(t, path, "tego_ssl_part"), "lost || tego_ssl_emit(") {
		t.Errorf("tego_ssl_part short-circuits the emit once a part is lost; every remaining chunk must " +
			"still be emitted, marked")
	}
}

// TestSSLEmitClampsBeforeTheRead pins the source half of the 6.1/6.8 verifier fix (kernel matrix 2026-09-29):
// clang deleted tego_ssl_emit_class's `if (n > cls) n = cls` as dead, because its caller's class branches
// already proved it, and passed the read a copy of n from a stack slot the branches had not tested; the 6.1 and
// 6.8 verifiers refused every capturing program ("R2 unbounded memory access", "mem_size=592 off=80
// size=32768"). The clamp must follow barrier_var(n), which hides n's range from clang so the clamp stays, and
// must be the last thing before bpf_probe_read_user, so the bound is in the register the helper is passed.
// internal/bpf TestSSLUserReadSizeIsClampedAtTheCall checks the compiled objects themselves.
func TestSSLEmitClampsBeforeTheRead(t *testing.T) {
	t.Parallel()
	body := functionBody(t, uprobeSSL(t), "tego_ssl_emit_class")
	compact := strings.Join(strings.Fields(body), "")
	const clampThenRead = "barrier_var(n);if(n>cls)n=cls;if(bpf_probe_read_user(e->data,n,buf)!=0)"
	if !strings.Contains(compact, clampThenRead) {
		t.Errorf("tego_ssl_emit_class does not clamp n to its class behind barrier_var(n) right before "+
			"bpf_probe_read_user; want %q with nothing between", clampThenRead)
	}
	if strings.Count(compact, "bpf_probe_read_user(") != 1 {
		t.Errorf("tego_ssl_emit_class should read the plaintext once, with the clamped n")
	}
}

// TestChunksAreNumberedBeforeTheirReserve: userspace numbered chunks on arrival, so a chunk the
// ring never took left no hole and a lost response paired every later response on its connection with the
// request before its own. The kernel numbers each chunk of a connection from tego_ssl_seq, and must take the
// number before the reserve, or a failed reserve would use none up and the hole would close.
func TestChunksAreNumberedBeforeTheirReserve(t *testing.T) {
	t.Parallel()
	path := uprobeSSL(t)
	// A chunk's number is taken in tego_ssl_emit, before it hands the chunk to the size class that reserves
	// it; a hole (a read not read, §6 #3, R5) takes its number before its own reserve.
	emit := functionBody(t, path, "tego_ssl_emit")
	seqAt := strings.Index(emit, "tego_ssl_next_seq(")
	classAt := strings.Index(emit, "tego_ssl_emit_class(")
	if seqAt < 0 || classAt < 0 || seqAt > classAt || strings.Contains(emit, "bpf_ringbuf_reserve(") {
		t.Errorf("tego_ssl_emit takes the chunk's number at %d and hands it to a reserve at %d: the number "+
			"must come first", seqAt, classAt)
	}
	hole := functionBody(t, path, "tego_ssl_hole")
	if a, b := strings.Index(hole, "tego_ssl_next_seq("), strings.Index(hole, "bpf_ringbuf_reserve("); a < 0 || b < 0 || a > b {
		t.Errorf("tego_ssl_hole takes its number at %d and reserves at %d: the number must come first", a, b)
	}
	if !strings.Contains(functionBody(t, path, "tego_ssl_meta"), "m->seq = seq") {
		t.Errorf("tego_ssl_meta does not stamp the number on the record")
	}
	next := functionBody(t, path, "tego_ssl_next_seq")
	if !strings.Contains(next, "&tego_ssl_seq") {
		t.Errorf("tego_ssl_next_seq does not count in tego_ssl_seq")
	}
}

// TestCaptureCountsItsOwnDrops: the capture probes and the kernel record's programs both bumped
// tego_lost, so the record's drain reported capture's dropped chunks as ringbuf-full and the capture source
// reported the record's dropped samples as ring-buffer-drop, each a gap of the wrong mechanism. Capture's
// reserve failures go to its own tego_capture_lost, and nothing in the capture object touches the record's.
func TestCaptureCountsItsOwnDrops(t *testing.T) {
	t.Parallel()
	src := read(t, uprobeSSL(t))
	if strings.Contains(src, "&tego_lost)") || strings.Contains(src, "&tego_lost,") || strings.Contains(src, "&tego_events") {
		t.Errorf("%s counts into the record's tego_lost or writes its rings", uprobeSSLSource)
	}
	// Every function that reserves counts its failure; the read return probe also counts a read that moved
	// bytes on a connection no row names any more (R5).
	path := uprobeSSL(t)
	for _, fn := range []string{"tego_ssl_emit_class", "tego_ssl_hole", "tego_ssl_free", "tego_ssl_read_return"} {
		body := functionBody(t, path, fn)
		if strings.Contains(body, "bpf_ringbuf_reserve(") != strings.Contains(body, "tego_lost_inc(&tego_capture_lost, run->run_idx)") &&
			fn != "tego_ssl_read_return" {
			t.Errorf("%s reserves without counting a failed reserve in tego_capture_lost", fn)
		}
		if fn == "tego_ssl_read_return" && !strings.Contains(body, "tego_lost_inc(&tego_capture_lost, run->run_idx)") {
			t.Errorf("%s drops a read whose connection it cannot name without counting it", fn)
		}
	}
	if n, want := strings.Count(src, "bpf_ringbuf_reserve("), 3; n != want {
		t.Errorf("%s has %d reserves, want %d (a chunk's, a hole's, a close's): check each counts its failure",
			uprobeSSLSource, n, want)
	}
}

// TestEntryOnlyWriteLimitationIsStated is the deliverable for the half of the write path that cannot be
// fixed in this file. docs/p0/capture-derive.md §6 #12 reasons about entry-only write capture in one
// direction only — "no data lost for plain SSL_write/_ex2/_ex (length known at entry)" — and never about
// data gained, and the file inherited that one-sidedness.
//
// openssl/ssl.h defines SSL_MODE_ENABLE_PARTIAL_WRITE as "Allow SSL_write(..., n) to return r with
// 0 < r < n", and SSL_write(3ssl) requires a call that failed with WANT_READ/WANT_WRITE to "be repeated with
// the same arguments"; probesFor() places no return probe for a write. So a failed write, a mandated retry
// and a partial write each emit bytes the wire did not carry once. The in-kernel repair that suggests itself
// — suppressing a write whose buffer range lies inside the previous one — is an evasion channel, because the
// traced process owns the buffer and can change its contents between the two calls. A reader of this file
// must be told all of that rather than left with the one-sided claim, so the limitation is pinned here.
func TestEntryOnlyWriteLimitationIsStated(t *testing.T) {
	t.Parallel()
	path := uprobeSSL(t)
	header := readRaw(t, path)
	if i := strings.Index(header, "#define TEGO_CAPTURE_MAPS"); i > 0 {
		header = header[:i] // the file's own header comment, not a stray mention further down
	}
	for _, want := range []struct{ frag, why string }{
		{"SSL_MODE_ENABLE_PARTIAL_WRITE", "the partial-write mode that makes a write's return value less than its length"},
		{"WANT_READ/WANT_WRITE", "the retry contract that fires the entry probe twice over one buffer"},
		{"evasion channel", "why suppressing the apparent retry in-kernel is not the fix"},
		{"uretprobe", "what closing it properly would take"},
	} {
		if !strings.Contains(header, want.frag) {
			t.Errorf("the file header never mentions %q: %s", want.frag, want.why)
		}
	}
}
