// SPDX-License-Identifier: Apache-2.0

package bpftests

import (
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestActivityStampIsGatedAndCoarse pins tego_activity_stamp (bpf/include/common.h, limits R4): the flag a
// stall-bounded run's row carries is tested before anything else, so a run with no stall budget pays one test of a
// byte already loaded; the slot is the run's own; and an action in the jiffy the slot already names returns before
// the clock is read, so the clock read and the stores are paid once a jiffy, and a busy run's threads share the cache
// line instead of bouncing it on every action.
func TestActivityStampIsGatedAndCoarse(t *testing.T) {
	t.Parallel()
	body := squash(functionBody(t, filepath.Join(sourceDir, "include", "common.h"), "tego_activity_stamp"))
	flag := strings.Index(body, "if (!(run->flags & TEGO_RUN_ACTIVITY)) return;")
	idx := strings.Index(body, "idx = run->run_idx;")
	lookup := strings.Index(body, "bpf_map_lookup_elem(activity, &idx)")
	jiffy := strings.Index(body, "j = bpf_jiffies64(); if (j == slot->jiffies) return;")
	store := strings.Index(body, "slot->jiffies = j; slot->mono_ns = bpf_ktime_get_ns();")
	if flag < 0 || idx < flag || lookup < idx || jiffy < lookup || store < jiffy {
		t.Fatalf("tego_activity_stamp is not flag, slot, the jiffy's return, then the clock and the stores, in that order:\n%s", body)
	}
	if strings.Count(body, "bpf_ktime_get_ns(") != 1 {
		t.Errorf("tego_activity_stamp reads the clock other than once, after the jiffy's return")
	}
	for _, banned := range []string{"bpf_probe_read", "bpf_ringbuf_", "__sync_", "tego_recording("} {
		if strings.Contains(body, banned) {
			t.Errorf("tego_activity_stamp calls %q: a stamp reads registers and writes one slot", banned)
		}
	}
	events := squash(read(t, filepath.Join(sourceDir, "include", "events.h")))
	for _, want := range []string{"TEGO_RUN_LISTENER_RESULTS = 0x01,", "TEGO_RUN_ACTIVITY = 0x02,",
		"struct tego_activity_slot { __u64 mono_ns; __u64 jiffies; };"} {
		if !strings.Contains(events, want) {
			t.Errorf("events.h lacks %q (internal/bpf RunActivity, ActivitySlot mirror it)", want)
		}
	}
	maps := squash(read(t, filepath.Join(sourceDir, "include", "maps.h")))
	decl := regexp.MustCompile(`struct \{ __uint\(type, BPF_MAP_TYPE_ARRAY\); __uint\(max_entries, TEGO_MAX_SLOTS\); ` +
		`__uint\(pinning, LIBBPF_PIN_BY_NAME\); __type\(key, __u32\); __type\(value, struct tego_activity_slot\); \} tego_activity SEC\("\.maps"\);`)
	at := strings.Index(maps, "} tego_activity SEC(")
	if !decl.MatchString(maps) || at < 0 {
		t.Fatal("maps.h does not declare tego_activity as a pinned ARRAY of TEGO_MAX_SLOTS tego_activity_slot by run_idx")
	}
	// Declared in every object, as the counters beside it are: no #ifdef may be open around it.
	if open := strings.Count(maps[:at], "#if"); open != strings.Count(maps[:at], "#endif")+1 {
		t.Errorf("tego_activity sits inside a conditional block (%d #if, %d #endif before it): every object must declare it",
			open, strings.Count(maps[:at], "#endif"))
	}
}

// TestRecordOffReturnsStampActivity: every return trace_proc takes for an allowed action because the run records
// nothing (tego_recording false) stamps the run's activity first, so an agent busy with allowed reads, writes and
// connects under record: off is not ended as stalled (limits R4). A gate that returned without the stamp is an
// action the stall check never sees.
func TestRecordOffReturnsStampActivity(t *testing.T) {
	t.Parallel()
	src := squash(read(t, filepath.Join(sourceDir, "trace_proc.bpf.c")))
	gate := regexp.MustCompile(`if \((?:ret == 0 && )?!tego_recording\(run\)\) ([^}]*)\}?`)
	found := gate.FindAllStringSubmatch(src, -1)
	if len(found) != 4 {
		t.Fatalf("found %d record: off gates in trace_proc, want 4 (file_open, tego_fsop_begin, the mknod hold, "+
			"socket_connect): a new gate needs its stamp and this count", len(found))
	}
	for _, m := range found {
		if !strings.HasPrefix(m[1], "{ tego_activity_stamp(&tego_activity, run); return 0;") {
			t.Errorf("a record: off gate returns without stamping the run's activity first: %q", m[0])
		}
	}
	if n := strings.Count(src, "tego_activity_stamp("); n != 4 {
		t.Errorf("trace_proc stamps activity at %d places, want the 4 record: off gates only: under summary and full "+
			"the action is a sample the record keeps", n)
	}
}

// TestTLSProbesStampBeforeTheModeAndReadNothingUnderOff is the probes' half (A-REC-1, A-REC-5): a write that asks to
// move bytes and a read return that moved some stamp right after the run-set hit, before the record mode is looked
// at, so a response streaming for longer than stall_after is activity in every mode; and under record: off the
// program returns right after, having read no user memory, made no scratch row, taken no chunk number, reserved
// nothing and counted no miss. Read entries and SSL_free stamp nothing.
func TestTLSProbesStampBeforeTheModeAndReadNothingUnderOff(t *testing.T) {
	t.Parallel()
	path := uprobeSSL(t)
	for _, tc := range []struct{ prog, cond string }{
		{"tego_ssl_write", "if (num > 0) tego_activity_stamp(&tego_activity, run);"},
		{"tego_ssl_write_ex", "if ((__u64)PT_REGS_PARM3(ctx) > 0) tego_activity_stamp(&tego_activity, run);"},
		{"tego_ssl_read_return", "if (ret > 0) tego_activity_stamp(&tego_activity, run);"},
	} {
		body := squash(functionBody(t, path, tc.prog))
		hit := strings.Index(body, "if (!run) return 0;")
		stamp := strings.Index(body, tc.cond)
		off := strings.Index(body, "if (!tego_recording(run)) return 0;")
		if hit < 0 || stamp < hit || off < stamp {
			t.Errorf("%s: not run-set hit, %q, then the record: off return:\n%s", tc.prog, tc.cond, body)
			continue
		}
		before := body[:off]
		for _, banned := range []string{"bpf_probe_read_user", "tego_ssl_enter", "tego_ssl_next_seq", "tego_ssl_take_",
			"bpf_ringbuf_reserve", "tego_capture_ring", "tego_lost_inc", "bpf_map_update_elem", "bpf_map_delete_elem"} {
			if strings.Contains(before, banned) {
				t.Errorf("%s: %s before the record: off return: an off run's TLS call must leave nothing but its stamp",
					tc.prog, banned)
			}
		}
	}
	for _, prog := range []string{"tego_ssl_read", "tego_ssl_read_ex", "tego_ssl_free"} {
		body := squash(functionBody(t, path, prog))
		if strings.Contains(body, "tego_activity_stamp(") {
			t.Errorf("%s stamps activity: a read entry has moved nothing yet, and a free moves nothing", prog)
		}
		if !strings.Contains(body, "if (!run || !tego_recording(run)) return 0;") {
			t.Errorf("%s no longer returns at once for a run that records nothing", prog)
		}
	}
}
