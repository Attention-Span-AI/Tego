// SPDX-License-Identifier: Apache-2.0

package bpftests

import (
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The slot header (enforce-plane R6; bpf/include/events.h struct tego_plane_slot): what a slot says of the run whose
// rows it holds. These tests hold every plane body to reading it, and the plane to failing closed where a row or a
// header is missing.

// planeSlotRefuses matches a body's refusal on a missing header: `if (!tego_plane_slot_of(run)) { ... return -EACCES;`
// or the same on a header read into hdr.
var planeSlotRefuses = regexp.MustCompile(`if \(!(tego_plane_slot_of\(run\)|hdr)\) \{[^}]*return -EACCES;`)

// TestPlaneEveryHookReadsTheSlotHeader is enforce-plane R6's header: every TEGO_PLANE_HOOK body reads its slot's
// header after its run-set hit (the run lookup and the mode check) and before any decision, and refuses with
// -EACCES when the slot holds no header of the run's gen; step C's bodies hand it to tego_map_decide, which refuses on
// none first. A missing row never reads as a permission: no body or helper reads a policy row whose absence meant
// "no exec: section" or "no net: section".
func TestPlaneEveryHookReadsTheSlotHeader(t *testing.T) {
	t.Parallel()
	bodies := planeBodies(t)
	if len(bodies) == 0 {
		t.Fatal("no TEGO_PLANE_HOOK bodies")
	}
	decisions := regexp.MustCompile(`tego_nearest\(|tego_plane_walk\(|tego_(create|truncate|protect)_hook\(|` +
		`tego_decide_remove\(|tego_plane_unix_reason\(|tego_socket_allowed\(|&tego_plane_exec_rows|tego_name_key\(`)
	for name, body := range bodies {
		mode := planeRunModeGuard(body)
		if name == "bpf" || name == "capable" {
			// These floors have no policy-row read or contract opt-out. An absent
			// slot must never permit BPF commands or the task's CAP_SYS_ADMIN.
			// A filesystem's own credential override is backing work (ADR 0055).
			if mode == nil || !strings.Contains(body[mode[1]:], "return tego_control_refuse(run, TEGO_HOOK_"+strings.ToUpper(name)+", TEGO_R_PROCESS_SCOPE") {
				t.Errorf("%s lost its unconditional governed refusal", name)
			}
			// An io_uring personality is an override userspace chose, never backing work:
			// an io thread (PF_IO_WORKER, 0x10; comments are stripped) or a ring user keeps the floor.
			if name == "capable" && (!strings.Contains(body, "task->flags & 0x00000010") ||
				!strings.Contains(body, "task->io_uring") || !strings.Contains(body, "&& !uring)")) {
				t.Error("capable admits a credential override without excluding io_uring's")
			}
			continue
		}
		hdr := strings.Index(body, "tego_plane_slot_of(run)")
		if mode == nil || hdr < mode[1] {
			t.Errorf("%s does not read its slot header after its run-set hit", name)
			continue
		}
		if loc := decisions.FindStringIndex(body); loc != nil && loc[0] < hdr {
			t.Errorf("%s decides (%s) before it reads its slot header", name, body[loc[0]:loc[1]])
		}
		if _, mapping := planeMapHooks[name]; mapping {
			if !strings.Contains(body, "tego_map_decide(run, tego_plane_slot_of(run),") &&
				!strings.Contains(body, "tego_map_decide(run, hdr,") {
				t.Errorf("%s does not hand its slot header to tego_map_decide", name)
			}
			continue
		}
		slotHelperRefusal := regexp.MustCompile(`if \(!(tego_plane_slot_of\(run\)|hdr|slot)\)\s*\{?[^}]*return tego_(control|listen)_refuse\(`).MatchString(body)
		slotDirectRefusal := regexp.MustCompile(`if \(!slot\)\s*return -EACCES;`).MatchString(body)
		if !planeSlotRefuses.MatchString(body) && !slotHelperRefusal && !slotDirectRefusal {
			t.Errorf("%s does not refuse (-EACCES) on a slot with no header of the run's gen", name)
		}
	}
	decide := squash(functionBody(t, stepCPath, "tego_map_decide"))
	if !strings.HasPrefix(strings.TrimPrefix(decide[strings.Index(decide, "int res;")+len("int res;"):], " "),
		"if (!hdr) { tego_plane_unslotted(hook, obj); return tego_map_refuse(") {
		t.Errorf("tego_map_decide does not refuse on a missing header before anything else:\n%s", decide)
	}

	path, src := planeSource(t)
	slot := squash(functionBody(t, path, "tego_plane_slot_of"))
	for _, want := range []string{"bpf_map_lookup_elem(&tego_plane_slots, &idx)", "if (!s || s->gen != run->gen) {",
		"TEGO_PLANE_COUNT(run->run_idx, norows); return 0;"} {
		if !strings.Contains(slot, want) {
			t.Errorf("tego_plane_slot_of lacks %q:\n%s", want, slot)
		}
	}
	for _, gone := range []string{"TEGO_EXEC_POLICY_KEY", "TEGO_NET_POLICY_KEY", "TEGO_EXEC_ANON_ALLOW", "TEGO_NET_ICMP",
		"pol->decides"} {
		if strings.Contains(src, gone) {
			t.Errorf("the plane still reads %s: a section's absence is a header flag, never a missing row", gone)
		}
	}
	for _, flag := range []string{"TEGO_SLOT_EXEC_DECIDES", "TEGO_SLOT_EXEC_ANON", "TEGO_SLOT_UNIX_DECIDES",
		"TEGO_SLOT_NET_DECIDES", "TEGO_SLOT_NET_ICMP"} {
		if !strings.Contains(src, "hdr->flags & "+flag) {
			t.Errorf("no body reads the header's %s", flag)
		}
	}
	maps := read(t, filepath.Join(sourceDir, "include", "maps.h"))
	if !regexp.MustCompile(`BPF_MAP_TYPE_ARRAY\);[^}]*LIBBPF_PIN_BY_NAME[^}]*struct tego_plane_slot\);\s*\} tego_plane_slots`).
		MatchString(maps) {
		t.Error("tego_plane_slots is not a pinned ARRAY of struct tego_plane_slot")
	}
}

// TestPlaneOpenSkipKeysOnThePrivateClone is enforce-plane R8: file_open and file_truncate skip a backing open by its
// mount alone, a private clone (tego_internal_mount), which no open of the agent's own resolves through; no
// FMODE_BACKING bit is read there, so no bit misread from BTF can change their verdict. Step C still reads the bit,
// to start its walk at a backing file's user_path.
func TestPlaneOpenSkipKeysOnThePrivateClone(t *testing.T) {
	t.Parallel()
	bodies := planeBodies(t)
	for _, hook := range []string{"file_open", "file_truncate"} {
		body := bodies[hook]
		if n := strings.Count(body, "if (tego_internal_mount(file->f_path.mnt))\n        return 0;"); n != 1 {
			t.Errorf("%s has %d private-clone skips, want one", hook, n)
		}
		if strings.Contains(body, "tego_is_backing(") {
			t.Errorf("%s reads the FMODE_BACKING bit; its skip is keyed on the private clone alone", hook)
		}
	}
	stepc := read(t, filepath.Join(sourceDir, "decide_stepc.h"))
	if !strings.Contains(stepc, "tego_is_backing(file->f_mode) && bpf_core_field_exists(struct backing_file, user_path)") {
		t.Error("step C no longer starts a backing file's walk at its user_path")
	}
}
