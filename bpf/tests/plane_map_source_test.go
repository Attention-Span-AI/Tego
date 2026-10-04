// SPDX-License-Identifier: Apache-2.0

package bpftests

import (
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Step C of the decision plane (ADR 0027; TIER3-PLAN T14; docs/p0/enforce-plane.md R26): mmap_file and file_mprotect
// in bpf/decide_stepc.h.

// planeMapHooks are step C's hooks, whose bodies return 0 before the run-set lookup for no file or no PROT_EXEC.
var planeMapHooks = map[string]bool{"mmap_file": true, "file_mprotect": true}

// stepCPath is the file step C's bodies and helpers are in.
var stepCPath = filepath.Join(sourceDir, "decide_stepc.h")

// squash collapses every run of white space to one space, so a check reads code and not its layout (read strips
// comments and leaves their white space behind).
func squash(s string) string { return strings.Join(strings.Fields(s), " ") }

// TestPlaneMapHooksReturnBeforeTheRunLookup is ADR 0027's host cost and enforce-plane R26: both bodies return 0
// before the run-set lookup when there is no file or no PROT_EXEC, so an anonymous or non-executable map on the
// host pays a branch, and nothing before the lookup can refuse. mmap_file's only call there is tego_mmap_prot,
// fmod_ret mode's effective prot.
func TestPlaneMapHooksReturnBeforeTheRunLookup(t *testing.T) {
	t.Parallel()
	bodies := planeBodies(t)
	for name := range planeMapHooks {
		body, ok := bodies[name]
		if !ok {
			t.Fatalf("no TEGO_PLANE_HOOK body for %s", name)
		}
		lookup := strings.Index(body, "run = tego_current_run(&tego_run_set);")
		if lookup < 0 {
			t.Fatalf("%s: no run-set lookup", name)
		}
		pre := squash(body[:lookup])
		if !strings.Contains(pre, "if (!(prot & TEGO_PROT_EXEC)) return 0;") {
			t.Errorf("%s: no return 0 for a mapping without PROT_EXEC before the run-set lookup", name)
		}
		if !strings.Contains(pre, "if (!file) return 0;") {
			t.Errorf("%s: no return 0 for a mapping with no file before the run-set lookup", name)
		}
		for _, m := range returnRe.FindAllStringSubmatch(pre, -1) {
			if strings.TrimSpace(m[1]) != "0" {
				t.Errorf("%s returns %q before the run-set lookup; only 0 may come before it", name, m[1])
			}
		}
		for _, call := range regexp.MustCompile(`\b([a-z_][a-z0-9_]*)\s*\(`).FindAllStringSubmatch(pre, -1) {
			if call[1] != "if" && call[1] != "tego_mmap_prot" {
				t.Errorf("%s calls %s before the run-set lookup", name, call[1])
			}
		}
	}
}

// TestPlaneMapDecidesOnTheEffectiveProt is ADR 0024 (8), ADR 0027 and its 2026-09-29 amendment: both hooks decide on
// the prot the kernel maps with, not the one the task asked for. bpf_lsm_mmap_file's third argument is
// mmap_prot(file, reqprot); security_mmap_file, which fmod_ret mode attaches to ahead of that computation, is handed
// reqprot, so the fmod_ret program computes it as the kernel does (READ_IMPLIES_EXEC adds PROT_EXEC to a PROT_READ
// map on a mount that is not noexec). file_mprotect's hook is handed the effective prot in both modes, and reqprot is
// never read. The fmod_ret program never reads its fourth parameter, which is security_mmap_file's return slot.
func TestPlaneMapDecidesOnTheEffectiveProt(t *testing.T) {
	t.Parallel()
	bodies := planeBodies(t)
	mm := squash(bodies["mmap_file"])
	if !strings.Contains(mm, "if (mode == TEGO_PLANE_LSM) { prot = a2; flags = a3; } else { "+
		"prot = tego_mmap_prot(file, a1); flags = a2; }") {
		t.Error("mmap_file does not take LSM mode's prot (a2) and flags (a3), and fmod_ret mode's mmap_prot(file, a1) and flags (a2)")
	}
	if n := regexp.MustCompile(`\ba3\b`).FindAllString(mm, -1); len(n) != 1 {
		t.Errorf("mmap_file reads a3 %d times; only LSM mode's flags may read it (in fmod_ret mode it is the return slot)", len(n))
	}
	if strings.Contains(bodies["file_mprotect"], "reqprot") {
		t.Error("file_mprotect reads reqprot; it decides on the effective prot (ADR 0027's amendment)")
	}
	prot := squash(functionBody(t, stepCPath, "tego_mmap_prot"))
	for _, want := range []string{
		"(prot & (TEGO_PROT_READ | TEGO_PROT_EXEC)) != TEGO_PROT_READ", "t->personality & TEGO_READ_IMPLIES_EXEC",
		"if (!file) return prot | TEGO_PROT_EXEC;", "mnt_flags & TEGO_MNT_NOEXEC", "s_iflags & TEGO_SB_I_NOEXEC",
	} {
		if !strings.Contains(prot, want) {
			t.Errorf("tego_mmap_prot lacks %q: it is include/linux/security.h's mmap_prot()", want)
		}
	}
	src := read(t, stepCPath)
	for _, def := range []string{"#define TEGO_PROT_READ 0x1", "#define TEGO_PROT_WRITE 0x2", "#define TEGO_PROT_EXEC 0x4",
		"#define TEGO_MAP_TYPE 0x0f", "#define TEGO_MAP_PRIVATE 0x02", "#define TEGO_READ_IMPLIES_EXEC 0x0400000",
		"#define TEGO_MNT_NOEXEC 0x04", "#define TEGO_SB_I_NOEXEC 0x02", "#define TEGO_VM_EXEC 0x04",
		"#define TEGO_VM_SHARED 0x08"} {
		if !strings.Contains(src, def) {
			t.Errorf("decide_stepc.h lacks %q (uapi mman.h, personality.h, mount.h, fs.h, mm.h values)", def)
		}
	}
}

// TestPlaneMapPolicy is enforce-plane R26's decision in tego_map_decide: a slot with no header of the run's gen
// refuses; a header without the exec flag (no exec: section) decides nothing; anonymous memory (an S_PRIVATE inode)
// is not a file; no scratch value or no exec-rows map refuses and counts; execmem and execmod refuse; an anonymous
// file follows exec.anonymous; a file's nearest write row
// refuses unless an exec.allow directory, its own exec row or a name row covers it; a mismatched exec row refuses
// and counts; a walk that failed refuses; an overlay mapping on 6.8+ walks from the user's path. file_mprotect
// decides only a mapping that becomes executable, except for execmem.
func TestPlaneMapPolicy(t *testing.T) {
	t.Parallel()
	decide := squash(functionBody(t, stepCPath, "tego_map_decide"))
	at := 0
	for _, want := range []string{
		"if (!hdr) { tego_plane_unslotted(hook, obj); return tego_map_refuse(",
		"if (!(hdr->flags & TEGO_SLOT_EXEC_DECIDES)) return 0;",
		"inode->i_flags & TEGO_S_PRIVATE",
		"TEGO_PLANE_COUNT(run->run_idx, unresolved); return tego_map_refuse(",
		"TEGO_PLANE_COUNT(run->run_idx, norows);",
		"bpf_core_field_exists(struct backing_file, user_path)",
		"tego_is_anonymous(dentry) || (dentry->d_sb->s_flags & TEGO_SB_NOUSER)",
		"hdr->flags & TEGO_SLOT_EXEC_ANON",
		"if (wx) {",
		"tego_walk_failed(tego_nearest(sc, dentry, file->f_path.mnt, run, &kind, &rule, &depth))",
		"(kind & TEGO_ROW_MODIFY_ALLOW) && !(kind & TEGO_ROW_EXEC_DIR)",
		"tego_map_exec_row(sc, exec_rows, run, dentry, inode, &rule)",
		"reason = TEGO_R_IDENTITY_MISMATCH;",
		"reason = TEGO_R_EXEC_NOT_ALLOWED;",
	} {
		i := strings.Index(decide[at:], want)
		if i < 0 {
			t.Errorf("tego_map_decide lacks %q, or has it out of order", want)
			continue
		}
		at += i + len(want)
	}
	if i := strings.Index(decide, "bpf_core_field_exists(struct backing_file, user_path)"); i >= 0 {
		backing := decide[i:]
		if !strings.Contains(backing, "sc->launder_dentry = TEGO_BF_USER_DENTRY(file); sc->launder_mnt = TEGO_BF_USER_MNT(file);") ||
			!strings.Contains(backing, "tego_plane_walk(*(volatile __u64 *)&sc->launder_dentry, *(volatile __u64 *)&sc->launder_mnt,") ||
			!strings.Contains(backing, "(h.kind & TEGO_ROW_MODIFY_ALLOW) && !(h.kind & TEGO_ROW_EXEC_DIR)") {
			t.Error("an overlay mapping on 6.8+ is not walked from backing_file_user_path() and decided by its fs rows")
		}
	}
	// R23: every refusal writes the plane's own sample, the refused mapping's one ledger line.
	if strings.Contains(decide, "return -EACCES;") {
		t.Error("tego_map_decide refuses without its sample: every refusal returns tego_map_refuse(...)")
	}
	refuse := squash(functionBody(t, stepCPath, "tego_map_refuse"))
	for _, want := range []string{"a.kind = TEGO_EV_PLANE_MAP;", "tego_plane_own_sample(run, &a);", "return -EACCES;"} {
		if !strings.Contains(refuse, want) {
			t.Errorf("tego_map_refuse lacks %q", want)
		}
	}
	// The file arm is bprm_check's own function (tego_exec_file_row), so the key a mapping looks up is the link key
	// the fill writes (§6 E15), never the inode pointer alone.
	row := squash(functionBody(t, stepCPath, "tego_map_exec_row"))
	for _, want := range []string{"tego_name_key(dentry, &nm)", "tego_exec_file_row(sc, exec_rows, run, dentry, inode, &nm, key, rule)",
		"tego_name_eq(&nm, r)", "bpf_map_lookup_elem(exec_rows, &key)"} {
		if !strings.Contains(row, want) {
			t.Errorf("tego_map_exec_row lacks %q: it is bprm_check's file and name arms", want)
		}
	}
	if strings.Contains(row, "(__u64)inode;") {
		t.Error("tego_map_exec_row keys an exec row by the inode alone, which no link-keyed row answers")
	}
	bodies := planeBodies(t)
	mm := squash(bodies["mmap_file"])
	if !strings.Contains(mm, "(prot & TEGO_PROT_WRITE) && (flags & TEGO_MAP_TYPE) == TEGO_MAP_PRIVATE") {
		t.Error("mmap_file's execmem is not a writable and executable private mapping")
	}
	mp := squash(bodies["file_mprotect"])
	for _, want := range []string{"wx = (prot & TEGO_PROT_WRITE) && !(vm_flags & TEGO_VM_SHARED);",
		"if (vm_flags & TEGO_VM_EXEC) { if (!wx) return 0; } else if (vma->anon_vma && !(vm_flags & TEGO_VM_SHARED)) { wx = 1; }"} {
		if !strings.Contains(mp, want) {
			t.Errorf("file_mprotect lacks %q", want)
		}
	}
	for _, banned := range []string{"bpf_d_path", "_str(", "bpf_probe_read_kernel_str"} {
		if strings.Contains(decide+row+mm+mp, banned) {
			t.Errorf("step C uses %s: it decides on the object and inode keys, never a path string", banned)
		}
	}
}
