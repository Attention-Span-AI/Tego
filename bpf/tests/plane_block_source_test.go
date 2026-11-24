// SPDX-License-Identifier: Apache-2.0

package bpftests

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The live blocks in the plane (ADR 0124, amendment 2026-11-21): every fs hook the plane decides asks them, with the
// classes its action belongs to, after the contract's own decision allowed and was settled (so the verifier walks the
// check on one path) and before the decision is recorded, so a refusal is the hook's one line under the block's rule.

// blockCallRe is one call of tego_block_check, its classes argument captured.
var blockCallRe = regexp.MustCompile(`tego_block_check\(sc, run, [^,]+, [^,]+,\s*([^,]+),\s*([A-Za-z_]+),\s*([A-Za-z_]+),\s*&rule(?:32)?\)`)

// TestPlaneEveryFSHookAsksTheLiveBlocks holds each fs hook to its block classes: file_open its read and write by f_mode;
// a removal (unlink, rmdir) writes and guards the object; a creation (mknod, mkdir, symlink) writes and asks the name
// rows; a truncate writes; a rename asks both ends for read, write and guard, the new end the name rows too; a link
// asks the source for read and write and the new name for those and the name rows; the attribute hooks write, chmod and
// chown on their path's mount. The hooks that share tego_modify_hook or tego_protect_hook pass the check through it.
func TestPlaneEveryFSHookAsksTheLiveBlocks(t *testing.T) {
	t.Parallel()
	path, _ := planeSource(t)
	bodies := planeBodies(t)
	classesOf := func(body string) []string {
		var out []string
		for _, m := range blockCallRe.FindAllStringSubmatch(body, -1) {
			out = append(out, strings.Join(strings.Fields(m[1]), " "))
		}
		return out
	}
	direct := map[string][]string{
		"file_open":   {"(read ? TEGO_BLOCK_READ : 0) | (modify ? TEGO_BLOCK_WRITE : 0)"},
		"path_rename": {"TEGO_BLOCK_READ | TEGO_BLOCK_WRITE | TEGO_BLOCK_GUARD", "TEGO_BLOCK_READ | TEGO_BLOCK_WRITE | TEGO_BLOCK_GUARD | TEGO_BLOCK_CREATE"},
		"path_link":   {"TEGO_BLOCK_READ | TEGO_BLOCK_WRITE", "TEGO_BLOCK_READ | TEGO_BLOCK_WRITE | TEGO_BLOCK_CREATE"},
	}
	for hook, want := range direct {
		body := bodies[hook]
		got := classesOf(body)
		if strings.Join(got, ";") != strings.Join(want, ";") {
			t.Errorf("%s asks the live blocks for %q, want %q", hook, got, want)
		}
		settle := strings.Index(body, "tego_plane_settle(")
		first := strings.Index(body, "tego_block_check(")
		record := strings.Index(body, "tego_plane_record(")
		if settle < 0 || first < 0 || record < 0 || first < settle || first > record {
			t.Errorf("%s does not ask the live blocks after it settles its decision and before it records it", hook)
		}
		if !strings.Contains(body[:first], "if (!reason") {
			t.Errorf("%s asks the live blocks of an action it already refused: a block only tightens, after the contract allowed", hook)
		}
	}
	// The rename and the link ask the second end only when the first allowed.
	for _, hook := range []string{"path_rename", "path_link"} {
		if !strings.Contains(bodies[hook], "!(reason = tego_block_check(") {
			t.Errorf("%s does not ask its second end after the first allowed", hook)
		}
	}
	modify := functionBody(t, path, "tego_modify_hook")
	if c := classesOf(modify); len(c) != 1 || c[0] != "bq" {
		t.Errorf("tego_modify_hook asks the live blocks for %q, want its bq argument once", c)
	}
	if i, j, k := strings.Index(modify, "tego_block_check("), strings.Index(modify, "tego_plane_settle("),
		strings.Index(modify, "tego_plane_record("); i < 0 || i < j || i > k || !strings.Contains(modify[:i], "if (!reason)") {
		t.Error("tego_modify_hook does not ask the live blocks after its own decision allowed and settled, before it records")
	}
	viaModify := map[string]string{
		"path_unlink": "TEGO_BLOCK_WRITE | TEGO_BLOCK_GUARD", "path_rmdir": "TEGO_BLOCK_WRITE | TEGO_BLOCK_GUARD",
		"path_mknod": "TEGO_BLOCK_WRITE | TEGO_BLOCK_CREATE", "path_mkdir": "TEGO_BLOCK_WRITE | TEGO_BLOCK_CREATE",
		"path_symlink": "TEGO_BLOCK_WRITE | TEGO_BLOCK_CREATE", "path_truncate": "TEGO_BLOCK_WRITE",
		"file_truncate": "TEGO_BLOCK_WRITE",
	}
	for hook, bq := range viaModify {
		re := regexp.MustCompile(`tego_modify_hook\([^;]*, ` + regexp.QuoteMeta(bq) + `\)`)
		if !re.MatchString(bodies[hook]) {
			t.Errorf("%s does not pass the live-block classes %s to tego_modify_hook", hook, bq)
		}
	}
	protect := functionBody(t, filepath.Join(sourceDir, "decide_stepb.h"), "tego_protect_hook")
	if c := classesOf(protect); len(c) != 1 || c[0] != "TEGO_BLOCK_WRITE" {
		t.Errorf("tego_protect_hook asks the live blocks for %q, want TEGO_BLOCK_WRITE once", c)
	}
	if !strings.Contains(protect, "tego_block_check(sc, run, dentry, mnt,") {
		t.Error("tego_protect_hook does not walk the live blocks on its hook's mount")
	}
	for hook, mnt := range map[string]string{
		"path_chmod": "path->mnt", "path_chown": "path->mnt", "inode_setxattr": "0", "inode_removexattr": "0",
		"inode_set_acl": "0", "inode_remove_acl": "0",
	} {
		if !strings.Contains(bodies[hook], "tego_protect_hook(") || !regexp.MustCompile(`tego_protect_hook\([^,]+, `+regexp.QuoteMeta(mnt)+`, run,`).MatchString(bodies[hook]) {
			t.Errorf("%s does not ask the live blocks through tego_protect_hook on mount %s", hook, mnt)
		}
	}
}

// TestPlaneBlockWalkGoesToTheRoot holds the block walk to what makes it a block and not a row: it reads the slot's
// block rows only, never the contract's (so a nearer contract row does not stop it), it says NONE only at the namespace
// root or a superblock's root (a walk out of iterations, a disconnected dentry or one past the bound refuses), it checks
// every hit's identity, and a name row is asked only for a creation.
func TestPlaneBlockWalkGoesToTheRoot(t *testing.T) {
	t.Parallel()
	path, _ := planeSource(t)
	step := functionBody(t, path, "tego_block_step")
	if strings.Contains(step, "tego_plane_rows") || !strings.Contains(step, "bpf_map_lookup_elem(s->rows, &key)") {
		t.Error("tego_block_step reads something other than the slot's block rows")
	}
	if strings.Count(step, "s->result = TEGO_BLOCK_NONE;") != 2 {
		t.Errorf("tego_block_step says NONE %d times, want twice (the superblock's root, the namespace root)", strings.Count(step, "s->result = TEGO_BLOCK_NONE;"))
	}
	if !strings.Contains(step, "r->i_ino != TEGO_I_INO(inode) || r->i_generation != TEGO_I_GEN(inode)") {
		t.Error("tego_block_step does not compare a hit's identity")
	}
	if !strings.Contains(step, "(s->steps ? r->beneath_q : r->self_q) & s->q") {
		t.Error("tego_block_step does not test the row's mask for its level")
	}
	decide := functionBody(t, path, "tego_block_decide")
	if !strings.Contains(decide, "s.result = TEGO_BLOCK_UNRESOLVED;\n            bpf_loop(") {
		t.Error("tego_block_decide does not start the walk UNRESOLVED, so a walk out of iterations would allow")
	}
	// The name row's check, statement by statement with the whitespace collapsed (a pin on a prefix let
	// "&& 0" after it, or a dropped identity compare, pass): asked for a creation only and nothing else, looked up in
	// the slot's block rows, and a row whose directory lost its identity refuses identity-mismatch.
	flat := strings.Join(strings.Fields(decide), " ")
	for _, want := range []string{
		"if (code == TEGO_BLOCK_NONE && (s.q & TEGO_BLOCK_CREATE) && st->names && parent) {",
		"key = tego_block_name_key(parent, nk); r = bpf_map_lookup_elem(s.rows, &key); if (r && r->gen == gen && r->name_key == nk) {",
		"if (r->i_ino != TEGO_I_INO(parent) || r->i_generation != TEGO_I_GEN(parent) || r->s_dev != TEGO_I_SDEV(parent)) { code = TEGO_BLOCK_MISMATCH; } else if (r->self_q && (!r->from_ns || s.now >= r->from_ns)) { code = TEGO_BLOCK_HIT;",
	} {
		if !strings.Contains(flat, want) {
			t.Errorf("tego_block_decide's name row lacks %q", want)
		}
	}
	// The fill gives every row its guard in the object's own mask, so a guard-only row refuses its object's move.
	fillPath := filepath.Join(filepath.Dir(path), "decide_fill.bpf.c")
	fill, err := os.ReadFile(fillPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(strings.Fields(string(fill)), " "),
		"row.self_q = (w->block_guard ? TEGO_BLOCK_GUARD : 0) | ((row.flags & TEGO_BLOCK_SELF) ? cls : 0); row.beneath_q = (row.flags & TEGO_BLOCK_BENEATH) ? cls : 0;") {
		t.Errorf("%s does not derive the row masks with the guard in self_q", fillPath)
	}
	for _, want := range []string{"TEGO_R_IDENTITY_MISMATCH", "TEGO_R_PATH_UNRESOLVED", "st->over & TEGO_BLOCK_READ",
		"st->over & TEGO_BLOCK_WRITE", "st->gen != gen", "r->name_key == nk"} {
		if !strings.Contains(decide, want) {
			t.Errorf("tego_block_decide has no %s", want)
		}
	}
}

// TestPlaneRecvmsgPassesOnlyTheDeputy holds ADR 0128's 2026-11-21 amendment in socket_recvmsg: the deputy's identity is
// asked after the slot's flag, the identity is the thread-group id in the launcher's pid namespace and the thread-group
// leader's start time in USER_HZ ticks, and a slot with no deputy passes nobody.
func TestPlaneRecvmsgPassesOnlyTheDeputy(t *testing.T) {
	t.Parallel()
	body := planeBodies(t)["socket_recvmsg"]
	flag, deputy := strings.Index(body, "TEGO_SLOT_IMPORTS_DENIED"), strings.Index(body, "tego_is_deputy(hdr)")
	if flag < 0 || deputy < 0 || deputy < flag {
		t.Error("socket_recvmsg does not ask for the deputy after the slot's flag")
	}
	is := functionBody(t, filepath.Join(sourceDir, "decide_import.h"), "tego_is_deputy")
	for _, want := range []string{"if (!hdr->deputy_tgid)", "bpf_get_ns_current_pid_tgid(hdr->pidns_dev, hdr->pidns_ino,",
		"ns.tgid != hdr->deputy_tgid", "t->group_leader->start_boottime / TEGO_NSEC_PER_USER_TICK == hdr->deputy_start"} {
		if !strings.Contains(is, want) {
			t.Errorf("tego_is_deputy has no %q", want)
		}
	}
}
