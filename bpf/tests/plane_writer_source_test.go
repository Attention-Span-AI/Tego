// SPDX-License-Identifier: Apache-2.0

package bpftests

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// TestPlaneSampleHasOneWriter is enforce-plane R23's sample in one writer: every refusal the plane writes to the
// ring itself (bprm_check, the attribute hooks, socket_create, the mapping hooks) goes through
// tego_plane_own_sample, the one function that reserves a struct tego_ev_plane, and that writer sets every field
// of the struct. Reserved ring memory is not zeroed, so a field no writer sets carries an earlier record's bytes.
func TestPlaneSampleHasOneWriter(t *testing.T) {
	t.Parallel()
	_, src := planeSource(t)
	if n := strings.Count(src, "struct tego_ev_plane *e;"); n != 1 {
		t.Errorf("the plane has %d writers of struct tego_ev_plane, want 1 (tego_plane_own_sample)", n)
	}
	if strings.Contains(src, "tego_plane_exec_sample") {
		t.Error("bprm_check keeps a sample writer of its own beside tego_plane_own_sample")
	}
	events := read(t, filepath.Join(sourceDir, "include", "events.h"))
	decl := regexp.MustCompile(`struct tego_ev_plane \{([^}]*)\};`).FindStringSubmatch(events)
	if decl == nil {
		t.Fatal("events.h: no struct tego_ev_plane")
	}
	fields := regexp.MustCompile(`(?m)^\s*(?:struct\s+)?[a-z_0-9]+\s+([a-z_0-9]+)(?:\[[A-Z_]+\])?;`).FindAllStringSubmatch(decl[1], -1)
	if len(fields) < 10 {
		t.Fatalf("events.h: struct tego_ev_plane has %d fields parsed, want every one", len(fields))
	}
	var writer string
	for _, name := range []string{"decide.bpf.c", "decide_stepb.h", "decide_stepc.h"} {
		if p := filepath.Join(sourceDir, name); strings.Contains(read(t, p), "tego_plane_own_sample(const") {
			writer = functionBody(t, p, "tego_plane_own_sample")
		}
	}
	if writer == "" {
		t.Fatal("no definition of tego_plane_own_sample")
	}
	for _, f := range fields {
		var set *regexp.Regexp
		switch f[1] {
		case "hdr":
			set = regexp.MustCompile(`tego_hdr_fill\(&e->hdr,`)
		case "path":
			set = regexp.MustCompile(`\(\(__u64 \*\)e->path\)\[k\] =`)
		default:
			set = regexp.MustCompile(`e->` + f[1] + `\s*=[^=]`)
		}
		if !set.MatchString(writer) {
			t.Errorf("tego_plane_own_sample never sets e->%s: the ring record carries stale bytes there", f[1])
		}
	}
}

// TestPlaneModificationsShareOneDecision holds the plane's "walk, then refuse unless TEGO_ROW_MODIFY_ALLOW" for a
// modification at the object (decide.PlaneRows.Decide, PlaneModify) in one helper, tego_modify_hook, that unlink,
// rmdir, the creates and the truncates call with their own refusal reason.
func TestPlaneModificationsShareOneDecision(t *testing.T) {
	t.Parallel()
	_, src := planeSource(t)
	if n := len(regexp.MustCompile(`if \(!reason && !\(kind & TEGO_ROW_MODIFY_ALLOW\)\)`).FindAllString(src, -1)); n != 1 {
		t.Errorf("the modification decision is written %d times, want once (tego_modify_hook)", n)
	}
	for _, old := range []string{"tego_decide_remove", "tego_decide_create", "tego_create_hook", "tego_truncate_hook"} {
		if strings.Contains(src, old+"(") {
			t.Errorf("%s is still a copy of tego_modify_hook", old)
		}
	}
	bodies := planeBodies(t)
	for hook, reason := range map[string]string{
		"path_unlink": "TEGO_R_DELETE_OUTSIDE_CONTRACT", "path_rmdir": "TEGO_R_DELETE_OUTSIDE_CONTRACT",
		"path_mknod": "TEGO_R_WRITE_OUTSIDE_CONTRACT", "path_mkdir": "TEGO_R_MKDIR_OUTSIDE_CONTRACT",
		"path_symlink": "TEGO_R_WRITE_OUTSIDE_CONTRACT", "path_truncate": "TEGO_R_WRITE_OUTSIDE_CONTRACT",
		"file_truncate": "TEGO_R_WRITE_OUTSIDE_CONTRACT",
	} {
		if hook == "path_mknod" {
			// The names argument (1: a file at a covered name is refused too, ADR 0043 D1) is
			// TestNameCheckCallersAreTheListedHooks'.
			floor := regexp.MustCompile(`__u8 floor = tego_modify_hook\(dentry, dir->mnt, run, hdr, [01], TEGO_HOOK_PATH_MKNOD, \(__u64\)dentry,\s*` + reason + `\);`)
			if !floor.MatchString(bodies[hook]) || !strings.Contains(bodies[hook], "return floor ? -EACCES : 0;") {
				t.Error("path_mknod lost its shared filesystem mutation floor")
			}
			continue
		}
		re := regexp.MustCompile(`tego_modify_hook\([^;]*TEGO_HOOK_` + strings.ToUpper(hook) + `,[^;]*` + reason + `\)\)\s*return -EACCES;`)
		if !re.MatchString(bodies[hook]) {
			t.Errorf("%s does not decide through tego_modify_hook, refused %s", hook, reason)
		}
	}
}

// TestBPFDefinesOnce holds each TEGO_ macro to one definition per compilation unit (a program and the local headers
// it includes), outside alternatives of one #if: a second copy is a value that silently wins or loses by include
// order once the copies drift.
func TestBPFDefinesOnce(t *testing.T) {
	t.Parallel()
	units, _ := filepath.Glob(filepath.Join(sourceDir, "*.bpf.c"))
	more, _ := filepath.Glob(filepath.Join(sourceDir, "testonly", "*.bpf.c"))
	units = append(units, more...)
	if len(units) == 0 {
		t.Fatal("no BPF programs found")
	}
	for _, unit := range units {
		seen := map[string]string{}
		visited := map[string]bool{}
		var walk func(path string)
		walk = func(path string) {
			if visited[path] {
				return
			}
			visited[path] = true
			var cond []string
			for i, line := range strings.Split(read(t, path), "\n") {
				line = strings.TrimSpace(line)
				switch {
				case strings.HasPrefix(line, "#include \""):
					name := strings.TrimSuffix(strings.TrimPrefix(line, "#include \""), "\"")
					if name == "vmlinux.h" || strings.HasPrefix(name, "libbpf/") {
						continue
					}
					for _, dir := range []string{filepath.Dir(path), sourceDir, filepath.Join(sourceDir, "include")} {
						if _, err := os.Stat(filepath.Join(dir, name)); err == nil {
							walk(filepath.Join(dir, name))
							break
						}
					}
				case strings.HasPrefix(line, "#if"):
					cond = append(cond, line)
				case strings.HasPrefix(line, "#el") && len(cond) > 0:
					cond[len(cond)-1] += "|" + line
				case strings.HasPrefix(line, "#endif") && len(cond) > 0:
					cond = cond[:len(cond)-1]
				case strings.HasPrefix(line, "#define TEGO_"):
					name := strings.FieldsFunc(strings.TrimPrefix(line, "#define "), func(r rune) bool { return r == ' ' || r == '(' || r == '\t' })[0]
					if len(cond) > 0 && cond[len(cond)-1] == "#ifndef "+name {
						cond[len(cond)-1] = "" // a header's own guard, or a guarded default: no alternative
						continue
					}
					where := strings.Join(cond, "/")
					key := name + "@" + where
					at := path + ":" + strconv.Itoa(i+1)
					if prev, ok := seen[key]; ok {
						t.Errorf("%s: %s is defined at %s and again at %s", unit, name, prev, at)
						continue
					}
					seen[key] = at
				}
			}
		}
		walk(unit)
	}
}
