// SPDX-License-Identifier: Apache-2.0

package bpftests

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// sourceDir is bpf/ relative to this package.
const sourceDir = ".."

// dualSPDX is the licence line ADR 0012 requires on every C file under bpf/.
const dualSPDX = "// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)"

// licenseDecl is the section without which the kernel refuses every GPL-only helper and kfunc call.
const licenseDecl = `char _license[] SEC("license") = "Dual BSD/GPL";`

// program is one SEC()-annotated function extracted from a C source.
type program struct {
	file    string
	section string
	name    string
	body    string
}

var (
	// whileRe matches any while loop head; whileZeroRe matches the do { } while (0) macro idiom, which is
	// not a loop at all.
	whileRe     = regexp.MustCompile(`while\s*\([^)]*\)`)
	whileZeroRe = regexp.MustCompile(`^while\s*\(\s*0\s*\)$`)
	secRe       = regexp.MustCompile(`(?m)^SEC\("([^"]+)"\)\n`)
	funcRe      = regexp.MustCompile(`^(?:int|long)\s+(?:BPF_PROG\(\s*)?([A-Za-z_][A-Za-z0-9_]*)`)
)

// sources lists the .bpf.c files that exist; the set grows as other tickets land theirs.
func sources(t *testing.T) []string {
	t.Helper()
	got, err := filepath.Glob(filepath.Join(sourceDir, "*.bpf.c"))
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	if len(got) == 0 {
		t.Fatal("no .bpf.c sources found; this package must run from bpf/tests")
	}
	slices.Sort(got)
	return got
}

// read returns a source file's text with every comment replaced by a space. Every check here reasons about
// code, and a sentence in a doc comment that happens to contain "return 1" or "while" is not code.
func read(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return stripComments(string(b))
}

// readRaw returns a source file's text unchanged, for the checks that are about the comments themselves.
func readRaw(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

// stripComments removes /* */ and // comments while preserving line structure and string literals, which is
// enough for C that never puts a comment marker inside a string.
func stripComments(src string) string {
	var out strings.Builder
	out.Grow(len(src))
	for i := 0; i < len(src); {
		switch {
		case strings.HasPrefix(src[i:], "/*"):
			end := strings.Index(src[i+2:], "*/")
			if end < 0 {
				return out.String()
			}
			for _, r := range src[i : i+2+end+2] {
				if r == '\n' {
					out.WriteByte('\n')
				}
			}
			i += 2 + end + 2
		case strings.HasPrefix(src[i:], "//"):
			end := strings.IndexByte(src[i:], '\n')
			if end < 0 {
				return out.String()
			}
			out.WriteByte('\n')
			i += end + 1
		case src[i] == '"':
			j := i + 1
			for j < len(src) && src[j] != '"' {
				if src[j] == '\\' {
					j++
				}
				j++
			}
			if j >= len(src) {
				out.WriteString(src[i:])
				return out.String()
			}
			out.WriteString(src[i : j+1])
			i = j + 1
		default:
			out.WriteByte(src[i])
			i++
		}
	}
	return out.String()
}

// programs extracts every SEC()-annotated function body from a source, by brace counting from the opening
// brace that follows the declaration.
func programs(t *testing.T, path string) []program {
	t.Helper()
	src := read(t, path)
	var out []program
	for _, m := range secRe.FindAllStringSubmatchIndex(src, -1) {
		section := src[m[2]:m[3]]
		rest := src[m[1]:]
		decl := funcRe.FindStringSubmatch(rest)
		if decl == nil {
			continue // a SEC() on something that is not a program, such as .maps or license
		}
		open := strings.Index(rest, "{")
		if open < 0 {
			t.Fatalf("%s: SEC(%q) has no function body", path, section)
		}
		depth, end := 0, -1
		for i := open; i < len(rest); i++ {
			switch rest[i] {
			case '{':
				depth++
			case '}':
				depth--
				if depth == 0 {
					end = i
				}
			}
			if end >= 0 {
				break
			}
		}
		if end < 0 {
			t.Fatalf("%s: SEC(%q) body is unbalanced", path, section)
		}
		out = append(out, program{file: filepath.Base(path), section: section, name: decl[1], body: rest[open : end+1]})
	}
	return out
}

// localIncludeRe matches an #include of a header that lives beside the sources in bpf/ itself (not include/).
var localIncludeRe = regexp.MustCompile(`(?m)^#include "([a-z_]+\.h)"$`)

// programsWithIncludes is programs of a source and of every header in bpf/ it includes: cgroup_net.bpf.c defines
// its packet, sockops and sock_release programs in net_packet.h and net_budget.h, which sources() never globs.
func programsWithIncludes(t *testing.T, path string) []program {
	t.Helper()
	out := programs(t, path)
	for _, m := range localIncludeRe.FindAllStringSubmatch(read(t, path), -1) {
		header := filepath.Join(sourceDir, m[1])
		if _, err := os.Stat(header); err == nil {
			out = append(out, programs(t, header)...)
		}
	}
	return out
}

// TestLicenceAndSPDX covers ADR 0012 and §9: the dual SPDX header on line one and the license section every
// program needs before the kernel will let it call a GPL-only helper.
func TestLicenceAndSPDX(t *testing.T) {
	t.Parallel()
	for _, path := range sources(t) {
		t.Run(filepath.Base(path), func(t *testing.T) {
			src := readRaw(t, path)
			if !strings.HasPrefix(src, dualSPDX) {
				t.Errorf("first line is not %q", dualSPDX)
			}
			if !strings.Contains(src, licenseDecl) {
				t.Errorf("missing %s", licenseDecl)
			}
		})
	}
}

// TestEveryInlineHelperHasACaller: a static helper nothing calls is never emitted, and reads as a path the
// programs take. tego_listen_sample suggested socket_bind refusals had a record of their own while their only line
// was the terminal bind producer's (decide_socket.h). A test-only program (testonly/) is a caller: its object is
// built and loaded, as ADR 0048 P2's K0 probe calls bpf/include/exec_pin.h's MAC before the plane does.
func TestEveryInlineHelperHasACaller(t *testing.T) {
	t.Parallel()
	var all strings.Builder
	for _, glob := range []string{"*.bpf.c", "*.h", filepath.Join("include", "*.h"), filepath.Join("testonly", "*.bpf.c")} {
		paths, err := filepath.Glob(filepath.Join(sourceDir, glob))
		if err != nil {
			t.Fatalf("glob: %v", err)
		}
		for _, path := range paths {
			if filepath.Base(path) != "vmlinux.h" {
				all.WriteString(read(t, path))
			}
		}
	}
	src := all.String()
	defs := regexp.MustCompile(`static __always_inline [a-z_ 0-9*]+\b(tego_[a-z0-9_]+)\(`).FindAllStringSubmatch(src, -1)
	if len(defs) == 0 {
		t.Fatal("no static __always_inline helpers found")
	}
	for _, d := range defs {
		if n := len(regexp.MustCompile(`\b`+d[1]+`\(`).FindAllStringIndex(src, -1)); n < 2 {
			t.Errorf("%s is defined and never called", d[1])
		}
	}
}

// TestHeaderSPDX asserts every shared header carries a licence too. vmlinux.h is generated and exempt
// (scripts/check-spdx.sh, docs/REPO-LAYOUT.md); the vendored libbpf headers carry their own upstream line.
func TestHeaderSPDX(t *testing.T) {
	t.Parallel()
	headers, err := filepath.Glob(filepath.Join(sourceDir, "include", "*.h"))
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	if len(headers) == 0 {
		t.Fatal("no headers found")
	}
	for _, path := range headers {
		if filepath.Base(path) == "vmlinux.h" {
			continue
		}
		if !strings.HasPrefix(readRaw(t, path), dualSPDX) {
			t.Errorf("%s: first line is not %q", path, dualSPDX)
		}
	}
}

// TestSectionNames asserts every attach point matches bpf/README.md's table exactly: the kernel resolves a
// program by this string, so a typo is a load failure at the worst possible moment.
func TestSectionNames(t *testing.T) {
	t.Parallel()
	want := map[string][]string{
		"cgroup_net.bpf.c": {
			"cgroup/connect4", "cgroup/connect6", "cgroup/sendmsg4", "cgroup/sendmsg6",
			"cgroup/bind4", "cgroup/bind6", "cgroup/post_bind4", "cgroup/post_bind6", "cgroup/connect_unix", "cgroup/sendmsg_unix",
			"cgroup/sock_create", "cgroup/setsockopt",
			// net_packet.h and net_budget.h, which cgroup_net.bpf.c includes
			"cgroup_skb/ingress", "cgroup_skb/egress", "sockops", "cgroup/sock_release",
		},
		"cgroup_track.bpf.c": {"tp_btf/cgroup_mkdir", "tp_btf/cgroup_rmdir"},
		"trace_proc.bpf.c": {
			"tp_btf/sched_process_exec", "tp_btf/sched_process_exit",
			"tracepoint/syscalls/sys_exit_execve", "tracepoint/syscalls/sys_exit_execveat", "tracepoint/syscalls/sys_exit_bind", "tracepoint/syscalls/sys_exit_listen",
			"fexit/security_file_open", "fexit/security_path_unlink", "fexit/security_path_rename",
			"fexit/security_path_mkdir", "fexit/security_path_mknod", "fexit/security_path_rmdir",
			"fexit/security_path_link", "fexit/security_path_symlink", "fexit/security_path_truncate",
			"fexit/security_file_truncate", "fentry/security_socket_connect", "fexit/io_bind", "fexit/io_listen",
		},
	}
	for _, path := range sources(t) {
		base := filepath.Base(path)
		expected, ok := want[base]
		if !ok {
			continue // a source another ticket owns; its own test pins its sections
		}
		t.Run(base, func(t *testing.T) {
			var got []string
			for _, p := range programsWithIncludes(t, path) {
				got = append(got, p.section)
			}
			slices.Sort(got)
			sorted := slices.Clone(expected)
			slices.Sort(sorted)
			if !slices.Equal(got, sorted) {
				t.Fatalf("sections = %v, want %v", got, sorted)
			}
		})
	}
}

// TestRunSetLookupFirst covers docs/p0/enforce-cgroup-observe.md I1: every hook consults the run set before anything else, through the shared
// helper, and no hook ever walks a cgroup ancestry at hook time (§5 R2). cgroup_net.bpf.c's packet, sockops and
// sock_release programs live in its headers and are scanned too; they never read the run set (their run is the
// attachment's cgroup storage, as the sock_addr programs' is) and read the run's network-control maps by that
// run_idx in their own bodies, so the direct-lookup rule alone is not theirs.
//
// One named exception to "run set before the reserve": cgroup_net.bpf.c's tego_cg_sock_create and
// tego_cg_setsockopt, the two network programs that record (§5 R5 as amended, ADR 0018 PR 2 and (7)). Their run is
// their attachment's owner storage, which TestNetDecisionReadsTheAttachmentNotTheCaller forbids them to take from a
// run-set lookup, so I1's intent (the record's run is decided before anything is reserved) is held by the storage
// read and its configured guard coming first.
func TestRunSetLookupFirst(t *testing.T) {
	t.Parallel()
	for _, path := range sources(t) {
		for _, p := range programsWithIncludes(t, path) {
			t.Run(p.file+"/"+p.name, func(t *testing.T) {
				if strings.Contains(p.body, "bpf_map_lookup_elem(&tego_run_set") {
					t.Fatalf("looks the run set up directly; use tego_run_lookup/tego_current_run so I1 stays checkable")
				}
				direct := strings.Count(p.body, "bpf_map_lookup_elem(")
				if fromHeader := p.file != filepath.Base(path); fromHeader && !strings.Contains(p.body, "bpf_get_local_storage(&tego_net_owners") {
					t.Fatalf("a header program that does not take its run from tego_net_owners")
				} else if direct > 0 && !fromHeader {
					t.Fatalf("%d direct map lookups in a program body; the verdict maps are read through helpers", direct)
				}
				for _, banned := range []string{"bpf_get_current_ancestor_cgroup_id", "cgrp_ancestor", "->self.parent->"} {
					if strings.Contains(p.body, banned) {
						t.Fatalf("uses %q: no hook may walk cgroup ancestry at hook time (R2)", banned)
					}
				}
				// "before anything else": a program that reserves a ring-buffer record must have decided it
				// belongs to a run first, so an unmatched cgroup costs one map lookup and nothing more.
				reserve := strings.Index(p.body, "bpf_ringbuf_reserve(")
				if reserve < 0 {
					return
				}
				if p.file == "cgroup_net.bpf.c" && (p.name == "tego_cg_sock_create" || p.name == "tego_cg_setsockopt") {
					storage := strings.Index(p.body, "bpf_get_local_storage(&tego_net_owners")
					guard := strings.Index(p.body, "owner->cgroup_id == 0")
					if storage < 0 || guard < storage || reserve < guard {
						t.Fatalf("reserves a ring-buffer record before reading its run from tego_net_owners behind " +
							"the configured guard (I1's exception for the owner-storage program)")
					}
					return
				}
				lookup := strings.Index(p.body, "tego_run_lookup(")
				if lookup < 0 {
					lookup = strings.Index(p.body, "tego_current_run(")
				}
				if lookup < 0 || lookup > reserve {
					t.Fatalf("reserves a ring-buffer record before looking the run set up (I1)")
				}
			})
		}
	}
}

// TestRecordsGoToTheRunsOwnRing is ADR 0026 (1): no source reserves on a ring outer or a map named directly, only
// on the ring tego_ring_of (or capture's tego_capture_ring, which wraps it) looked up by the run's slot after the
// run-set hit, and a lost count is always taken at the run's slot. A reserve on a named map is a ring every run of
// the build shares, which takes one reader, so a second concurrent run of a build had no record and no capture.
func TestRecordsGoToTheRunsOwnRing(t *testing.T) {
	t.Parallel()
	for _, path := range sources(t) {
		src := read(t, path)
		if strings.Contains(src, "bpf_ringbuf_reserve(&") {
			t.Errorf("%s reserves on a map it names; reserve on the run's own ring (tego_ring_of)", path)
		}
		for _, call := range regexp.MustCompile(`tego_lost_inc\([^;]*\)`).FindAllString(stripComments(src), -1) {
			if path == filepath.Join(sourceDir, "cgroup_track.bpf.c") && call == "tego_lost_inc(&tego_tracking_failed, val.run_idx)" {
				continue // Membership insertion uses the inherited parent row's slot, before ring emission.
			}
			if !regexp.MustCompile(`,\s*run->run_idx\)$`).MatchString(call) && !strings.HasPrefix(call, "tego_lost_inc(void *") {
				t.Errorf("%s counts a loss at no run's slot: %s", path, call)
			}
		}
	}
	common := read(t, filepath.Join(sourceDir, "include", "common.h"))
	if !strings.Contains(common, "bpf_map_lookup_elem(outer, &idx)") {
		t.Error("tego_ring_of no longer looks the ring up by the run's slot")
	}
}

// TestCgroupProgramsReturnOnlyZeroOrOne covers I3: a cgroup_net program returns 1 (allow, which is also what R4's
// protocol guard and a run with no listener control return) or 0 (refuse) and nothing else. Anything else is either
// a verifier rejection or, worse, a value the kernel reads as allow. The check covers each SEC() body, those of the
// headers cgroup_net.bpf.c includes (the packet, sockops and sock_release programs), and the shared decisions they
// tail into; the decisions also keep an exact count of their allow and refusal returns, so an added early allow
// (on a missing map row, say) has to change this test too.
func TestCgroupProgramsReturnOnlyZeroOrOne(t *testing.T) {
	t.Parallel()
	path := filepath.Join(sourceDir, "cgroup_net.bpf.c")
	if _, err := os.Stat(path); err != nil {
		t.Skipf("cgroup_net.bpf.c not present: %v", err)
	}
	bodies := map[string]string{}
	inHeader := map[string]bool{}
	for _, p := range programsWithIncludes(t, path) {
		bodies[p.name] = p.body
		inHeader[p.name] = p.file != filepath.Base(path)
	}
	for _, name := range []string{"tego_cg_ingress", "tego_cg_egress", "tego_cg_sockops", "tego_cg_release"} {
		if !inHeader[name] {
			t.Errorf("%s is not among the programs of cgroup_net.bpf.c's own headers; this test no longer sees it", name)
		}
	}
	packet := filepath.Join(sourceDir, "net_packet.h")
	delegates := map[string]string{
		"tego_net_decide": path, "tego_unix_decide": path, "tego_bind_decide": path, "tego_commit_bind": path,
		"tego_packet_ingress": packet, "tego_packet_egress": packet, "tego_flow_save": packet,
	}
	for name, file := range delegates {
		bodies[name] = functionBody(t, file, name)
		inHeader[name] = file != path
	}

	for name, value := range map[string]string{"TEGO_SOCK_OK": "1", "TEGO_SOCK_REFUSE": "0"} {
		if !regexp.MustCompile(`(?m)^#define ` + name + ` ` + value + `$`).MatchString(read(t, path)) {
			t.Errorf("%s must expand to %s", name, value)
		}
	}
	returnRe := regexp.MustCompile(`return\s+([^;]+);`)
	for name, body := range bodies {
		for _, m := range returnRe.FindAllStringSubmatch(body, -1) {
			expr := strings.TrimSpace(m[1])
			if call, _, ok := strings.Cut(expr, "("); ok && delegates[call] != "" {
				continue // the SEC() bodies tail into a checked shared decision
			}
			switch {
			case expr == "TEGO_SOCK_OK" || expr == "TEGO_SOCK_REFUSE":
				continue
			case (inHeader[name] || name == "tego_commit_bind") && (expr == "0" || expr == "1"):
				continue // the packet, sockops and sock programs and post_bind's commit spell the two values bare
			case name == "tego_commit_bind" && expr == "err == 0":
				continue // a C comparison is exactly zero or one
			case name == "tego_flow_save" && strings.HasSuffix(expr, "== 0"):
				continue
			case name == "tego_cg_ingress" && expr == "admitted" && strings.Contains(body, "int admitted = tego_packet_ingress("):
				continue
			}
			t.Errorf("%s returns %q; only TEGO_SOCK_OK and TEGO_SOCK_REFUSE are permitted (I3)", name, expr)
		}
	}
	// Exact counts per decision (I3). tego_net_decide: R4's protocol guard and the allow verdict allow; the
	// verdict refusal and the connection-budget refusal (tego_reserve_socket) refuse. R1's neutral branch for a
	// cgroup absent from the run set went with the lookup it guarded (TestNetDecisionReadsTheAttachmentNotTheCaller).
	// tego_unix_decide has no protocol guard: one allow and one refusal, both at its end (R7). tego_bind_decide
	// allows a run with no listener control (its legacy behaviour) and a granted address; it refuses an attachment
	// not configured yet, a protocol other than TCP or UDP, an address without a grant, and an attempt it could
	// not record for post_bind's commit. tego_cg_sock_create allows the allowlist's triples only; it refuses an
	// attachment not configured yet, a refusal whose record could not be reserved, and a recorded refusal.
	// tego_cg_setsockopt allows every option but TCP_ULP, and refuses as tego_cg_sock_create does.
	for _, c := range []struct {
		name          string
		allow, refuse int
	}{{"tego_net_decide", 2, 2}, {"tego_unix_decide", 1, 1}, {"tego_bind_decide", 2, 4}, {"tego_cg_sock_create", 1, 3}, {"tego_cg_setsockopt", 1, 3}} {
		body := bodies[c.name]
		if n := strings.Count(body, "return TEGO_SOCK_OK;"); n != c.allow {
			t.Errorf("%s has %d allow returns, want exactly %d (I3)", c.name, n, c.allow)
		}
		if n := strings.Count(body, "return TEGO_SOCK_REFUSE;"); n != c.refuse {
			t.Errorf("%s has %d refusal returns, want exactly %d (I3)", c.name, n, c.refuse)
		}
	}
}

// TestNetDecisionReadsTheAttachmentNotTheCaller covers the fix for a tier-2 network verdict that never
// happened. The kernel picks a CGROUP_SOCK_ADDR program array by the socket's cgroup, so the run's connect4/6
// runs for every connect on the agent's sockets; but the seccomp supervisor makes each allowed connect itself,
// from its own process, on a pidfd_getfd duplicate (docs/p0/supervisor.md R9, I2). A decision keyed by
// bpf_get_current_cgroup_id() therefore looked up the supervisor's cgroup, missed the run set, took R1's
// neutral branch and allowed, and wrote no breadcrumb. The run is now the one the attachment belongs to, read
// from the attach point's cgroup storage, and an attachment whose storage is still zero refuses.
//
// The one use of the caller's cgroup left is connect_unix's recognition of the supervisor's relay name
// (/proc/self/fd/<n>, §5 R7), which must know who is calling because that name means something only in the
// relaying process. It selects no run and no row: it compares the caller with the relay cgroup Attach wrote
// into the owner, inside tego_unix_relayed alone, and neither decision function calls the helper itself.
func TestNetDecisionReadsTheAttachmentNotTheCaller(t *testing.T) {
	t.Parallel()
	path := filepath.Join(sourceDir, "cgroup_net.bpf.c")
	src := read(t, path)
	for _, banned := range []string{"tego_current_run(", "tego_run_lookup("} {
		if strings.Contains(src, banned) {
			t.Errorf("cgroup_net.bpf.c calls %s; the caller of connect(2) is the supervisor for every relayed "+
				"connect, so a network decision must not be keyed by it", strings.TrimSuffix(banned, "("))
		}
	}
	relayed := functionBody(t, path, "tego_unix_relayed")
	if n, all := strings.Count(relayed, "bpf_get_current_cgroup_id("), strings.Count(src, "bpf_get_current_cgroup_id("); n != 1 || all != 1 {
		t.Errorf("bpf_get_current_cgroup_id is called %d times in all, %d of them in tego_unix_relayed; the "+
			"caller's cgroup is read once, to recognise the supervisor's relay, and nowhere else", all, n)
	}
	if !strings.Contains(relayed, "bpf_get_current_cgroup_id() != owner->relay_cgroup_id") ||
		!strings.Contains(relayed, "owner->relay_cgroup_id == 0") {
		t.Errorf("tego_unix_relayed does not compare the caller with the owner's relay cgroup, or admits the " +
			"relay name when Attach wrote none")
	}
	unixDecide := functionBody(t, path, "tego_unix_decide")
	if !strings.Contains(unixDecide, "bpf_get_local_storage(&tego_net_owners") ||
		!strings.Contains(unixDecide, "owner->cgroup_id != 0") {
		t.Errorf("tego_unix_decide does not read its run from tego_net_owners behind the configured guard")
	}
	if key := strings.Index(unixDecide, "tego_unix_key_of("); key < strings.Index(unixDecide, "owner->cgroup_id != 0") {
		t.Errorf("tego_unix_decide builds its key before checking the attachment is configured")
	}
	decide := functionBody(t, path, "tego_net_decide")
	storage := strings.Index(decide, "bpf_get_local_storage(&tego_net_owners")
	if storage < 0 {
		t.Fatalf("tego_net_decide does not read its run from tego_net_owners, the attach point's cgroup storage")
	}
	guard := strings.Index(decide, "owner->cgroup_id != 0")
	if guard < 0 {
		t.Fatalf("tego_net_decide has no guard for an attachment whose storage is not configured yet")
	}
	// Everything that can reach the allow verdict sits inside the configured branch: the key is built from
	// the owner's run_idx only once the owner is known.
	if key := strings.Index(decide, "tego_net_key_of("); key < guard {
		t.Errorf("tego_net_decide builds the verdict key before checking the attachment is configured")
	}
	if strings.Contains(decide, "TEGO_V_ALLOW;") && !strings.Contains(decide, "verdict = TEGO_V_REFUSED") {
		t.Errorf("the decision's verdict does not start as a refusal")
	}
	if !strings.Contains(read(t, filepath.Join(sourceDir, "include", "maps.h")), "BPF_MAP_TYPE_CGROUP_STORAGE") {
		t.Errorf("maps.h defines no cgroup storage map for the network programs")
	}
}

// functionBody extracts one named function's body by brace counting. An occurrence of the name followed by a ';'
// before any '{' is a declaration or a call, not the definition, and is passed over.
func functionBody(t *testing.T, path, name string) string {
	t.Helper()
	src := read(t, path)
	i, open := -1, -1
	for from := 0; ; {
		k := strings.Index(src[from:], name+"(")
		if k < 0 {
			break
		}
		k += from
		o := strings.Index(src[k:], "{")
		if o >= 0 && !strings.Contains(src[k:k+o], ";") {
			i, open = k, o
			break
		}
		from = k + len(name)
	}
	if i < 0 {
		t.Fatalf("%s: no function %s", path, name)
	}
	rest := src[i+open:]
	depth := 0
	for j := 0; j < len(rest); j++ {
		switch rest[j] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return rest[:j+1]
			}
		}
	}
	t.Fatalf("%s: %s body is unbalanced", path, name)
	return ""
}

// TestTracingProgramsReturnZero covers ARCHITECTURE §11.1 rule 2 for this component's tracing programs: a
// record-only program never reports a verdict, so it returns 0 and only 0.
func TestTracingProgramsReturnZero(t *testing.T) {
	t.Parallel()
	for _, path := range sources(t) {
		for _, p := range programs(t, path) {
			if !strings.HasPrefix(p.section, "tp_btf/") && !strings.HasPrefix(p.section, "fentry/") &&
				!strings.HasPrefix(p.section, "fexit/") {
				continue
			}
			t.Run(p.file+"/"+p.name, func(t *testing.T) {
				for _, m := range regexp.MustCompile(`return\s+([^;]*);`).FindAllStringSubmatch(p.body, -1) {
					if expr := strings.TrimSpace(m[1]); expr != "0" {
						t.Errorf("returns %q; a record-only program returns 0 (ARCHITECTURE §11.1)", expr)
					}
				}
			})
		}
	}
}

// TestDPathOnlyWhereAllowed covers R9/R10: bpf_d_path may be called only from the one program whose hook the
// kernel's fixed btf_allowlist_d_path BTF_SET contains that uses it, security_file_open's. The other
// security_path_* hooks but truncate are in that set on no kernel version, so a call from them would be a load
// failure — and, before that, a design error; the truncate programs carry the fsop layout like the rest.
func TestDPathOnlyWhereAllowed(t *testing.T) {
	t.Parallel()
	allowed := map[string]bool{
		"fexit/security_file_open": true,
		"lsm/file_open":            true, // tier 3's own program, when it lands
	}
	for _, path := range sources(t) {
		for _, p := range programs(t, path) {
			if strings.Contains(p.body, "bpf_d_path(") && !allowed[p.section] {
				t.Errorf("%s: %s calls bpf_d_path from SEC(%q), which is not in btf_allowlist_d_path (R9/R10)",
					p.file, p.name, p.section)
			}
		}
	}
}

// TestNoInodeKeyedKernelMap covers docs/p0/enforce-cgroup-observe.md I9: ADR 0010's inode storage stays tier-3-only, and no map this component
// defines is keyed by a (device, inode) pair. The only (dev, inode) structure here is userspace's dirIndex.
//
// The decision plane's rows (ADR 0025, which supersedes 0010) are keyed by a struct inode * and are the one
// exception: they are declared only inside maps.h's TEGO_PLANE_MAPS block, which only bpf/decide.bpf.c compiles.
func TestNoInodeKeyedKernelMap(t *testing.T) {
	t.Parallel()
	raw := readRaw(t, filepath.Join(sourceDir, "include", "maps.h"))
	planeStart, planeEnd := strings.Index(raw, "#ifdef TEGO_PLANE_MAPS"), strings.Index(raw, "#endif /* TEGO_PLANE_MAPS */")
	if planeStart < 0 || planeEnd < planeStart {
		t.Fatal("maps.h has no TEGO_PLANE_MAPS block")
	}
	outside := raw[:planeStart] + raw[planeEnd:]
	if strings.Contains(outside, "struct inode *") {
		t.Error("maps.h keys a map by an inode pointer outside TEGO_PLANE_MAPS")
	}
	maps := stripComments(outside)
	for _, banned := range []string{"BPF_MAP_TYPE_INODE_STORAGE", "dir_ino", "i_ino", "devino"} {
		if strings.Contains(maps, banned) {
			t.Errorf("maps.h mentions %q: no kernel map here may key on an inode (I9, ADR 0010)", banned)
		}
	}
	for _, path := range sources(t) {
		if strings.Contains(read(t, path), "BPF_MAP_TYPE_INODE_STORAGE") {
			t.Errorf("%s declares a BPF_MAP_TYPE_INODE_STORAGE map, which is tier-3-only (I9)", path)
		}
		if base := filepath.Base(path); base != "decide.bpf.c" && base != "decide_fill.bpf.c" &&
			strings.Contains(read(t, path), "#define TEGO_PLANE_MAPS") {
			t.Errorf("%s compiles the plane's inode-keyed maps; only decide.bpf.c and its fill may", path)
		}
	}
}

// TestNoRingbufRetryLoop covers I7: a failed reserve bumps the lost counter and returns; it never retries
// and never blocks a kernel-side producer. Every reserve's NULL branch must reach tego_lost_inc, no reserve
// may sit inside a loop, and every reserved record must be submitted.
func TestNoRingbufRetryLoop(t *testing.T) {
	t.Parallel()
	for _, path := range sources(t) {
		src := read(t, path)
		reserves := strings.Count(src, "bpf_ringbuf_reserve(")
		if reserves == 0 {
			continue
		}
		t.Run(filepath.Base(path), func(t *testing.T) {
			// Each reserve is immediately followed by its NULL check and the lost-counter bump.
			for i := 0; ; {
				j := strings.Index(src[i:], "bpf_ringbuf_reserve(")
				if j < 0 {
					break
				}
				i += j + 1
				window := src[i:min(i+300, len(src))]
				if !strings.Contains(window, "tego_lost_inc(") {
					t.Errorf("a bpf_ringbuf_reserve at offset %d has no tego_lost_inc on its failure path (I7)", i)
				}
			}
			// do { ... } while (0) is a macro idiom, not a loop; anything else is a retry.
			for _, loop := range whileRe.FindAllString(src, -1) {
				if !whileZeroRe.MatchString(loop) {
					t.Errorf("contains %q; a reserve is never retried (I7)", loop)
				}
			}
			if strings.Contains(src, "goto ") {
				t.Errorf("contains a goto; a reserve is never retried (I7)")
			}
			if submits := strings.Count(src, "bpf_ringbuf_submit("); submits < reserves {
				t.Errorf("%d reserves and only %d submits; a reserved record is always submitted", reserves, submits)
			}
			if strings.Contains(src, "bpf_ringbuf_output(") {
				t.Errorf("uses bpf_ringbuf_output; this component reserves and submits so a record is never copied twice")
			}
		})
	}
}

// TestSharedHeadersOnly asserts every source draws its maps and structs from the shared headers rather than
// redeclaring them, which is what keeps bpf/include/events.h the single source of truth (§9).
func TestSharedHeadersOnly(t *testing.T) {
	t.Parallel()
	for _, path := range sources(t) {
		src := read(t, path)
		t.Run(filepath.Base(path), func(t *testing.T) {
			if !strings.Contains(src, `#include "maps.h"`) {
				t.Errorf("does not include maps.h")
			}
			if strings.Contains(src, `SEC(".maps")`) {
				t.Errorf("declares its own map; every map belongs in include/maps.h (§9)")
			}
			if strings.Contains(src, "#include <bpf/") {
				t.Errorf("includes a system libbpf header; the vendored copies under include/libbpf are the build's only input")
			}
		})
	}
}

// TestNoMapNamedLikeAStruct covers what stopped `make gen` after the targets were fixed. bpf2go resolves
// each -type name against every named type in the object's BTF, and a map is a named BTF variable, so a map
// called tego_ssl_scratch beside struct tego_ssl_scratch made the lookup ambiguous: "collect C types:
// looking up type tego_ssl_scratch: found multiple types". The check is over all shared headers, not only
// the structs gen.go names today, because the next -type flag would hit the same wall.
func TestNoMapNamedLikeAStruct(t *testing.T) {
	t.Parallel()
	mapRe := regexp.MustCompile(`\}\s*([A-Za-z_][A-Za-z0-9_]*)\s+SEC\("\.maps"\)`)
	structRe := regexp.MustCompile(`(?m)^struct\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{`)
	structs := map[string]string{}
	for _, h := range []string{"events.h", "common.h", "maps.h"} {
		for _, m := range structRe.FindAllStringSubmatch(read(t, filepath.Join(sourceDir, "include", h)), -1) {
			structs[m[1]] = h
		}
	}
	maps := mapRe.FindAllStringSubmatch(read(t, filepath.Join(sourceDir, "include", "maps.h")), -1)
	if len(maps) == 0 {
		t.Fatal("found no map definitions in maps.h")
	}
	for _, m := range maps {
		if h, clash := structs[m[1]]; clash {
			t.Errorf("map %s shares its name with struct %s in %s; bpf2go -type cannot tell them apart", m[1], m[1], h)
		}
	}
}

// TestContextReadByValue covers the verifier rejection that kept connect6 and sendmsg6 out of the kernel. A
// CGROUP_SOCK_ADDR context is rewritten load by load into the kernel's own struct, and only a load made
// directly off the context register at a constant offset can be rewritten. Passing ctx->user_ip6 to a helper
// passes a pointer into the context, which the helper's memcpy then advances and loads through: "dereference
// of modified ctx ptr". Every context member is therefore read by value, and user_ip6 one word at a time.
func TestContextReadByValue(t *testing.T) {
	t.Parallel()
	path := filepath.Join(sourceDir, "cgroup_net.bpf.c")
	src := read(t, path)
	if strings.Contains(src, "&ctx->") {
		t.Errorf("takes the address of a context member; the verifier refuses loads through it")
	}
	for _, m := range regexp.MustCompile(`ctx->user_ip6(.?)`).FindAllStringSubmatch(src, -1) {
		if m[1] != "[" {
			t.Errorf("uses ctx->user_ip6 as a pointer; read ctx->user_ip6[0..3] by value")
		}
	}
	if !strings.Contains(src, "ctx->user_ip6[3]") {
		t.Errorf("never reads the last word of ctx->user_ip6; an IPv6 key is built from all four")
	}
}

// TestFexitReadsTheChainAndRecordsRefusalsUnderRecordOff is ADR 0016 (3) as the source shows it: every fs program
// is an fexit program whose last declared argument is the chain's return, stores it in its record with ret_ok
// set, and skips a record for record: off only when the chain allowed (ret == 0), so a refusal is recorded under
// record: off too. The one fentry program left is security_socket_connect, whose return never holds connect4/6's
// verdict.
func TestFexitReadsTheChainAndRecordsRefusalsUnderRecordOff(t *testing.T) {
	t.Parallel()
	path := filepath.Join(sourceDir, "trace_proc.bpf.c")
	src := read(t, path)
	for _, p := range programs(t, path) {
		switch {
		case strings.HasPrefix(p.section, "fentry/") && p.section != "fentry/security_socket_connect":
			t.Errorf("SEC(%q) is fentry: an fs program must be fexit to read the chain's return", p.section)
		case strings.HasPrefix(p.section, "fexit/"):
			decl := src[strings.Index(src, "int BPF_PROG("+p.name):]
			decl = decl[:strings.Index(decl, ")")]
			if !strings.HasSuffix(decl, ", int ret") {
				t.Errorf("SEC(%q) does not declare the return after every argument: %s", p.section, decl)
			}
		}
	}
	for _, fill := range []string{"tego_fs_fill", "tego_fsop_init"} {
		body := helperBody(t, src, fill)
		if !strings.Contains(body, "e->ret = ret;") || !strings.Contains(body, "e->ret_ok = 1;") {
			t.Errorf("%s does not store the chain's return", fill)
		}
	}
	re := regexp.MustCompile(`[^\n]*!tego_recording\(run\)`)
	for _, m := range re.FindAllString(src, -1) {
		line := strings.TrimSpace(m)
		if strings.Contains(line, "ret == 0 && !tego_recording(run)") {
			continue
		}
		if line == "if (!tego_recording(run)" {
			continue // the connect record's own gate, after its flush
		}
		t.Errorf("record: off gates on %q: a refusal (ret != 0) must be recorded under record: off too", line)
	}
}

// TestHeldRecordsAreConsumedOnlyByTheirOwnAction pins that a held record is finished only by the hook of the action
// it holds (ADR 0016 (3), one action, one line). A held O_TRUNC open whose own truncate never ran (the open failed
// in the filesystem's ->open, or fanotify refused it from 6.13) was consumed by the task's next truncate of any
// file: that truncate's return became the open's verdict and the truncate itself got no line. A held mknod was
// dropped by any later open of its name, so a mknod(2) followed by a plain open of the file lost the mknod's line.
func TestHeldRecordsAreConsumedOnlyByTheirOwnAction(t *testing.T) {
	t.Parallel()
	src := read(t, filepath.Join(sourceDir, "trace_proc.bpf.c"))
	open := helperBody(t, " "+src[strings.Index(src, "BPF_PROG(tego_file_open,"):], "BPF_PROG")
	if !strings.Contains(open, "held->dentry = (__u64)TEGO_READ(file, f_path.dentry);") {
		t.Errorf("tego_file_open does not keep the dentry of the O_TRUNC open it holds")
	}
	if !regexp.MustCompile(`TEGO_HELD_CREATE &&[^;]*TEGO_O_CREAT[^;]*tego_held_names\(held, file\)`).MatchString(open) {
		t.Errorf("tego_file_open drops a held create for an open without O_CREAT: a mknod(2) then open loses its line")
	}
	trunc := helperBody(t, src, "tego_truncate")
	if !strings.Contains(trunc, "held->tag == TEGO_HELD_OPEN && held->dentry == (__u64)dentry") {
		t.Errorf("tego_truncate consumes a held open without asking whether the truncate is that open's")
	}
}

// TestRecorderSkipsPrivateCloneOpens pins that the recorder skips an open on a private clone of a mount (mnt_ns
// MNT_NS_INTERNAL), as the plane does (tego_internal_mount). overlayfs' copy-up opens the lower file and the new
// upper one there in the agent's task, after the agent's own open of the merged file: recorded, a first write to a
// lower file was three open lines, two of them layer-relative paths (ADR 0016 (3), one action, one line). The skip
// comes after the plane's scratch is taken, so its decision is still consumed, and before the hold is read, so the
// agent's own O_TRUNC hold waits for its truncate.
func TestRecorderSkipsPrivateCloneOpens(t *testing.T) {
	t.Parallel()
	src := read(t, filepath.Join(sourceDir, "trace_proc.bpf.c"))
	if !strings.Contains(src, "#define TEGO_MNT_NS_INTERNAL ((__u64)-22)") {
		t.Error("trace_proc has no TEGO_MNT_NS_INTERNAL, ERR_PTR(-EINVAL)")
	}
	internal := helperBody(t, src, "tego_rec_internal_mount")
	for _, want := range []string{
		"bpf_core_field_offset(struct mount, mnt)",
		"bpf_core_cast((void *)m, struct mount)->mnt_ns == TEGO_MNT_NS_INTERNAL",
		"BPF_CORE_READ((struct mount *)m, mnt_ns) == TEGO_MNT_NS_INTERNAL",
	} {
		if !strings.Contains(internal, want) {
			t.Errorf("tego_rec_internal_mount lacks %q (each build's reader of mnt_ns):\n%s", want, internal)
		}
	}
	open := helperBody(t, " "+src[strings.Index(src, "BPF_PROG(tego_file_open,"):], "BPF_PROG")
	take := strings.Index(open, "tego_plane_take(")
	skip := strings.Index(open, "if (tego_rec_internal_mount(file))\n        return 0;")
	held := strings.Index(open, "tego_held_of(")
	if skip < 0 {
		t.Fatalf("tego_file_open records opens on a private clone (overlayfs copy-up):\n%s", open)
	}
	if take < 0 || take > skip {
		t.Error("tego_file_open skips a private-clone open before taking the plane's scratch")
	}
	if held < 0 || held < skip {
		t.Error("tego_file_open reads the hold before skipping a private-clone open: copy-up would flush it")
	}
}

// TestExecArgvReadFailureIsMarked covers enforce-cgroup-observe.md §6 E25: when the exec probe's read of argv
// fails, the record is marked truncated, so the recorder raises the argv-truncated gap instead of writing an exec
// line that reads as one with no arguments.
func TestExecArgvReadFailureIsMarked(t *testing.T) {
	body := ""
	for _, p := range programs(t, filepath.Join(sourceDir, "trace_proc.bpf.c")) {
		if p.name == "tego_sched_exec" {
			body = p.body
		}
	}
	if body == "" {
		t.Fatal("trace_proc.bpf.c: no program tego_sched_exec")
	}
	flat := strings.Join(strings.Fields(body), " ")
	want := "if (bpf_probe_read_user(&e->argv, len, (void *)arg_start) == 0) e->argv_len = len; else e->argv_truncated = 1;"
	if !strings.Contains(flat, want) {
		t.Fatalf("tego_sched_exec: a failed argv read must set argv_truncated; want %q in the body", want)
	}
}
