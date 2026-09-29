// SPDX-License-Identifier: Apache-2.0

package bpftests

import (
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestNetMatchIsExactThenLongestPrefixThenRefused is docs/p0/enforce-cgroup-observe.md §5 R3 and §6 E8 in
// the source: the exact table is consulted first and CIDR is consulted only on a miss, so no CIDR row can outrank it and
// neither the order the rows were inserted in nor the width of an overlapping prefix matters; the CIDR
// table is looked up only after, at the full key width so the trie itself picks the longest prefix; and a
// destination neither names leaves the verdict at its refused, net-not-allowed default.
func TestNetMatchIsExactThenLongestPrefixThenRefused(t *testing.T) {
	t.Parallel()
	src := read(t, filepath.Join(sourceDir, "cgroup_net.bpf.c"))
	body := funcBody(t, src, "tego_net_match")
	exact := strings.Index(body, "bpf_map_lookup_elem(&tego_net_exact")
	cidr := strings.Index(body, "bpf_map_lookup_elem(&tego_net_cidr")
	if exact < 0 || cidr < 0 || exact > cidr {
		t.Fatalf("tego_net_match must look the exact table up before the CIDR table (exact at %d, cidr at %d)", exact, cidr)
	}
	miss := regexp.MustCompile(`if \(!v\)\s*\{`).FindStringIndex(body)
	if miss == nil || miss[0] < exact || miss[1] > cidr {
		t.Fatal("the CIDR lookup must be inside the exact-miss branch")
	}
	depth, end := 1, miss[1]
	for ; end < len(body) && depth > 0; end++ {
		switch body[end] {
		case '{':
			depth++
		case '}':
			depth--
		}
	}
	if cidr >= end || strings.Contains(body[end:], "bpf_map_lookup_elem(&tego_net_cidr") {
		t.Error("a prefix lookup can replace an exact hit")
	}
	if !strings.Contains(body, "prefixlen = TEGO_LPM_MAX_BITS") {
		t.Errorf("the CIDR lookup must ask for the full key width, so the trie returns the longest matching prefix")
	}
	decide := funcBody(t, src, "tego_net_decide")
	if !strings.Contains(decide, "__u8 verdict = TEGO_V_REFUSED;") || !strings.Contains(decide, "__u8 reason = TEGO_R_NET_NOT_ALLOWED;") {
		t.Errorf("a destination no row names must default to a refusal with net-not-allowed")
	}
}

// TestBindProgramsRequireAdmissionBeforeSuccessfulAttribution checks F3's copied
// address admission and successful-post-bind commit boundary. Legacy nil listener
// controls retain their behavior; an explicit empty table has no matching grant.
func TestBindProgramsRequireAdmissionBeforeSuccessfulAttribution(t *testing.T) {
	t.Parallel()
	path := filepath.Join(sourceDir, "cgroup_net.bpf.c")
	src := read(t, path)
	found := map[string]bool{}
	for _, p := range programs(t, path) {
		if p.section != "cgroup/bind4" && p.section != "cgroup/bind6" && p.section != "cgroup/post_bind4" && p.section != "cgroup/post_bind6" {
			continue
		}
		found[p.section] = true
		call := "tego_bind_decide(ctx, TEGO_AF_INET)"
		if p.section == "cgroup/bind6" {
			call = "tego_bind_decide(ctx, TEGO_AF_INET6)"
		} else if strings.HasPrefix(p.section, "cgroup/post_bind") {
			call = "tego_commit_bind(ctx)"
		}
		if got := strings.Join(strings.Fields(p.body), " "); got != "{ return "+call+"; }" {
			t.Errorf("%s must delegate its copied address or successful completion to %s; got %q", p.name, call, got)
		}
	}
	if len(found) != 4 {
		t.Fatalf("found %v, want both bind and post-bind families", found)
	}
	bind := funcBody(t, src, "tego_bind_decide")
	for _, invariant := range []string{
		"if (!owner->cgroup_id)",
		"if (!control || !(control->flags & TEGO_NC_LISTEN))",
		"tego_net_key_of(&key, ctx, owner->run_idx, family)",
		"if (!grant || grant->verdict != TEGO_V_ALLOW)",
		"attempt.socket.gen = control->gen",
		"attempt.task = bpf_get_current_pid_tgid()",
	} {
		if !strings.Contains(bind, invariant) {
			t.Errorf("bind admission is missing %q", invariant)
		}
	}
	refused := strings.Index(bind, "if (!grant || grant->verdict != TEGO_V_ALLOW)")
	pending := strings.Index(bind, "bpf_map_update_elem(&tego_bind_pending")
	if refused < 0 || pending < refused || strings.Contains(bind, "bpf_map_update_elem(&tego_net_binds") {
		t.Error("a bind attempt must be admitted before staging and must not commit successful attribution")
	}
	commit := funcBody(t, src, "tego_commit_bind")
	lookup := strings.Index(commit, "bpf_map_lookup_elem(&tego_bind_pending")
	missing := strings.Index(commit, "if (!rule)")
	write := strings.Index(commit, "bpf_map_update_elem(&tego_net_binds")
	clear := strings.Index(commit, "bpf_map_delete_elem(&tego_bind_pending")
	if lookup < 0 || missing < lookup || write < missing || clear < write || !strings.Contains(commit, "return err == 0;") {
		t.Error("successful post-bind must require, commit and consume the exact pending admission")
	}
	decide := funcBody(t, src, "tego_net_decide")
	reserve := strings.Index(decide, "!tego_reserve_socket(")
	if reserve < 0 || !strings.Contains(decide[reserve:], "return TEGO_SOCK_REFUSE;") {
		t.Error("an admitted destination must still refuse an exhausted socket reservation")
	}
}

// funcBody returns the braced body of the function name in src.
func funcBody(t *testing.T, src, name string) string {
	t.Helper()
	i := strings.Index(src, name+"(")
	if i < 0 {
		t.Fatalf("no function %s in the source", name)
	}
	open := strings.Index(src[i:], "{")
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
	t.Fatalf("function %s is unbalanced", name)
	return ""
}

// TestConnectRecordNeedsTheFamilysAddress is docs/p0/enforce-cgroup-observe.md R5's "the connect record reads
// only what the caller passed": security_socket_connect runs before the protocol's own length check, so an
// AF_INET address shorter than sockaddr_in, or an AF_INET6 one shorter than SIN6_LEN_RFC2133, reached it with
// addrlen >= 2 and was recorded zeroed, a line naming 0.0.0.0:0 for a call that fails EINVAL. The program must
// return before it reserves a record for either (the supervisor keeps its line for them, supervisor R7).
func TestConnectRecordNeedsTheFamilysAddress(t *testing.T) {
	t.Parallel()
	var body string
	for _, p := range programs(t, filepath.Join(sourceDir, "trace_proc.bpf.c")) {
		if p.section == "fentry/security_socket_connect" {
			body = p.body
		}
	}
	if body == "" {
		t.Fatal("trace_proc.bpf.c has no fentry/security_socket_connect program")
	}
	reserve := strings.Index(body, "bpf_ringbuf_reserve(")
	if reserve < 0 {
		t.Fatal("the connect program reserves no record")
	}
	for _, re := range []*regexp.Regexp{
		regexp.MustCompile(`if \(family == TEGO_AF_INET && addrlen < \(int\)sizeof\(struct sockaddr_in\)\)\s*return 0;`),
		regexp.MustCompile(`if \(family == TEGO_AF_INET6 && addrlen < 24\s*\)\s*return 0;`), // 24: SIN6_LEN_RFC2133
	} {
		if m := re.FindStringIndex(body); m == nil || m[0] > reserve {
			t.Errorf("the connect program must return before bpf_ringbuf_reserve when %s", re)
		}
	}
}

// TestSockCreateIsTheAllowlistOnTheAttachmentsRun is ADR 0018 PR 2 (enforce-cgroup-observe §5 R4, R5) in the
// source. cgroup/sock_create takes its run from the attachment's owner storage and refuses before anything else
// while that storage is unconfigured (R1); it decides with the one allowlist the plane's socket_create uses
// (include/socket_allow.h, ADR 0018 (1)), ping sockets as the owner's flag says, on the whole protocol number (a
// (__u8) cast makes MPTCP's 262 TCP and IPPROTO_SMC's 256 protocol 0); and a refusal records its own line on the
// run's ring, found by the owner's run_idx and stamped with the owner's gen and cgroup id, under record: off too,
// before it returns the kernel's EPERM.
func TestSockCreateIsTheAllowlistOnTheAttachmentsRun(t *testing.T) {
	t.Parallel()
	path := filepath.Join(sourceDir, "cgroup_net.bpf.c")
	src := read(t, path)
	if !strings.Contains(src, `#include "socket_allow.h"`) {
		t.Fatal(`cgroup_net.bpf.c does not take the allowlist from include/socket_allow.h`)
	}
	var body string
	for _, p := range programs(t, path) {
		if p.section == "cgroup/sock_create" {
			body = p.body
		}
	}
	if body == "" {
		t.Fatal("cgroup_net.bpf.c has no cgroup/sock_create program")
	}
	order := []string{
		"bpf_get_local_storage(&tego_net_owners, 0)",
		"if (owner->cgroup_id == 0)\n        return TEGO_SOCK_REFUSE;",
		"if (tego_socket_allowed(family, type, protocol, (owner->flags & TEGO_OWNER_NET_ICMP) != 0))\n        return TEGO_SOCK_OK;",
		"r.run_idx = owner->run_idx;",
		"r.gen = owner->gen;",
		"tego_ring_of(&tego_events, run)",
		"bpf_ringbuf_reserve(ring, sizeof(*e), 0)",
		"tego_hdr_fill(&e->hdr, TEGO_EV_SOCK_CREATE, sizeof(*e), run, owner->cgroup_id);",
		"e->hdr.verdict = TEGO_V_REFUSED;",
		"e->hdr.reason = TEGO_R_NET_NOT_ALLOWED;",
		"bpf_ringbuf_submit(e, 0);\n    return TEGO_SOCK_REFUSE;\n}",
	}
	at := 0
	for _, want := range order {
		i := strings.Index(body[at:], want)
		if i < 0 {
			t.Fatalf("tego_cg_sock_create lacks, or has out of order, %q", want)
		}
		at += i + len(want)
	}
	for _, want := range []string{"int family = ctx->family;", "int type = ctx->type;", "int protocol = ctx->protocol;"} {
		if !strings.Contains(body, want) {
			t.Errorf("tego_cg_sock_create does not read %q whole", want)
		}
	}
	for _, banned := range []string{"(__u8)", "tego_recording(", "bpf_get_current_cgroup_id("} {
		if strings.Contains(body, banned) {
			t.Errorf("tego_cg_sock_create uses %q: it decides the whole protocol, records every refusal (record: off "+
				"included), and names the attachment's cgroup, never the caller's", banned)
		}
	}
	// One allowlist: the plane's socket_create and this program call the header's function, which no other source
	// defines again.
	defs := 0
	for _, glob := range []string{"*.bpf.c", "*.h", filepath.Join("include", "*.h")} {
		paths, err := filepath.Glob(filepath.Join(sourceDir, glob))
		if err != nil {
			t.Fatal(err)
		}
		for _, p := range paths {
			if filepath.Base(p) == "vmlinux.h" {
				continue
			}
			n := len(regexp.MustCompile(`static __always_inline int tego_socket_allowed\(`).FindAllStringIndex(read(t, p), -1))
			if n > 0 && p != filepath.Join(sourceDir, "include", "socket_allow.h") {
				t.Errorf("%s defines tego_socket_allowed again; include/socket_allow.h is the one allowlist", p)
			}
			defs += n
		}
	}
	if defs != 1 {
		t.Errorf("tego_socket_allowed is defined %d times, want once (include/socket_allow.h)", defs)
	}
	events := read(t, filepath.Join(sourceDir, "include", "events.h"))
	for _, want := range []string{"TEGO_EV_SOCK_CREATE = 28,", "#define TEGO_OWNER_NET_ICMP 0x1", "struct tego_ev_sock {"} {
		if !strings.Contains(events, want) {
			t.Errorf("events.h lacks %q", want)
		}
	}
}

// TestSetsockoptRefusesEveryTCPULPOnTheAttachmentsRun is ADR 0018 (7) (review RSOCK-S1) in the source.
// cgroup/setsockopt takes its run from the attachment's owner storage and refuses while it is unconfigured (R1), as
// cgroup/sock_create does; it decides SOL_TCP's TCP_ULP alone, whatever the name, since a ULP is how a TCP socket was
// turned into another family (the smc module's "smc"); every other option passes untouched but for the documented
// PAGE_SIZE rule, an option longer than the kernel shows a program handed back with optlen 0 so the kernel uses the
// caller's own value as it would with no program; and a refusal records its own line on the run's ring, the name read
// from the kernel's copy of the value (optval..optval_end, checked against its end, the 15 bytes the kernel reads at
// most, with optlen for the reader to cut it at), under record: off too, before it returns the kernel's EPERM.
func TestSetsockoptRefusesEveryTCPULPOnTheAttachmentsRun(t *testing.T) {
	t.Parallel()
	path := filepath.Join(sourceDir, "cgroup_net.bpf.c")
	var body string
	for _, p := range programs(t, path) {
		if p.section == "cgroup/setsockopt" {
			body = p.body
		}
	}
	if body == "" {
		t.Fatal("cgroup_net.bpf.c has no cgroup/setsockopt program")
	}
	order := []string{
		"bpf_get_local_storage(&tego_net_owners, 0)",
		"if (owner->cgroup_id == 0)\n        return TEGO_SOCK_REFUSE;",
		"if (ctx->level != TEGO_SOL_TCP || ctx->optname != TEGO_TCP_ULP) {",
		"if (ctx->optlen > TEGO_SOCKOPT_SHOWN)\n            ctx->optlen = 0;\n        return TEGO_SOCK_OK;\n    }",
		"r.run_idx = owner->run_idx;",
		"r.gen = owner->gen;",
		"tego_ring_of(&tego_events, run)",
		"bpf_ringbuf_reserve(ring, sizeof(*e), 0)",
		"tego_hdr_fill(&e->hdr, TEGO_EV_SOCKOPT, sizeof(*e), run, owner->cgroup_id);",
		"e->hdr.verdict = TEGO_V_REFUSED;",
		"e->hdr.reason = TEGO_R_NET_NOT_ALLOWED;",
		"bpf_ringbuf_submit(e, 0);\n    return TEGO_SOCK_REFUSE;\n}",
	}
	at := 0
	for _, want := range order {
		i := strings.Index(body[at:], want)
		if i < 0 {
			t.Fatalf("tego_cg_setsockopt lacks, or has out of order, %q", want)
		}
		at += i + len(want)
	}
	for _, want := range []string{"e->optlen = ctx->optlen;",
		"if (optval + TEGO_ULP_NAME_MAX <= end)\n        __builtin_memcpy(e->name, optval, TEGO_ULP_NAME_MAX);"} {
		if !strings.Contains(body, want) {
			t.Errorf("tego_cg_setsockopt's name copy lacks %q: it reads the kernel's copy, checked against its end, "+
				"no further than the kernel's own bound, and records optlen for the reader to cut the name at", want)
		}
	}
	for _, banned := range []string{"tego_recording(", "bpf_get_current_cgroup_id(", "bpf_probe_read", "ctx->optval["} {
		if strings.Contains(body, banned) {
			t.Errorf("tego_cg_setsockopt uses %q: it records every refusal (record: off included), names the attachment's "+
				"cgroup, never the caller's, and reads the value only through the bounds-checked copy", banned)
		}
	}
	src := read(t, path)
	for _, def := range []string{"#define TEGO_SOL_TCP 6", "#define TEGO_TCP_ULP 31", "#define TEGO_SOCKOPT_SHOWN 4096"} {
		if !strings.Contains(src, def) {
			t.Errorf("cgroup_net.bpf.c lacks %q", def)
		}
	}
	events := read(t, filepath.Join(sourceDir, "include", "events.h"))
	for _, want := range []string{"TEGO_EV_SOCKOPT = 29,", "#define TEGO_ULP_NAME_MAX 15", "struct tego_ev_sockopt {"} {
		if !strings.Contains(events, want) {
			t.Errorf("events.h lacks %q", want)
		}
	}
}
