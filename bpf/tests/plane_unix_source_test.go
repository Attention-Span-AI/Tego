// SPDX-License-Identifier: Apache-2.0

package bpftests

import (
	"path/filepath"
	"strings"
	"testing"

	ebpfbindings "github.com/attention-span-ai/tego/internal/bpf"
)

// TestPlaneUnixHooksDecideAsConnectUnixDoes is enforce-plane R14's step D in the source (TIER3-PLAN T15): below 6.7,
// where cgroup/connect_unix and sendmsg_unix do not exist, the plane's socket_connect and socket_sendmsg decide a
// run's unix names by the same rule and the same rows. Each finds its run by the socket's cgroup (the relay
// connects the agent's socket from the launcher's cgroup), decides an AF_UNIX connect or an addressed datagram
// only, reads the kernel's copy of the address through the build's reader, and shares tego_unix_canon_byte and
// tego_unix_relay_name with cgroup_net.bpf.c; a slot with no unix policy of the run's gen refuses, counted.
func TestPlaneUnixHooksDecideAsConnectUnixDoes(t *testing.T) {
	t.Parallel()
	path, _ := planeSource(t)
	bodies := planeBodies(t)
	unixHooks := map[string]bool{}
	for _, h := range ebpfbindings.PlaneHooks {
		if h.Unix {
			unixHooks[h.Name] = true
		}
		if h.Unix != (h.Name == "socket_connect" || h.Name == "socket_sendmsg") {
			t.Errorf("%s: PlaneHook.Unix is %v; the step D hooks, and only they, are loaded only below 6.7", h.Name, h.Unix)
		}
	}
	if !unixHooks["socket_connect"] || !unixHooks["socket_sendmsg"] || len(unixHooks) != 2 {
		t.Fatalf("the plane's unix hooks are %v, want socket_connect and socket_sendmsg", unixHooks)
	}

	run := functionBody(t, path, "tego_unix_sock_run")
	for _, want := range []string{"sk_cgrp_data.cgroup", "->kn->id", "TEGO_AF_UNIX", "tego_run_lookup(run_set,"} {
		if !strings.Contains(run, want) {
			t.Errorf("tego_unix_sock_run lacks %q: it keys the run by the unix socket's own cgroup", want)
		}
	}
	if strings.Contains(run, "bpf_get_current_cgroup_id") {
		t.Error("tego_unix_sock_run keys the run by the caller, which is the supervisor for every relayed connect")
	}

	connect, sendmsg := bodies["socket_connect"], bodies["socket_sendmsg"]
	if !strings.Contains(connect, "address->sa_family != TEGO_AF_UNIX") {
		t.Error("socket_connect decides an address that is not AF_UNIX (a datagram socket's AF_UNSPEC disconnect)")
	}
	for _, want := range []string{"sock->type != TEGO_SOCK_DGRAM", "msg->msg_namelen", "msg->msg_name"} {
		if !strings.Contains(sendmsg, want) {
			t.Errorf("socket_sendmsg lacks %q: only an addressed datagram is decided, as unix_dgram_sendmsg runs "+
				"sendmsg_unix", want)
		}
	}
	for name, body := range map[string]string{"socket_connect": connect, "socket_sendmsg": sendmsg} {
		op := "TEGO_EV_CONNECT"
		if name == "socket_sendmsg" {
			op = "TEGO_EV_SENDMSG"
		}
		if !strings.Contains(body, "tego_plane_unix_reason(") || !strings.Contains(body, op) {
			t.Errorf("%s does not decide through tego_plane_unix_reason as %s", name, op)
		}
		flag := strings.Index(body, "if (!(hdr->flags & TEGO_SLOT_UNIX_DECIDES))\n        return 0;")
		policy := strings.Index(body, "tego_plane_unix_of(run)")
		decision := strings.Index(body, "tego_plane_unix_reason(")
		if flag < 0 || policy < flag || decision < policy {
			t.Errorf("%s does not read the header's unix flag, then the slot's unix policy, before its decision", name)
		}
		if !strings.Contains(body, "TEGO_PLANE_COUNT(run->run_idx, norows)") {
			t.Errorf("%s does not count a slot with no unix policy of the run's gen, which it refuses", name)
		}
	}

	reason := functionBody(t, path, "tego_plane_unix_reason")
	for _, want := range []string{
		"tego_plane_unix_key(", "tego_plane_unix_canonical(addr, alen, pol)", "tego_unix_relay_name(k->name)",
		"bpf_get_current_cgroup_id() == pol->relay_cgroup_id", "pol->relay_cgroup_id != 0",
		"bpf_map_lookup_elem(&tego_unix_names, k)", "k->name[0] != '/'", "TEGO_R_NET_NOT_ALLOWED",
	} {
		if !strings.Contains(reason, want) {
			t.Errorf("tego_plane_unix_reason lacks %q: it is cgroup_net.bpf.c's tego_unix_decide", want)
		}
	}
	step := functionBody(t, path, "tego_unix_canon_step")
	for _, want := range []string{"tego_unix_canon_byte(&c->st, ch, j)", "TEGO_RD_WORD(c->addr + TEGO_SUN_PATH_OFF + j)",
		"j < c->n"} {
		if !strings.Contains(step, want) {
			t.Errorf("tego_unix_canon_step lacks %q: it runs common.h's rule over the kernel's copy, read in place", want)
		}
	}
	canon := functionBody(t, path, "tego_plane_unix_canonical")
	if !strings.Contains(canon, "c.st = pol->zero;") || !strings.Contains(canon, "c.ok = pol->zero;") {
		t.Error("tego_plane_unix_canonical starts its state from a constant, which a verifier before 6.8 takes for " +
			"the callback's every call (AL2023 6.1 refused every absolute name)")
	}
	key := functionBody(t, path, "tego_plane_unix_key")
	for _, want := range []string{"bpf_core_cast((void *)addr, struct sockaddr_un)", "bpf_probe_read_kernel(",
		"TEGO_SUN_PATH_OFF + TEGO_UNIX_NAME_MAX", "k->prefixlen = TEGO_UNIX_MAX_BITS"} {
		if !strings.Contains(key, want) {
			t.Errorf("tego_plane_unix_key lacks %q: it reads the kernel's copy through the build's reader", want)
		}
	}

	for _, src := range []string{"cgroup_net.bpf.c", "decide.bpf.c"} {
		text := read(t, filepath.Join(sourceDir, src))
		for _, fn := range []string{"int tego_unix_canonical(", "int tego_unix_canon_byte(", "int tego_unix_relay_name("} {
			if strings.Contains(text, fn) {
				t.Errorf("%s defines %s itself; include/common.h's one copy decides both tiers' names", src, fn)
			}
		}
	}
	if !strings.Contains(functionBody(t, filepath.Join(sourceDir, "cgroup_net.bpf.c"), "tego_unix_relayed"),
		"tego_unix_relay_name(name)") {
		t.Error("cgroup_net.bpf.c's tego_unix_relayed does not use common.h's tego_unix_relay_name")
	}
}

// ADR 0113's datagram floor must read the actual bound peer, never msg_name.
func TestBuiltinUnixNativePeerFloor(t *testing.T) {
	body := planeBodies(t)["unix_may_send"]
	for _, required := range []string{"tego_current_run(", "struct unix_sock", "peer->path.dentry", "i_nlink", "tego_builtin_name_decision(", "TEGO_ROW_BUILTIN_IPC", "hit.pad2 & 1", "tego_builtin_control_name(", "tego_builtin_peer_sample(", "return -EACCES;"} {
		if !strings.Contains(body, required) {
			t.Errorf("native peer floor lacks %q", required)
		}
	}
	if strings.Contains(body, "msg_name") || strings.Contains(body, "sockaddr") {
		t.Fatal("native peer floor trusts a supplied address")
	}
	for _, hook := range ebpfbindings.PlaneHooks {
		if hook.Name == "unix_may_send" && (hook.Unix || !hook.Decides) {
			t.Fatal("native peer floor must load on every kernel with the plane")
		}
	}
}

func TestBuiltinNameTagsNeverGrantAListener(t *testing.T) {
	body := functionBody(t, filepath.Join("..", "decide_socket.h"), "tego_listen_key_reason")
	if !strings.Contains(body, "row->rule_idx & 0xe000") {
		t.Fatal("private immutable/peer tags must not become listener grants")
	}
}
