// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"slices"
	"testing"
)

func TestBuiltinUnixDecisionTable(t *testing.T) {
	b := &BuiltinRefusals{Runtime: []string{"/run/user/1000"}, IPCDirs: []string{"/tmp/tmux-1000", "/run/screen/S-alice", "/tmp/emacs1000"}, TegoDirs: []string{"/home/alice/.tego", "/run/user/1000/tego"}, Ledger: "/ledger", Nodes: []string{"/run/dbus/system_bus_socket", "/bus-canonical", "/run/docker.sock"}, OwnRuntime: "/run/user/1000/tego/own"}
	cases := []struct {
		path     string
		explicit bool
		rule     string
	}{
		{"/run/user/1000/bus", true, BuiltinHostIPC},
		{"/run/user/1000/systemd/private", true, BuiltinHostIPC},
		{"/run/user/1000/gnupg/S.gpg-agent", true, BuiltinHostIPC},
		{"/run/user/1000/gnupg/S.gpg-agent.extra", true, BuiltinHostIPC},
		{"/run/user/1000/gnupg/S.gpg-agent.browser", true, BuiltinHostIPC},
		{"/run/user/1000/gnupg/S.dirmngr", true, BuiltinHostIPC},
		{"/run/user/1000/gnupg/d.deadbeef/S.gpg-agent", true, BuiltinHostIPC},
		{"/run/user/1000/gnupg/S.gpg-agent.ssh", false, ""},
		{"/run/user/1000/gnupg/d.deadbeef/S.gpg-agent.ssh", true, ""},
		{"/run/user/1000/gnupg/d./S.gpg-agent.ssh", true, BuiltinHostIPC},
		{"/run/user/1000/gnupg/d.deadbeef/deeper/S.gpg-agent.ssh", true, BuiltinHostIPC},
		{"/run/user/1000/openssh_agent", false, ""},
		{"/run/user/1000/ssh-agent.socket", false, ""},
		{"/run/user/1000/keyring/ssh", false, ""},
		{"/run/user/1000/gcr/ssh", false, ""},
		{"/tmp/ssh-abc/agent", false, ""},
		{"/run/user/1000/tego/other/operator.sock", true, BuiltinTegoSurface},
		{"/run/user/1000/tego/own/agent.sock", true, ""},
		{"/home/alice/.tego/api.sock", true, BuiltinTegoSurface},
		{"/ledger/other/ask.sock", true, BuiltinTegoSurface},
		{"/ledger/other/operator.sock", true, BuiltinTegoSurface},
		{"/run/dbus/system_bus_socket", true, BuiltinHostIPC},
		{"/bus-canonical", true, BuiltinHostIPC},
		{"/tmp/.X11-unix/X99", true, BuiltinHostIPC},
		{"/tmp/tmux-1000/default", true, BuiltinHostIPC},
		{"/tmp/tmux-10000/default", true, ""},
		{"/run/screen/S-alice/server", true, BuiltinHostIPC},
		{"/tmp/emacs1000/server", true, BuiltinHostIPC},
		{"/run/docker.sock", false, BuiltinHostIPC},
		{"/run/docker.sock", true, ""},
		{"/run/user/1000/docker.sock", false, BuiltinHostIPC},
		{"/run/user/1000/docker.sock", true, ""},
	}
	for _, tt := range cases {
		t.Run(tt.path+map[bool]string{true: "/explicit", false: "/implicit"}[tt.explicit], func(t *testing.T) {
			if got := b.UnixRule(tt.path, tt.explicit); got != tt.rule {
				t.Fatalf("rule=%q want %q", got, tt.rule)
			}
		})
	}
}

func TestBuiltinOtherTTYDecisionTable(t *testing.T) {
	for _, p := range []string{"/dev/pts/0", "/dev/pts/999", "/dev/tty0", "/dev/tty63"} {
		if !OtherTTY(p) {
			t.Errorf("missed %s", p)
		}
	}
	for _, p := range []string{"/dev/pts/ptmx", "/dev/ptmx", "/dev/tty", "/dev/ttyS0", "/dev/ttyUSB0", "/dev/ttyACM0", "/dev/ttyAMA0", "/dev/pts/1/x", "/dev/pts/+1"} {
		if OtherTTY(p) {
			t.Errorf("refused %s", p)
		}
	}
}

func TestBuiltinDatagramResidualOnlyWithoutNativePlane(t *testing.T) {
	rt := &RuleTable{Contract: &Contract{HostSockets: true}, Builtins: &BuiltinRefusals{}}
	for _, tt := range []struct {
		tier  backend.Tier
		plane string
		want  bool
	}{
		{backend.TierLandlock, "", true}, {backend.TierCgroup, "fanotify", true}, {backend.TierCgroup, "lsm", false},
		{backend.TierCgroup, "fmod_ret", false}, {backend.TierBPFLSM, "lsm", false}, {backend.TierObserve, "", false},
	} {
		if got := slices.Contains(rt.BestEffortCellsAt(tt.tier, tt.plane), BestEffortBuiltinIPC); got != tt.want {
			t.Errorf("%s/%s residual %v want %v", tt.tier, tt.plane, got, tt.want)
		}
	}
}

func TestBuiltinNetRefusalHasNoFilesystemMutationResidual(t *testing.T) {
	rt := &RuleTable{Contract: &Contract{HostSockets: true}, Builtins: &BuiltinRefusals{Runtime: []string{"/runtime"}},
		DenyWrite: []FSRule{{Path: "/runtime", Kind: FSDenyWrite, BuiltIn: true, BuiltinRule: BuiltinHostIPC, Unenforced: true}}}
	got := EvalResult{Verdict: VerdictRefused, Rule: BuiltinHostIPC}
	for _, kind := range []ActionKind{ActionNetConnect, ActionNetSend, ActionFSRead} {
		if cells := rt.BestEffortCellsFor(Action{Kind: kind, Path: "/runtime/bus", Proto: ProtoUnix}, got, backend.TierLandlock); slices.Contains(cells, BestEffortDenyWrite) {
			t.Errorf("%s got mutation cell %v", kind, cells)
		}
	}
}
