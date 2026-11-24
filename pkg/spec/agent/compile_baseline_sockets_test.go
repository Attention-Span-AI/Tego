// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestBaselineProtectedSocketMatrix(t *testing.T) {
	f := newSocketFixture(t, "home/.tego/runs/ask.sock")
	m := baselineMachine(t, f, "  env: {deny: [TOKEN]}\n")
	runtime := filepath.Join(f.root, "r")
	protected := []string{"/run/docker.sock", "/var/run/docker.sock", "/run/podman/podman.sock", "/var/run/podman/podman.sock", "/run/containerd/containerd.sock", "/var/run/containerd/containerd.sock", "/run/dbus/system_bus_socket", "/var/run/dbus/system_bus_socket", "/run/user/1234/bus", "/run/user/1234/systemd/private", "/run/user/1234/docker.sock", "/run/user/1234/podman/podman.sock", "/tmp/tmux-1234/server.sock", "/run/screen/S-1234/worker", "/tmp/emacs1234/server", "/tmp/nvim.1234/server", "/tmp/.X11-unix/X0", runtime + "/bus", runtime + "/systemd/private", runtime + "/docker.sock", runtime + "/tego/operator.sock", filepath.Join(f.home, ".screen/server"), filepath.Join(f.home, ".tego/operator.sock")}
	for _, key := range []string{"allow", "ask"} {
		for _, path := range protected {
			c := f.load("version: 0\nname: socket-matrix\ncommand: [static-tool]\nask: {}\nnet: {" + key + ": [" + strconv.Quote("unix:"+path) + "]}\n")
			rt, ds, err := Compile(c, m, f.opts(WithOwnerUID(1234), withHostSocketProbe(f.root, 1234), WithRuntimeDir(runtime))...)
			if err == nil || rt != nil || !strings.Contains(render(ds), CodeBaselineConflict) {
				t.Fatalf("%s %s: %v %s", key, path, err, render(ds))
			}
		}
	}
	for _, path := range []string{"/run/ordinary.sock", "/run/user/1234/openssh_agent", "/run/user/1234/gnupg/S.gpg-agent.ssh"} {
		c := f.load("version: 0\nname: socket-ordinary\ncommand: [static-tool]\nnet: {allow: [" + strconv.Quote("unix:"+path) + "]}\n")
		if _, ds, err := Compile(c, m, f.opts(WithOwnerUID(1234), withHostSocketProbe(f.root, 1234), WithRuntimeDir(runtime))...); err != nil {
			t.Fatalf("ordinary/SSH endpoint %s refused: %v %s", path, err, render(ds))
		}
	}
	t.Logf("%d protected names x allow/ask refused; 3 ordinary/fixed SSH names accepted", len(protected))
}

func TestBaselineSocketAliasesKeepSourceDiagnostics(t *testing.T) {
	f := newSocketFixture(t, "r/bus")
	runtime := filepath.Join(f.root, "r")
	if err := os.Mkdir(runtime, 0o700); err != nil {
		t.Fatal(err)
	}
	bus := filepath.Join(runtime, "bus")
	f.file(bus, "socket identity fixture", 0o600)
	link, hard := filepath.Join(f.root, "link.sock"), filepath.Join(f.root, "hard.sock")
	if err := os.Symlink(bus, link); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(bus, hard); err != nil {
		t.Fatal(err)
	}
	m := baselineMachine(t, f, "  env: {deny: [TOKEN]}\n")
	for _, path := range []string{link, hard} {
		c := f.load("version: 0\nname: socket-alias\ncommand: [static-tool]\nnet: {allow: [" + strconv.Quote("unix:"+path) + "]}\n")
		_, ds, err := Compile(c, m, f.opts(WithRuntimeDir(runtime))...)
		if err == nil {
			t.Fatalf("protected socket alias %s allowed", path)
		}
		found := false
		for _, d := range ds {
			if d.Code == CodeBaselineConflict && d.Baseline != nil && d.Baseline.GrantKey == "net.allow.0" && len(d.Baseline.Entry.Sources) == 1 {
				found = true
			}
		}
		if !found {
			t.Fatalf("alias lacks full conflict sources: %s", render(ds))
		}
	}
}
