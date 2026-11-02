// SPDX-License-Identifier: Apache-2.0

//go:build integration

package demo

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestFeatureScenes runs every feature scene of the map (README.md, "Feature map") that needs no root, key or login,
// in the kit's isolation, and holds each to what the presenter is told to point at. The "without Tego" half of a
// scene is asserted only where it does not depend on the host (an unprivileged user namespace, sudo's cache); the
// "under Tego" half must show no ALL-CAPS success line.
func TestFeatureScenes(t *testing.T) {
	k := newKit(t)
	k.mustDemo("setup")
	for _, tc := range []struct {
		args []string
		want []string
	}{
		{[]string{"rule", "read"}, []string{"GOT IT", "read-denied", "fs.deny_read[../secrets/]", "read it (allowed)"}},
		{[]string{"rule", "write"}, []string{"PROFILE CHANGED", "write-outside-contract", "shell profile now: # my shell profile"}},
		{[]string{"rule", "command"}, []string{"SRC DELETED", "refused: src/ is still there", "exec.deny[rm -r]"}},
		{[]string{"rule", "net"}, []string{"reached it (allowed)", "net-not-allowed", "127.0.0.2"}},
		{[]string{"rule", "process"}, []string{"landlock-topology", "unshare CLONE_NEWUSER"}},
		{[]string{"always"}, []string{"ANSWERED: stand-in docker daemon", "ANSWERED: stand-in ssh-agent", "host-sockets",
			"docker.sock", "agent.sock", "NoNewPrivs: 1"}},
		{[]string{"limits"}, []string{"of 500 started", "reason=pids", "pids (137)", "reason=oom", "oom (137)", "oom_kill 1"}},
		{[]string{"deny-write"}, []string{"HOOK PLANTED", "fs.deny_write[./.git/hooks/]", "git hook: none"}},
		{[]string{"presets"}, []string{"created agent.yaml (name: demo-preset, presets: no-secrets,no-prod,repo-only-writes)",
			"pass: [SECRETS, SINK, HOMEISH, PROJECT]", "could not read the secrets file (refused)", "net-not-allowed",
			"sink: 0 request(s) arrived", "shell profile: untouched", "git hook: none", "notes.txt: still there"}},
		{[]string{"receipt"}, []string{"Receipt for run", "demo-preset", "Refused actions"}},
		{[]string{"selftest"}, []string{"Tego self-check: 4 actions, 4 refused", "read-denied", "exec-not-allowed"}},
		{[]string{"identity"}, []string{`"launcher_user":`, `"host":`, `"contract_hash":`}},
		{[]string{"doctor"}, []string{"landlock: ABI"}},
		{[]string{"features"}, []string{"| Block read |", "| Escape self-test |"}},
	} {
		name := strings.Join(tc.args, " ")
		t.Run(strings.Join(tc.args, "-"), func(t *testing.T) {
			out := k.mustDemo(tc.args...)
			mustContain(t, name, out, tc.want...)
			if i := strings.Index(out, "== Under Tego"); i >= 0 {
				for _, bad := range []string{"GOT IT", "PROFILE CHANGED", "SRC DELETED", "STARTED", "MADE ONE",
					"REACHED IT", "ANSWERED", "HOOK PLANTED", "HELD 2 GiB", "500 of 500"} {
					if strings.Contains(out[i:], "-> "+bad) {
						t.Errorf("%s: %q under Tego:\n%s", name, bad, out[i:])
					}
				}
			}
		})
	}
	if strings.Contains(k.sinkLog(), "rogue reached the sink") {
		t.Errorf("the presets scene's rogue agent reached the sink:\n%s", k.sinkLog())
	}
}

// TestAskScene answers the ask scene from a second "terminal", as the presenter does: the agent waits, demo.sh
// approve finds the ask scene's pending ask and approves it, and the held write lands.
func TestAskScene(t *testing.T) {
	k := newKit(t)
	k.mustDemo("setup")
	cmd := exec.Command("sh", "demo.sh", "ask")
	cmd.Env = k.env
	var out strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	var ans string
	for i := 0; i < 100; i++ {
		var err error
		if ans, err = k.demo("approve"); err == nil {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("demo.sh ask: %v\n%s", err, out.String())
	}
	mustContain(t, "approve", ans, "' approve '", ": approved")
	mustContain(t, "ask", out.String(), "written: someone approved it", "held/plan.txt: written (approved)", "approved by uid:")
}

// TestReasonHookScene runs the Claude Code hook scene with the stand-in Claude Code and the model stub: the model's
// next request carries the refusal, as Tego's hook wrote it. It needs go (to build the stand-in) and openssl.
func TestReasonHookScene(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("as root the launcher makes no runtime directory, so no harness is provisioned")
	}
	gobin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go is not on PATH; the scene builds the stand-in Claude Code")
	}
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl is not installed; the scene makes the model stub's certificate with it")
	}
	k := newKit(t)
	// the scene builds with go: reuse this process's caches instead of a cold build under the kit's HOME
	for _, v := range []string{"GOCACHE", "GOMODCACHE", "GOPATH"} {
		if b, err := exec.Command(gobin, "env", v).Output(); err == nil {
			k.env = append(k.env, v+"="+strings.TrimSpace(string(b)))
		}
	}
	// This process's go goes first: a host may have an older go on the kit's PATH (GitHub's runner image has
	// 1.24 in /usr/bin), and go.mod asks for 1.27.
	for i, kv := range k.env {
		if p, ok := strings.CutPrefix(kv, "PATH="); ok {
			k.env[i] = "PATH=" + filepath.Dir(gobin) + ":" + p
		}
	}
	k.mustDemo("setup")
	out := k.mustDemo("reason-hook")
	mustContain(t, "reason-hook", out, "model read: SessionStart hook additional context: This run is governed by Tego",
		"model read: - Tego refused open", "this run may not write to that path", "write-outside-contract")
}
