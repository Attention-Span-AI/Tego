// SPDX-License-Identifier: Apache-2.0

//go:build integration

package runtime

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/liveblock"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

const ptyPolicyProbe = `import os, sys, errno, fcntl, json, time
path=sys.argv[1]
open('out/ready','w').close()
while not os.path.exists('out/go'): time.sleep(.01)
results={}
for name,flag in [('read',os.O_RDONLY),('write',os.O_WRONLY),('rdwr',os.O_RDWR)]:
    for form in ['path','ioctl','peer-default']:
        try:
            fd=os.open(path,flag|os.O_NOCTTY) if form=='path' else fcntl.ioctl(0,0x5441,flag if form=='peer-default' else flag|os.O_NOCTTY)
            os.close(fd); result='ok'
        except OSError as e: result=errno.errorcode.get(e.errno,str(e.errno))
        results[form+'-'+name]=result
with open('out/result','w') as f: json.dump(results,f)
`

func TestIntegrationBuiltinPTYPolicy(t *testing.T) {
	builtinPTYPolicy(t, tegoBinary(t), "landlock")
}

// Both relay APIs must apply policy even to a verified master held by the run.
// Passing a master as stdin fixes the slave identity before compilation; the
// existing builtin integration separately allocates new masters inside the run.
// Use direct reads: this tests the PTY relay's policy checks, which apply in
// either read mode. Auto would select held reads for deny_read under the tty
// write grant; devpts cannot supply ADR 0069's retained-identity snapshot.
func builtinPTYPolicy(t *testing.T, bin, tier string) {
	t.Helper()
	for _, mode := range []string{"allow", "deny_read", "deny_write", "live-read", "live-write"} {
		t.Run(mode, func(t *testing.T) {
			fd, err := unix.Open("/dev/ptmx", unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
			if err != nil {
				t.Fatal(err)
			}
			master := os.NewFile(uintptr(fd), "test-master")
			defer master.Close() //nolint:errcheck // terminal fixture
			if err := unix.IoctlSetPointerInt(fd, unix.TIOCSPTLCK, 0); err != nil {
				t.Fatal(err)
			}
			idx, err := unix.IoctlGetInt(fd, unix.TIOCGPTN)
			if err != nil {
				t.Fatal(err)
			}
			slave := fmt.Sprintf("/dev/pts/%d", idx)
			agentOwns(t, slave)
			py, err := exec.LookPath("python3")
			if err != nil {
				t.Fatal(err)
			}
			contract := fmt.Sprintf("version: 0\nname: iptypolicy\ncommand: [%q]\ntier: landlock\nrecord: full\nfs:\n  reads: direct\n  write: [\"./out/\", \"/dev/pts/\"]\n  deny_read: []\nlimits:\n  pids: 64\n", py)
			if mode == "deny_read" {
				contract = strings.Replace(contract, "deny_read: []", fmt.Sprintf("deny_read: [%q]", slave), 1)
			}
			if mode == "deny_write" {
				contract = strings.Replace(contract, "limits:\n", fmt.Sprintf("  deny_write: [%q]\nlimits:\n", slave), 1)
			}
			s := &askReadScene{bin: bin, f: newFixture(t, contract)}
			s.env = isolatedEnv(t, s.f)
			if tier != "landlock" {
				contract = strings.Replace(contract, "tier: landlock", "tier: "+tier, 1)
			}
			contractPath := filepath.Join(s.f.dir, "agent.yaml")
			if err := os.WriteFile(contractPath, []byte(contract), 0o644); err != nil {
				t.Fatal(err)
			}
			script := filepath.Join(s.f.dir, "probe.py")
			if err := os.WriteFile(script, []byte(ptyPolicyProbe), 0o644); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, bin, "run", contractPath, "--", py, script, slave)
			cmd.Dir, cmd.Env, cmd.Stdin = s.f.dir, s.env, master
			var output bytes.Buffer
			cmd.Stdout, cmd.Stderr = &output, &output
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			ran := make(chan error, 1)
			go func() { ran <- cmd.Wait() }()
			t.Cleanup(func() { cancel(); _ = cmd.Process.Kill() })
			dir := liveRunDir(t, s.f.root, ran, time.Now().Add(20*time.Second), 10*time.Millisecond)
			waitForFile(t, filepath.Join(s.f.out, "ready"), 20*time.Second)
			if strings.HasPrefix(mode, "live-") {
				kind := liveblock.Kind(strings.TrimPrefix(mode, "live-"))
				updateOverlay(t, dir, filepath.Base(dir), func(o *liveblock.Overlay) error {
					_, _, err := o.Add(kind, slave, "t", time.Now())
					return err
				})
				deadline := time.Now().Add(10 * time.Second)
				for {
					raw, _ := os.ReadFile(filepath.Join(dir, "events.jsonl"))
					if strings.Contains(string(raw), "live-block-added") {
						break
					}
					if time.Now().After(deadline) {
						t.Fatalf("block never applied: %s", raw)
					}
					time.Sleep(10 * time.Millisecond)
				}
			}
			if err := os.WriteFile(filepath.Join(s.f.out, "go"), nil, 0o644); err != nil {
				t.Fatal(err)
			}
			if err := <-ran; err != nil {
				t.Fatalf("run: %v\n%s", err, output.String())
			}
			raw, err := os.ReadFile(filepath.Join(s.f.out, "result"))
			if err != nil {
				t.Fatalf("%v\n%s", err, output.String())
			}
			var results map[string]string
			if err := json.Unmarshal(raw, &results); err != nil {
				t.Fatal(err)
			}
			for _, form := range []string{"path", "ioctl", "peer-default"} {
				for _, access := range []string{"read", "write", "rdwr"} {
					want := "ok"
					if (mode == "deny_read" || mode == "live-read") && access != "write" || (mode == "deny_write" || mode == "live-write") && access != "read" {
						want = "EACCES"
					}
					// The cgroup listener cannot distinguish read and write opens.
					if tier == "cgroup" && mode == "deny_read" {
						want = "EACCES"
					}
					if got := results[form+"-"+access]; got != want {
						t.Errorf("%s/%s=%s, want %s", form, access, got, want)
					}
				}
			}
			count := 0
			for _, ev := range events(t, dir) {
				if ev.Kind == record.KindFS && ev.Verdict == record.VerdictRefused {
					var p record.FSPayload
					if ev.DecodePayload(&p) == nil && p.Path == slave {
						prefix := "fs." + mode + "["
						if strings.HasPrefix(mode, "live-") {
							prefix = "live.block["
						}
						if !strings.HasPrefix(ev.Rule, prefix) {
							t.Errorf("refusal %s: want %s", ev.Rule, prefix)
						}
						count++
					}
				}
			}
			if mode != "allow" && count < 6 {
				t.Errorf("only %d policy refusal lines, want all relay forms and both denied access modes", count)
			}
		})
	}
}
