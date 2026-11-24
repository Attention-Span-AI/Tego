// SPDX-License-Identifier: Apache-2.0

package scan

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/attention-span-ai/tego/internal/scan/catalog"
	"golang.org/x/sys/unix"
)

// These fixtures prove ordering, not kernel credentials; the real drop is tested
// separately in disposable guests.
func recipientFixture(t *testing.T) (Options, func(Options) Outcome) {
	t.Helper()
	o := commandOptions(t)
	original := o.Caller
	o.Advanced = true
	o.Caller.UID, o.Caller.EUID, o.Caller.InitialRoot, o.Caller.Recipient = 0, 0, true, original.UID
	for name, text := range map[string]string{
		".codex/config.toml": "[mcp_servers.after_drop]\ncommand = \"codex\"\n",
		"package.json":       `{ "dependencies": { "@openai/codex": "1" } }`,
		".config/systemd/user/root_phase.service": "[Service]\nExecStart=/usr/bin/codex\n",
	} {
		path := filepath.Join(o.Directory, name)
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(text), 0600); err != nil {
			t.Fatal(err)
		}
	}
	identify := func(ctx context.Context, fs procAccess, root, passwd, boot string, _ Caller, _ bool) (callerIdentity, string) {
		v, r := identifyCaller(ctx, fs, root, passwd, boot, original)
		v.Accounts = []localAccount{{UID: original.UID, Home: o.Directory, Name: "me"}}
		return v, r
	}
	return o, func(requested Options) Outcome {
		return collectWithIdentity(t.Context(), requested, func(ctx context.Context, fs procAccess, root string, uid uint32, rows []catalog.Row) processSnapshot {
			return readProcesses(ctx, fs, root, uid, rows)
		}, identify)
	}
}

func recipientNoOpen(t *testing.T, home string) func() {
	t.Helper()
	fd, err := unix.InotifyInit1(unix.IN_NONBLOCK | unix.IN_CLOEXEC)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	for _, name := range []string{"package.json", ".codex/config.toml"} {
		if _, err := unix.InotifyAddWatch(fd, filepath.Join(home, name), unix.IN_OPEN|unix.IN_ACCESS); err != nil {
			t.Fatal(err)
		}
	}
	return func() {
		t.Helper()
		b := make([]byte, 4096)
		n, err := unix.Read(fd, b)
		if n > 0 {
			t.Fatal("recipient-controlled content opened while root")
		}
		if err != nil && err != unix.EAGAIN {
			t.Fatal(err)
		}
	}
}

func TestAdvancedRecipientReadsAfterDrop(t *testing.T) {
	for _, check := range []bool{false, true} {
		t.Run(map[bool]string{false: "save", true: "check"}[check], func(t *testing.T) {
			o, collect := recipientFixture(t)
			o.Check = check
			noOpen := recipientNoOpen(t, o.Directory)
			calls := 0
			o.ResolveDirectory = func() (string, error) {
				if calls != 1 {
					t.Fatal("working folder resolved before drop")
				}
				return o.Directory, nil
			}
			o.BeforeRecipient = func(uid, gid uint32) error {
				noOpen()
				calls++
				if uid != uint32(os.Getuid()) || gid != 42 {
					t.Fatalf("wrong recipient %d:%d", uid, gid)
				}
				// The root proc directory descriptor must already be closed. Sources are
				// never carried across the boundary, even as pinned read-only handles.
				targets, err := os.ReadDir("/proc/self/fd")
				if err != nil {
					t.Fatal(err)
				}
				for _, entry := range targets {
					target, _ := os.Readlink("/proc/self/fd/" + entry.Name())
					if target == o.ProcRoot {
						t.Fatal("root proc source descriptor survived to drop")
					}
				}
				return nil
			}
			got := collect(o)
			if calls != 1 {
				t.Fatalf("recipient credential boundary called %d times", calls)
			}
			if got.Snapshot.Status == "failed" || got.Snapshot.Counts.MCP != 1 || got.Snapshot.Counts.Project != 1 || got.Snapshot.Counts.Units != 1 {
				t.Fatalf("phase data lost: %+v status=%s", got.Snapshot.Counts, got.Snapshot.Status)
			}
		})
	}
}

func TestAdvancedDropFailureStopsRecipientReads(t *testing.T) {
	for _, missing := range []bool{false, true} {
		t.Run(map[bool]string{false: "failed", true: "missing"}[missing], func(t *testing.T) {
			o, collect := recipientFixture(t)
			noOpen := recipientNoOpen(t, o.Directory)
			if !missing {
				o.BeforeRecipient = func(uint32, uint32) error { return errors.New("drop refused") }
			}
			got := collect(o)
			noOpen()
			if got.Snapshot.Status != "failed" || got.Snapshot.Counts.MCP != 0 || got.Snapshot.Counts.Project != 0 {
				t.Fatal("failed or missing drop did not refuse recipient collection")
			}
		})
	}
}
