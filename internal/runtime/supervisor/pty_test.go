// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"fmt"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/liveblock"
	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/pkg/policy/gate"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

type ptyPolicyKernel struct {
	*fakeKernel
	delivered bool
}

func (k *ptyPolicyKernel) DeliverPty(_ uint64, _ *sys.FD, _ int) error {
	k.delivered = true
	return nil
}

func TestPtyDeliveryPolicy(t *testing.T) {
	master, err := unix.Open("/dev/ptmx", unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(master) //nolint:errcheck // test terminal
	if err := unix.IoctlSetPointerInt(master, unix.TIOCSPTLCK, 0); err != nil {
		t.Fatal(err)
	}
	path := "/dev/pts/" + ptyIndex(master)
	for _, tier := range []backend.Tier{backend.TierLandlock, backend.TierCgroup, backend.TierBPFLSM} {
		for _, tc := range []struct {
			name                     string
			flags                    int
			kind                     agent.FSKind
			live                     string
			score                    int
			askRead, askWrite, allow bool
			declaredAlias            bool
			rule                     string
		}{
			{name: "allow", flags: unix.O_RDWR, allow: true, rule: "fs.write[/dev/pts/]"},
			{name: "declared-alias", flags: unix.O_RDONLY, kind: agent.FSDenyRead, declaredAlias: true, rule: "fs.deny_read[/denied-alias]"},
			{name: "deny-read", flags: unix.O_RDONLY, kind: agent.FSDenyRead, rule: "fs.deny_read[/dev/pts/]"},
			{name: "deny-read-rdwr", flags: unix.O_RDWR, kind: agent.FSDenyRead, rule: "fs.deny_read[/dev/pts/]"},
			{name: "deny-write", flags: unix.O_WRONLY, kind: agent.FSDenyWrite, rule: "fs.deny_write[/dev/pts/]"},
			{name: "live-read", flags: unix.O_RDONLY, live: "read", rule: "live.block[read:/dev/pts]"},
			{name: "live-read-rdwr", flags: unix.O_RDWR, live: "read", rule: "live.block[read:/dev/pts]"},
			{name: "live-write", flags: unix.O_RDWR, live: "write", rule: "live.block[write:/dev/pts]"},
			{name: "gate-refuse", flags: unix.O_RDWR, score: 90},
			{name: "gate-ask", flags: unix.O_RDWR, score: 60},
			{name: "ask-read-device", flags: unix.O_RDONLY, askRead: true, kind: agent.FSDenyRead, rule: "fs.ask_read[/dev/pts/]"},
			{name: "ask-write-device", flags: unix.O_WRONLY, askWrite: true, rule: "fs.ask[/dev/pts/]"},
		} {
			t.Run(fmt.Sprintf("%s/%s", tier, tc.name), func(t *testing.T) {
				flags := tc.flags | unix.O_NOCTTY
				slave, err := peerFromMaster(master, flags, -1)
				if err != nil {
					t.Fatal(err)
				}
				defer slave.Close() //nolint:errcheck // test peer
				fs := []agent.FSRule{{Path: "/dev/pts", Raw: "/dev/pts/", Kind: agent.FSWrite}}
				pol := testPolicy(nil, fs, nil)
				pol.Rules.Tier, pol.Rules.Record = tier, agent.RecordFull
				if tc.askWrite {
					pol.Rules.FS = nil
					pol.Rules.FSAsk = []agent.FSRule{{Path: "/dev/pts", Raw: "/dev/pts/", Kind: agent.FSAsk}}
				}
				if tc.kind == agent.FSDenyRead {
					pol.Rules.FS = append(pol.Rules.FS, agent.FSRule{Path: path, Raw: path, Kind: tc.kind, AskRead: tc.askRead, Unenforced: true})
				}
				if tc.declaredAlias {
					pol.Rules.FS = []agent.FSRule{
						{Path: path, Resolved: "/elsewhere", Raw: path, Kind: agent.FSWrite},
						{Path: "/denied-alias", Resolved: path, Raw: "/denied-alias", Kind: agent.FSDenyRead, Unenforced: true},
					}
				}
				if tc.askRead {
					pol.Rules.FS = []agent.FSRule{{Path: "/dev/pts", Raw: "/dev/pts/", Kind: agent.FSDenyRead, AskRead: true}}
				}
				if tc.kind == agent.FSDenyWrite {
					pol.Rules.DenyWrite = []agent.FSRule{{Path: "/dev/pts", Raw: "/dev/pts/", Kind: tc.kind}}
				}
				if tc.score != 0 {
					pol.Rules.Gate = testGate(t, gate.ReadMatches, "/dev/pts/*", tc.score)
				}
				var blocks *liveblock.Set
				if tc.live != "" {
					blocks = liveSet(t, tc.live, "/dev/pts")
				}
				f := newFake()
				l, sink := newTestLoopOpts(t, f, pol, Options{LiveBlocks: func() *liveblock.Set { return blocks }})
				k := &ptyPolicyKernel{fakeKernel: f}
				l.k = k
				t.Cleanup(l.closeAskScopes)
				n := notifFor(nrFor(t, "ioctl"), 42, 5, unix.TIOCGPTPEER, uint64(flags))
				// An allowed spelling must not hide a refusal of the verified slave.
				l.deliverPty(n, slave, flags, path)
				if k.delivered != tc.allow {
					t.Fatalf("delivered=%v, want %v", k.delivered, tc.allow)
				}
				ev := sink.one(t)
				wantRule := tc.rule
				if tc.kind == agent.FSDenyRead && !tc.askRead {
					wantRule = strings.ReplaceAll(wantRule, "/dev/pts/", path)
				}
				if wantRule != "" && ev.Rule != wantRule {
					t.Errorf("rule %q, want %q", ev.Rule, wantRule)
				}
				if !tc.allow && ev.Verdict != record.VerdictRefused {
					t.Fatalf("%s: %s", ev.Verdict, ev.Payload)
				}
				if tc.score != 0 && ev.Authority != record.AuthorityGate {
					t.Errorf("authority=%s", ev.Authority)
				}
				if !tc.allow {
					resp, _ := f.lastResp()
					if resp.Flags != 0 || resp.Error != -int32(unix.EACCES) {
						t.Fatalf("response %+v", resp)
					}
				}
			})
		}
	}
}
