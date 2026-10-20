// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"context"
	"errors"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/runtime/ask"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestAskUnixHoldsTheConnectAndRelaysTheApprovedSocket: a unix connect that a net.ask unix: scope names and nothing
// admits is held while a person decides (ADR 0008), and an approval is carried out by the R11 relay, as the task, on
// the socket at the scope's place. A denial or a timeout refuses it with that reason and connects nothing; a name
// that reaches another place is not the scope's and is decided there (TestAskUnixScopeIsThePlaceTheNameReaches); a
// hold or tier that cannot carry the approval refuses before anyone is asked.
func TestAskUnixHoldsTheConnectAndRelaysTheApprovedSocket(t *testing.T) {
	const addr = 0x40000
	write := []agent.FSRule{{Path: "/work", Raw: "/work/", Kind: agent.FSWrite, Resolved: "/work"}}
	askPath := unixRuleOf("unix:/run/app.sock", "/run/app.sock", false)
	askAbs := unixRuleOf("unix:@bus", "bus", true)
	askWork := unixRuleOf("unix:/work/app.sock", "/work/app.sock", false)
	for _, r := range []*agent.NetRule{&askPath, &askAbs, &askWork} {
		r.Verdict = agent.VerdictAsk
	}
	for _, tc := range []struct {
		name     string
		path     string
		tier     backend.Tier
		hold     agent.AskHold
		declared []agent.NetRule
		symlinks map[string]string // planted after the loop was built
		cwd      string            // the task's cwd, for a relative name
		scope    string            // the scope's name a person is shown, when it is not path
		grant    bool              // the run's kernel can take an abstract-name grant (grantUnix)
		grantErr error
		domain   int   // the socket's SO_DOMAIN when it is not AF_UNIX
		ungrant  bool  // the grant is refused before the kernel is asked: no grantUnix call
		connErr  error // what the relayed connect itself returns
		answer   ask.Decision
		answerE  error
		asks     int
		errno    int32
		rule     string
		verdict  record.Verdict
		reason   string
		human    bool
		reached  string
	}{
		{name: "approved pathname", path: "/run/app.sock", answer: ask.Decision{Approved: true}, asks: 1,
			rule: "net[unix:/run/app.sock]", verdict: record.VerdictAllow, human: true, reached: "/run/app.sock"},
		{name: "denied", path: "/run/app.sock", answer: ask.Decision{Reason: ask.ReasonDenied}, asks: 1,
			errno: -int32(refusalErrno), rule: "net[unix:/run/app.sock]", verdict: record.VerdictRefused, reason: ask.ReasonDenied},
		{name: "timed out", path: "/run/app.sock", answer: ask.Decision{Reason: ask.ReasonTimeout}, asks: 1,
			errno: -int32(refusalErrno), rule: "net[unix:/run/app.sock]", verdict: record.VerdictRefused, reason: ask.ReasonTimeout},
		{name: "broker gone", path: "/run/app.sock", answerE: ask.ErrUnavailable, asks: 1,
			errno: -int32(refusalErrno), rule: "net[unix:/run/app.sock]", verdict: record.VerdictRefused, reason: ask.ReasonUnavailable},
		// The name reaches another place than the scope's, so it is not the scope's: decided there (R11c).
		{name: "the scope's name repointed before the connect", path: "/run/app.sock", answer: ask.Decision{Approved: true},
			symlinks: map[string]string{"/run/app.sock": "/run/docker.sock"},
			errno:    -int32(refusalErrno), rule: ruleUnmatched, verdict: record.VerdictRefused},
		{name: "a declared entry admits without asking", path: "/run/app.sock",
			declared: []agent.NetRule{unixRuleOf("unix:/run/app.sock", "/run/app.sock", false)},
			rule:     "net[unix:/run/app.sock]", verdict: record.VerdictAllow, reached: "/run/app.sock"},
		{name: "a relative name is asked as the scope's absolute one", path: "app.sock", cwd: "/run", scope: "/run/app.sock",
			answer: ask.Decision{Approved: true}, asks: 1,
			rule: "net[unix:/run/app.sock]", verdict: record.VerdictAllow, human: true, reached: "/run/app.sock"},
		{name: "a relative name from another cwd is refused unasked", path: "app.sock", cwd: "/srv",
			errno: -int32(refusalErrno), rule: ruleUnmatched, verdict: record.VerdictRefused},
		{name: "a scope inside a write entry is asked, not admitted by it", path: "/work/app.sock",
			answer: ask.Decision{Reason: ask.ReasonDenied}, asks: 1,
			errno: -int32(refusalErrno), rule: "net[unix:/work/app.sock]", verdict: record.VerdictRefused, reason: ask.ReasonDenied},
		{name: "a name no scope lists is refused unasked", path: "/run/other.sock",
			errno: -int32(refusalErrno), rule: ruleUnmatched, verdict: record.VerdictRefused},
		{name: "first_write cannot hold a unix connect", path: "/run/app.sock", hold: agent.AskHoldFirstWrite,
			errno: -int32(refusalErrno), rule: "net[unix:/run/app.sock]", verdict: record.VerdictRefused, reason: ask.ReasonUnavailable},
		{name: "approved pathname at tier cgroup needs no kernel grant", path: "/run/app.sock", tier: backend.TierCgroup,
			answer: ask.Decision{Approved: true}, asks: 1,
			rule: "net[unix:/run/app.sock]", verdict: record.VerdictAllow, human: true, reached: "/run/app.sock"},
		{name: "approved abstract name", path: "@bus", answer: ask.Decision{Approved: true}, asks: 1,
			rule: "net[unix:@bus]", verdict: record.VerdictAllow, human: true, reached: "@bus"},
		{name: "abstract name at tier bpflsm without a kernel grant is refused unasked", path: "@bus", tier: backend.TierBPFLSM,
			errno: -int32(refusalErrno), rule: "net[unix:@bus]", verdict: record.VerdictRefused, reason: ask.ReasonUnavailable},
		{name: "abstract name at tier cgroup with its kernel grant", path: "@bus", tier: backend.TierCgroup, grant: true,
			answer: ask.Decision{Approved: true}, asks: 1,
			rule: "net[unix:@bus]", verdict: record.VerdictAllow, human: true, reached: "@bus"},
		// The grant lapsed (its second ran out) or another program refused: the kernel's refusal is the task's answer,
		// and the line cannot say the approved connect happened.
		{name: "approved abstract name the cgroup program then refuses", path: "@bus", tier: backend.TierCgroup, grant: true,
			connErr: unix.EPERM, answer: ask.Decision{Approved: true}, asks: 1,
			errno: -int32(unix.EPERM), rule: "net[unix:@bus]", verdict: record.VerdictObserved, human: true, reached: "@bus"},
		{name: "approved abstract name the plane then refuses", path: "@bus", tier: backend.TierBPFLSM, grant: true,
			connErr: unix.EACCES, answer: ask.Decision{Approved: true}, asks: 1,
			errno: -int32(unix.EACCES), rule: "net[unix:@bus]", verdict: record.VerdictObserved, human: true, reached: "@bus"},
		{name: "approved abstract name nobody listens on", path: "@bus", tier: backend.TierCgroup, grant: true,
			connErr: unix.ECONNREFUSED, answer: ask.Decision{Approved: true}, asks: 1,
			errno: -int32(unix.ECONNREFUSED), rule: "net[unix:@bus]", verdict: record.VerdictAllow, human: true, reached: "@bus"},
		{name: "approved pathname the task may not write", path: "/run/app.sock", tier: backend.TierCgroup,
			connErr: unix.EACCES, answer: ask.Decision{Approved: true}, asks: 1,
			errno: -int32(unix.EACCES), rule: "net[unix:/run/app.sock]", verdict: record.VerdictAllow, human: true, reached: "/run/app.sock"},
		{name: "abstract grant refused by the kernel", path: "@bus", tier: backend.TierCgroup, grant: true, grantErr: errors.New("map full"),
			answer: ask.Decision{Approved: true}, asks: 1,
			errno: -int32(refusalErrno), rule: "net[unix:@bus]", verdict: record.VerdictRefused, reason: ask.ReasonUnavailable},
		// The grant names the socket by its cookie (GrantUnix takes no descriptor number), so the supervisor checks the
		// duplicate is a unix socket first, as GrantUnix did when it took the number.
		{name: "abstract grant on a socket that is not AF_UNIX", path: "@bus", tier: backend.TierCgroup, grant: true,
			domain: unix.AF_INET, ungrant: true, answer: ask.Decision{Approved: true}, asks: 1,
			errno: -int32(refusalErrno), rule: "net[unix:@bus]", verdict: record.VerdictRefused, reason: ask.ReasonUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake()
			sa := sockaddrUn(tc.path)
			f.put(addr, sa)
			f.sockType = unix.SOCK_STREAM
			f.sockDomain = unix.AF_UNIX
			if tc.domain != 0 {
				f.sockDomain = tc.domain
			}
			f.connectErr = tc.connErr
			pol := testPolicy(tc.declared, write, nil)
			pol.Rules.Tier = tc.tier
			pol.Rules.NetAsk = []agent.NetRule{askPath, askAbs, askWork}
			hold := tc.hold
			if hold == "" {
				hold = agent.AskHoldConnect
			}
			pol.Rules.AskConfig = &agent.AskConfig{Hold: hold, Timeout: agent.Duration(time.Second), MaxPending: 4}
			l, sink := newTestLoop(t, f, pol)
			for k, v := range tc.symlinks {
				f.symlinks[k] = v
				f.links[k] = v
			}
			if tc.cwd != "" {
				f.links["/proc/4242/cwd"] = tc.cwd
			}
			var asked []ask.Request
			l.ask = func(_ context.Context, r ask.Request) (ask.Decision, error) {
				asked = append(asked, r)
				return tc.answer, tc.answerE
			}
			granted, revoked := 0, 0
			if tc.grant {
				l.grantUnix = func(_ <-chan struct{}, cookie uint64, name []byte) (Revoke, error) {
					granted++
					if string(name) != "bus" {
						t.Errorf("granted %q, want the approved name", name)
					}
					if cookie != 77 {
						t.Errorf("granted cookie %d, want the duplicated socket's (77, the fake's SocketID)", cookie)
					}
					if tc.grantErr != nil {
						return nil, tc.grantErr
					}
					return func() (bool, error) { revoked++; return false, nil }, nil
				}
			}
			l.handle(notifFor(connectNR(), 4242, 5, addr, uint64(len(sa))))
			got, _ := f.lastResp()
			if got.Error != tc.errno || got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE != 0 {
				t.Errorf("response = %+v, want error %d", got, tc.errno)
			}
			if len(asked) != tc.asks {
				t.Fatalf("asked %d times, want %d: %+v", len(asked), tc.asks, asked)
			}
			if tc.asks == 1 {
				r, scope := asked[0], tc.path
				if tc.scope != "" {
					scope = tc.scope
				}
				if r.Op != "connect" || r.Target != "unix:"+scope || r.Rule != "net[unix:"+scope+"]" || r.Hold != string(agent.AskHoldConnect) || r.TID != 4242 {
					t.Errorf("request %+v", r)
				}
			}
			switch {
			case tc.reached == "" && len(f.unixConnects) != 0:
				t.Errorf("reached %q, want no connect", f.unixConnects)
			case tc.reached != "" && (len(f.unixConnects) != 1 || f.unixConnects[0] != tc.reached):
				t.Errorf("reached %q, want %s", f.unixConnects, tc.reached)
			}
			ev := sink.one(t)
			var p netPayload
			if err := ev.DecodePayload(&p); err != nil {
				t.Fatal(err)
			}
			if ev.Verdict != tc.verdict || ev.Rule != tc.rule || p.Dst != "unix:"+tc.path || p.Proto != protoUnix {
				t.Errorf("event = %s/%s dst %q proto %s, want %s/%s dst unix:%s", ev.Verdict, ev.Rule, p.Dst, p.Proto, tc.verdict, tc.rule, tc.path)
			}
			if tc.reason != "" && string(ev.Reason) != tc.reason {
				t.Errorf("reason %q, want %q", ev.Reason, tc.reason)
			}
			if human := ev.Authority == record.AuthorityHuman; human != tc.human {
				t.Errorf("authority %q, want human %v", ev.Authority, tc.human)
			}
			switch {
			case tc.ungrant && granted != 0:
				t.Errorf("grants %d, want none", granted)
			case tc.grant && !tc.ungrant && tc.asks == 1 && (granted != 1 || tc.grantErr == nil && revoked != 1):
				t.Errorf("grants %d revokes %d, want one each", granted, revoked)
			}
			if f.fdBalance() != 0 {
				t.Errorf("%d descriptors left open (E28)", f.fdBalance())
			}
		})
	}
}
