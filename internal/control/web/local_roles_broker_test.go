// SPDX-License-Identifier: Apache-2.0

package web

import (
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/askclient"
	"github.com/attention-span-ai/tego/internal/runlock"
	"github.com/attention-span-ai/tego/internal/runtime/ask"
)

// These traverse the normal handler, runact.Answer, verified launcher lock,
// askclient and real broker. The Unix connection and packet carry this test
// process's actual kernel credentials, which the authorization callback asserts.
// HTTP peer data and the policy-reader result are fixtures; neither supplies a
// broker identity refusal.
func TestLocalRolesDashboardRealBrokerRefusesNonRoot(t *testing.T) {
	localRolesDashboardBrokerRefusal(t, nil, []string{"only root may answer once", "root from a terminal outside any governed run", "request remains pending"})
}

func TestLocalRolesDashboardRealBrokerRefusesPolicyDrift(t *testing.T) {
	localRolesDashboardBrokerRefusal(t, os.ErrNotExist, []string{"the approval policy file changed since this run started", "tego stop", "relaunch with the same ledger configuration", "request remains pending"})
}

func localRolesDashboardBrokerRefusal(t *testing.T, policyErr error, want []string) {
	t.Helper()
	if os.Geteuid() == 0 {
		// The broker's refusal is of a caller that is not root, and this process's own kernel credentials are the
		// witness: as root they are the deciding role's, so nothing is refused. The unprivileged steps run it.
		t.Skip("as root the test process is the owner-only deciding role, so the broker refuses nobody; the unprivileged steps run this credential witness")
	}
	root := fixture(t)
	dir := filepath.Join(root, harmRun)
	started, err := runlock.StartBootNS(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	info := runlock.LockInfo{PID: os.Getpid(), StartBootNS: started, PIDNS: runlock.OwnPIDNS()}
	if err := os.WriteFile(filepath.Join(dir, "lock"), []byte(info.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	ready := make(chan string, 1)
	done := make(chan ask.Decision, 1)
	var authenticated, answers atomic.Int32
	b, err := ask.New(dir, ask.Options{
		UID: uint32(os.Geteuid()), Timeout: time.Minute,
		OwnerOnly: &ask.OwnerOnlyAuthority{AgentUID: uint32(os.Geteuid()), Check: func() error { return policyErr }},
		Authorize: func(p ask.Peer) error {
			if p.PID != os.Getpid() || p.UID != uint32(os.Geteuid()) || p.StartBootNS != started || p.Cgroup == "" || p.CgroupNS == 0 {
				return errors.New("broker did not read the test process's actual credential facts")
			}
			authenticated.Add(1)
			return nil
		},
		Emit: func(e ask.Event) error {
			if e.Kind == "answer" {
				answers.Add(1)
			}
			return nil
		},
		Pending: func(r ask.Request) { ready <- r.AskID },
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := b.Close(); err != nil {
			t.Error(err)
		}
		select {
		case d := <-done:
			if d.Approved {
				t.Error("non-root dashboard released the held operation")
			}
		case <-time.After(time.Second):
			t.Error("held operation did not stop with the broker")
		}
	})
	go func() {
		d, _ := b.Request(t.Context(), ask.Request{Op: "open", Target: "/held/effect", Rule: "fs.ask[0]", Hold: ask.HoldOpen, PID: os.Getpid(), TID: os.Getpid()})
		done <- d
	}()
	var id string
	select {
	case id = <-ready:
	case <-time.After(time.Second):
		t.Fatal("broker did not publish the held operation")
	}
	s := newServer(t, root)
	c := login(t, s)
	csrf := csrfOf(t, s, c, "/approvals")
	for _, decision := range []string{"approve", "deny"} {
		before := authenticated.Load()
		w := post(s, "/approvals/answer", url.Values{"csrf": {csrf}, "run": {harmRun}, "ask": {id}, "decision": {decision}}, own, own+"/approvals", c)
		body := follow(t, s, c, w)
		if authenticated.Load() < before+2 {
			t.Fatal("dashboard answer did not reach broker connection and packet authentication")
		}
		for _, text := range want {
			if !strings.Contains(body, text) {
				t.Errorf("broker refusal lacks %q: %s", text, body)
			}
		}
		if policyErr != nil && strings.Contains(body, "only root may answer once") {
			t.Error("policy drift incorrectly returned the identity remedy")
		}
		pending, err := askclient.List(t.Context(), dir, os.Getpid())
		if err != nil || len(pending) != 1 || pending[0].AskID != id || !b.Waiting() || answers.Load() != 0 {
			t.Fatalf("non-root %s consumed the ask: pending=%+v, answers=%d, err=%v", decision, pending, answers.Load(), err)
		}
		select {
		case d := <-done:
			done <- d
			t.Fatalf("held operation returned after non-root %s: %+v", decision, d)
		default:
		}
	}
}
