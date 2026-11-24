// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/check/rule"
	"github.com/attention-span-ai/tego/internal/contracts"
	"github.com/attention-span-ai/tego/internal/control/pathcheck"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

type resolverContextReply struct {
	Warnings           []UnresolvedHost
	Date               string
	Environment, Dials int
}

func resolverNoNetwork() (*net.Resolver, *atomic.Int32) {
	calls := new(atomic.Int32)
	return &net.Resolver{PreferGo: true, Dial: func(context.Context, string, string) (net.Conn, error) {
		calls.Add(1)
		return nil, errors.New("test forbids resolver network I/O")
	}}, calls
}

var resolverContextChanges = []rule.Change{{Key: "net.allow", Entry: "localhost:443"}, {Key: "net.ask", Entry: "127.0.0.1:443"}}

func init() {
	pathcheck.Register("test.resolver-context", func(ctx context.Context, payload []byte) ([]byte, error) {
		var state serviceState
		if err := pathcheck.Decode(payload, &state); err != nil {
			return nil, err
		}
		s, err := serviceFromState(ctx, state)
		if err != nil {
			return nil, err
		}
		var calls *atomic.Int32
		net.DefaultResolver, calls = resolverNoNetwork()
		reply := resolverContextReply{Warnings: s.unresolved(ctx, resolverContextChanges), Date: s.date(), Environment: len(os.Environ()), Dials: int(calls.Load())}
		return pathcheck.Encode(reply)
	})
}

func TestHelperPreviewResolverContextParity(t *testing.T) {
	old := net.DefaultResolver
	t.Cleanup(func() { net.DefaultResolver = old })
	var calls *atomic.Int32
	net.DefaultResolver, calls = resolverNoNetwork()
	for _, tc := range []struct{ key, value, selector string }{
		{"LOCALDOMAIN", "", "LOCALDOMAIN"},
		{"RES_OPTIONS", "attempts:1", "RES_OPTIONS"},
		{"HOSTALIASES", "/private/alias-values-must-not-cross-frame", "HOSTALIASES"},
		{"RESOLV_HOST_CONF", "", "RESOLV_HOST_CONF"},
		{"RESOLV_MULTI", "on", "RESOLV_MULTI"},
		{"RESOLV_REORDER", "off", "RESOLV_REORDER"},
		{"RESOLV_ADD_TRIM_DOMAINS", ".private.example", "RESOLV_ADD_TRIM_DOMAINS"},
		{"RESOLV_OVERRIDE_TRIM_DOMAINS", ".private.example", "RESOLV_OVERRIDE_TRIM_DOMAINS"},
		{"GODEBUG", "netdns=cgo", "GODEBUG/netdns"},
		{"GODEBUG", "netedns0=0", "GODEBUG/netedns0"},
		{"GODEBUG", "multipathtcp=1", "GODEBUG/multipathtcp"},
	} {
		t.Run(tc.selector, func(t *testing.T) {
			for _, key := range []string{"LOCALDOMAIN", "RES_OPTIONS", "HOSTALIASES", "RESOLV_HOST_CONF", "RESOLV_MULTI", "RESOLV_REORDER", "RESOLV_ADD_TRIM_DOMAINS", "RESOLV_OVERRIDE_TRIM_DOMAINS", "GODEBUG"} {
				t.Setenv(key, "")
				if err := os.Unsetenv(key); err != nil {
					t.Fatal(err)
				}
			}
			t.Setenv(tc.key, tc.value)
			caller := config.CaptureCaller()
			framed, err := json.Marshal(caller)
			if err != nil {
				t.Fatal(err)
			}
			rawValue, err := json.Marshal(tc.value)
			if err != nil {
				t.Fatal(err)
			}
			if tc.value != "" && bytes.Contains(framed, rawValue) {
				t.Fatal("resolver setting value entered caller context")
			}
			ctx, closeSession := contracts.WithHelperSession(contracts.ContextWithCaller(context.Background(), caller))
			defer closeSession()
			s := &Service{caller: &caller}
			want := s.unresolved(ctx, resolverContextChanges)
			if len(want) != 1 || want[0].Host != "localhost" || !strings.Contains(want[0].Why, "cannot tell:") || !strings.Contains(want[0].Why, tc.selector) {
				t.Fatalf("caller resolver uncertainty lost: %+v", want)
			}
			var got resolverContextReply
			if err := pathcheck.Call(ctx, "test.resolver-context", serviceState{Caller: &caller}, &got); err != nil {
				t.Fatal(err)
			}
			wantBytes, err := json.Marshal(want)
			if err != nil {
				t.Fatal(err)
			}
			gotBytes, err := json.Marshal(got.Warnings)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(gotBytes, wantBytes) || got.Environment != 0 || got.Dials != 0 || calls.Load() != 0 {
				t.Fatalf("helper differs or used environment/network: got=%+v want=%s caller-dials=%d", got, wantBytes, calls.Load())
			}
			custom := &hostResolver{}
			s.Resolver = custom
			if out := s.unresolved(ctx, resolverContextChanges); out != nil || custom.count() != 1 {
				t.Fatalf("explicit resolver was ignored: warnings=%+v calls=%d", out, custom.count())
			}
		})
	}
}

func TestHelperCallerDateParity(t *testing.T) {
	caller := config.CaptureCaller()
	caller.CheckedAt = time.Date(2001, 2, 3, 0, 30, 0, 0, time.FixedZone("caller", 14*60*60))
	if caller.CheckedAt.UTC().Format(time.DateOnly) != "2001-02-02" {
		t.Fatal("fixture does not cross a calendar day")
	}
	ctx, closeSession := contracts.WithHelperSession(contracts.ContextWithCaller(context.Background(), caller))
	defer closeSession()
	var got resolverContextReply
	if err := pathcheck.Call(ctx, "test.resolver-context", serviceState{Caller: &caller}, &got); err != nil {
		t.Fatal(err)
	}
	if want := (&Service{caller: &caller}).date(); want != "2001-02-03" || got.Date != want {
		t.Fatalf("caller date lost: helper=%q caller=%q", got.Date, want)
	}
}

func TestHelperExplicitDateClock(t *testing.T) {
	f := newFixture(t)
	// Use production transport with a real compiler and an explicit date seam.
	home := filepath.Join(f.dir, "date-home")
	if err := os.Mkdir(home, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(f.proj, "private"), 0o700); err != nil {
		t.Fatal(err)
	}
	writeFile(t, f.contract, "version: 0\nname: tester\ncommand: [/bin/true]\nexec:\n  allow: [/bin/true]\n")
	machine := config.Builtin()
	machine.Home = home
	f.s = &Service{Ledger: f.ledger, Home: home, Machine: machine, PATH: "/usr/bin:/bin"}
	f.s.Now = func() time.Time { return time.Date(2001, 2, 3, 0, 30, 0, 0, time.FixedZone("caller", 14*60*60)) }
	ref := f.ref(t, f.contract)
	p, err := f.s.PlanChange(context.Background(), ChangeReq{Ref: ref.Ref, Base: ref.Base, Edits: []Edit{{Op: "add", Key: "fs.deny_read", Entry: "./private/"}}})
	if err != nil || p.Err != "" {
		t.Fatalf("preview: %+v %v", p, err)
	}
	if !strings.Contains(p.Diff, "2001-02-03") {
		t.Fatalf("explicit date clock lost: %s", p.Diff)
	}
}
