// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/liveblock"
	"github.com/attention-span-ai/tego/internal/watch/adopt"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// machineWithHome is a machine config whose passwd home is home.
func machineWithHome(home string) *config.Machine { return &config.Machine{Home: home} }

// blockGapLines drains r's queue for the gap lines that carry a live_block, in order.
func blockGapLines(t *testing.T, r *runner) []record.GapPayload {
	t.Helper()
	r.queue.Close()
	var out []record.GapPayload
	for ev := range r.queue.C() {
		if ev.Kind != record.KindGap {
			continue
		}
		var p record.GapPayload
		if err := ev.DecodePayload(&p); err != nil {
			t.Fatal(err)
		}
		if p.LiveBlock != nil {
			out = append(out, p)
		}
	}
	return out
}

// TestNameBlockRecordsItsAddresses (ADR 0157): the gap line of a net block put in force by a host name names the addresses
// the live set refuses the name by (unmapped, a zone kept, sorted by address, at most record.MaxLiveBlockAddrs with the rest
// counted); a block by address names none, a name no lookup answered names none, and neither does a removal.
func TestNameBlockRecordsItsAddresses(t *testing.T) {
	const host = "cdn.example.test"
	many := func(n int) []netip.Addr {
		var out []netip.Addr
		for i := range n {
			out = append(out, netip.MustParseAddr(fmt.Sprintf("10.0.%d.%d", i/200, i%200+1)))
		}
		return slices.Concat(out[len(out)/2:], out[:len(out)/2]) // unsorted, as a resolver answers
	}
	for _, c := range []struct {
		name   string
		value  string
		answer []netip.Addr
		fail   bool
		want   []string
		more   int
	}{
		{name: "a name: sorted, mapped answers unmapped, a zone kept", value: host + ":443",
			answer: []netip.Addr{netip.MustParseAddr("fe80::1%2"), netip.MustParseAddr("::ffff:198.51.100.7"),
				netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("198.51.100.3")},
			want: []string{"198.51.100.3", "198.51.100.7", "2001:db8::1", "fe80::1%2"}},
		{name: "a name with no port", value: host, answer: []netip.Addr{netip.MustParseAddr("198.51.100.3")}, want: []string{"198.51.100.3"}},
		{name: "a lookup that failed", value: host + ":443", fail: true},
		{name: "a lookup that answered none", value: host + ":443"},
		{name: "past the cap", value: host + ":443", answer: many(record.MaxLiveBlockAddrs + 8),
			want: func() []string {
				var out []string
				for i := range record.MaxLiveBlockAddrs {
					out = append(out, fmt.Sprintf("10.0.0.%d", i+1))
				}
				return out
			}(), more: 8},
		{name: "at the cap", value: host + ":443", answer: many(record.MaxLiveBlockAddrs), want: func() []string {
			var out []string
			for i := range record.MaxLiveBlockAddrs {
				out = append(out, fmt.Sprintf("10.0.0.%d", i+1))
			}
			return out
		}()},
		{name: "a block by address", value: "198.51.100.9:443", answer: []netip.Addr{netip.MustParseAddr("198.51.100.3")}},
		{name: "a block by IPv6 address", value: "[2001:db8::9]:443", answer: []netip.Addr{netip.MustParseAddr("198.51.100.3")}},
	} {
		t.Run(c.name, func(t *testing.T) {
			var now liveblock.Clock
			r, _ := blockHostRunner(t, host, &now, func() ([]netip.Addr, error) {
				if c.fail {
					return nil, errors.New("no such host")
				}
				return c.answer, nil
			})
			b := &liveBlocks{}
			changeBlock(t, r, true, liveblock.KindNet, c.value)
			r.pollLiveBlocks(context.Background(), b)
			changeBlock(t, r, false, liveblock.KindNet, c.value)
			r.pollLiveBlocks(context.Background(), b)
			lines := blockGapLines(t, r)
			if len(lines) != 2 || lines[0].Why != record.GapLiveBlockAdded || lines[1].Why != record.GapLiveBlockRemoved {
				t.Fatalf("lines %+v: want an add and a remove", lines)
			}
			add, remove := lines[0].LiveBlock, lines[1].LiveBlock
			if !slices.Equal(add.Addrs, c.want) || add.AddrsMore != c.more {
				t.Errorf("the add line names %v and %d more, want %v and %d", add.Addrs, add.AddrsMore, c.want, c.more)
			}
			if len(remove.Addrs) != 0 || remove.AddrsMore != 0 {
				t.Errorf("the remove line names addresses: %+v", remove)
			}
		})
	}
}

// TestRestoredNameFenceRecordsItsAddresses: a restored fence entry by name carries the addresses its refusal came back on
// (the ones its single lookup at the run's start answered); one by address, and the lift, carry none.
func TestRestoredNameFenceRecordsItsAddresses(t *testing.T) {
	const fenceHost = "db.example.test"
	r := fenceRunner(t)
	value := fenceHost + ":5432"
	r.rt.Live.Entries[1].Value = value
	old := liveLookup
	liveLookup = func(_ context.Context, host string) ([]netip.Addr, error) {
		if host != fenceHost {
			return nil, errors.New("no such host")
		}
		return []netip.Addr{netip.MustParseAddr("192.0.2.78"), netip.MustParseAddr("192.0.2.77")}, nil
	}
	t.Cleanup(func() { liveLookup = old })
	ctx := context.Background()
	b, err := r.startLiveBlocks(ctx)
	if err != nil {
		t.Fatal(err)
	}
	key := b.fence.(*liveFence).key
	updateOverlay(t, r.dir, string(r.id), func(o *liveblock.Overlay) error {
		_, e := o.Lift(liveblock.KindNet, value, "uid:1 pid:3 cli", time.Now(), time.Time{}, key)
		return e
	})
	r.pollLiveBlocks(ctx, b)
	updateOverlay(t, r.dir, string(r.id), func(o *liveblock.Overlay) error {
		_, e := o.Restore(liveblock.KindNet, value, "uid:1 pid:3 cli", time.Now())
		return e
	})
	r.pollLiveBlocks(ctx, b)
	lines := blockGapLines(t, r)
	if len(lines) != 2 || lines[0].Why != record.GapLiveRuleLifted || lines[1].Why != record.GapLiveRuleRestored {
		t.Fatalf("lines %+v: want a lift and a restore", lines)
	}
	if got := lines[0].LiveBlock; len(got.Addrs) != 0 {
		t.Errorf("the lift names addresses: %v", got.Addrs)
	}
	if got := lines[1].LiveBlock; !slices.Equal(got.Addrs, []string{"192.0.2.77", "192.0.2.78"}) || got.AddrsMore != 0 {
		t.Errorf("the restore names %v (%d more), want both addresses sorted", got.Addrs, got.AddrsMore)
	}
}

// TestEveryRunStartIsRevision41: a launch's run_start and an adoption's carry record_minor 41 and the home their run
// resolved: the launching user's passwd home for a launch, the agent owner's for an adoption, none when the run has none, and
// never one a reader could not fold against (relative, or not clean). Below 41 (a test's reserved revision) no home is written.
func TestEveryRunStartIsRevision41(t *testing.T) {
	if launchMinor != record.MinorEveryLaunch {
		t.Fatalf("launchMinor %d, want %d", launchMinor, record.MinorEveryLaunch)
	}
	for _, c := range []struct {
		name string
		deps Deps
		want string
	}{
		{"the machine's passwd home", Deps{Config: machineWithHome("/home/ada")}, "/home/ada"},
		{"no home resolved", Deps{Config: machineWithHome("")}, ""},
		{"a relative home", Deps{Config: machineWithHome("home/ada")}, ""},
		{"a home that is not clean", Deps{Config: machineWithHome("/home/ada/")}, ""},
		{"a launch ignores Deps.Home (an adoption's)", Deps{Config: machineWithHome("/home/ada"), Home: "/root"}, "/home/ada"},
	} {
		t.Run(c.name, func(t *testing.T) {
			c.deps.Labels, c.deps.Environ = map[string]string{}, []string{}
			line := runStartLine(t, c.deps)
			e, err := record.Decode([]byte(line))
			if err != nil {
				t.Fatal(err)
			}
			var p record.RunStartPayload
			if err := e.DecodePayload(&p); err != nil {
				t.Fatal(err)
			}
			if p.RecordMinor != record.MinorEveryLaunch || p.Home != c.want {
				t.Errorf("record_minor %d home %q, want 41 and %q", p.RecordMinor, p.Home, c.want)
			}
		})
	}
	// Below 41 the field would be refused, so it is not written.
	defer func(m int) { launchMinor = m }(launchMinor)
	launchMinor = record.MinorLearn
	line := runStartLine(t, Deps{Config: machineWithHome("/home/ada"), Labels: map[string]string{}, Environ: []string{}})
	e, err := record.Decode([]byte(line))
	if err != nil {
		t.Fatal(err)
	}
	var p record.RunStartPayload
	if err := e.DecodePayload(&p); err != nil || p.Home != "" || p.RecordMinor != record.MinorLearn {
		t.Errorf("at revision 31: home %q record_minor %d (%v)", p.Home, p.RecordMinor, err)
	}
}

// TestAdoptionRunStartRecordsTheOwnersHome: an adoption's run_start is revision 41 and carries the home of the agent's
// owner the adoption was compiled against (Deps.Home), never the adopter's machine config's; none when the owner has none.
func TestAdoptionRunStartRecordsTheOwnersHome(t *testing.T) {
	for _, c := range []struct {
		name string
		deps Deps
		want string
	}{
		{"the owner's home", Deps{Home: "/home/owner", Config: machineWithHome("/root")}, "/home/owner"},
		{"an owner with none", Deps{Home: "", BaselineOwnerUnknown: true, Config: machineWithHome("/root")}, ""},
		{"a relative home", Deps{Home: "owner", Config: machineWithHome("/root")}, ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			const id = "r-00000000-000000000000a-adopt1"
			dir := filepath.Join(t.TempDir(), id)
			w, err := ledger.Open(dir, record.RunRef{ID: id, Agent: "retriever"}, ledger.WithAnchor(nopAnchor{}))
			if err != nil {
				t.Fatal(err)
			}
			defer w.Abandon()
			c.deps.Enforce, c.deps.Cwd, c.deps.Labels, c.deps.Environ = tierBackend{tier: backend.TierLandlock}, "/srv/proj", map[string]string{}, []string{}
			r := newTestRunner(c.deps)
			r.writer, r.cmd = w, []string{"/bin/true"}
			r.rt = &agent.RuleTable{ContractPath: "/srv/agent.yaml", Contract: &agent.Contract{Name: "retriever"}}
			procRoot := t.TempDir()
			task := filepath.Join(procRoot, "4242")
			if err := os.Mkdir(task, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("/srv/proj", filepath.Join(task, "cwd")); err != nil {
				t.Fatal(err)
			}
			a := &adoption{r: r, spec: AdoptSpec{Root: adopt.Process{PID: 4242, Argv: []string{"/bin/true"}}}, env: adopt.Env{Proc: adopt.NewFS(procRoot)}}
			if err := a.writeRunStart(); err != nil {
				t.Fatal(err)
			}
			if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
				t.Fatal(err)
			}
			b, err := os.ReadFile(filepath.Join(dir, ledger.EventsFile))
			if err != nil {
				t.Fatal(err)
			}
			first, _, _ := strings.Cut(string(b), "\n")
			e, err := record.Decode([]byte(first))
			if err != nil {
				t.Fatal(err)
			}
			var p record.RunStartPayload
			if err := e.DecodePayload(&p); err != nil {
				t.Fatal(err)
			}
			if p.RecordMinor != record.MinorEveryLaunch || p.Home != c.want {
				t.Errorf("record_minor %d home %q, want 41 and %q", p.RecordMinor, p.Home, c.want)
			}
		})
	}
}
