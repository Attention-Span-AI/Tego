// SPDX-License-Identifier: Apache-2.0

package landlock

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

func inet(port int) agent.NetRule {
	return agent.NetRule{Raw: "host:" + itoa(port), Host: "host", Port: port, Proto: agent.ProtoInet, Verdict: agent.VerdictAllow}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for ; i > 0; i /= 10 {
		b = append([]byte{byte('0' + i%10)}, b...)
	}
	return string(b)
}

// TestNetRulesBands is R6/R22 across the ABI bands (LL-E4: below ABI 4 no port rule and no handled net right), port dedup, the resolver port, port 0,
// the ephemeral UDP bind at ABI 10 and the two ways a contract can leave net unrestricted.
//
// Spec: docs/p0/enforce-landlock.md E4.
func TestNetRulesBands(t *testing.T) {
	entries := []agent.NetRule{inet(443), inet(8080), inet(443), inet(0), {Raw: "unix:@x", Proto: agent.ProtoUnix, UnixPath: "x", Abstract: true}}
	tcp := uint64(accessNetConnectTCP)
	both := uint64(accessNetConnectTCP | accessNetConnectSendUDP)
	bindUDP := uint64(accessNetBindUDP)
	cases := []struct {
		name      string
		abi       int
		contract  *agent.Contract
		entries   []agent.NetRule
		wantNet   uint64
		wantRules []netCall
	}{
		{"abi 1: nothing", 1, contractWith(true, true), entries, 0, nil},
		{"abi 3: nothing", 3, contractWith(true, true), entries, 0, nil},
		{"abi 4: tcp ports + resolver", 4, contractWith(true, true), entries, uint64(profileFor(4).Net), []netCall{{tcp, 53, 0}, {tcp, 443, 0}, {tcp, 8080, 0}}},
		{"abi 8: same as 4", 8, contractWith(true, true), entries, uint64(profileFor(8).Net), []netCall{{tcp, 53, 0}, {tcp, 443, 0}, {tcp, 8080, 0}}},
		{"abi 9: same as 4", 9, contractWith(true, true), entries, uint64(profileFor(9).Net), []netCall{{tcp, 53, 0}, {tcp, 443, 0}, {tcp, 8080, 0}}},
		{"abi 10: udp joins", 10, contractWith(true, true), entries, uint64(profileFor(10).Net), []netCall{{bindUDP, 0, 0}, {both, 53, 0}, {both, 443, 0}, {both, 8080, 0}}},
		{"abi 10, net.allow empty: handled, no rule", 10, contractWith(true, true), nil, uint64(profileFor(10).Net), nil},
		{"abi 10, unix only: no udp bind", 10, contractWith(true, true), entries[4:], uint64(profileFor(10).Net), nil},
		{"net.allow empty: handled, no rule", 7, contractWith(true, true), nil, uint64(profileFor(7).Net), nil},
		{"unix only: no resolver port", 7, contractWith(true, true), entries[4:], uint64(profileFor(7).Net), nil},
		{"no net section: unrestricted", 7, contractWith(true, false), entries, 0, nil},
		{"nil contract fails closed", 7, nil, nil, uint64(profileFor(7).Net), nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rt := &agent.RuleTable{Contract: tc.contract, Net: tc.entries}
			_, fake := prepare(t, tc.abi, rt)
			if got := fake.created[0].Handled_access_net; got != tc.wantNet {
				t.Errorf("handled net = %#x, want %#x", got, tc.wantNet)
			}
			if !reflect.DeepEqual(fake.nets, tc.wantRules) {
				t.Errorf("net rules = %+v, want %+v", fake.nets, tc.wantRules)
			}
			// R6: BIND_TCP never; R22: BIND_UDP on the ephemeral port only, and alone on its rule.
			for _, n := range fake.nets {
				if n.Access&uint64(accessNetBindTCP) != 0 ||
					(n.Access&uint64(accessNetBindUDP) != 0 && (n.Port != 0 || n.Access != bindUDP)) {
					t.Errorf("bind granted: %+v", n)
				}
			}
		})
	}
	rt := &agent.RuleTable{Contract: contractWith(true, true), Net: []agent.NetRule{{Raw: "x", Proto: "quic"}}}
	if err := prepareErr(t, 7, rt, nil); !errors.Is(err, ErrRulesetBuild) {
		t.Errorf("unknown proto: %v", err)
	}
}

// TestUnixEntries: abstract names carry no fd at any ABI; pathname entries are held with
// RESOLVE_UNIX at ABI ≥ 9 only, and a write entry gains RESOLVE_UNIX there too.
//
// Spec: docs/p0/enforce-landlock.md R21.
func TestUnixEntries(t *testing.T) {
	root := tempDir(t)
	sock := filepath.Join(root, "daemon.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	mkTree(t, root, "out/")
	rt := &agent.RuleTable{
		Contract: contractWith(true, true),
		FS:       []agent.FSRule{fsRule(agent.FSWrite, filepath.Join(root, "out"))},
		Net: []agent.NetRule{
			{Raw: "unix:" + sock, Proto: agent.ProtoUnix, UnixPath: sock},
			{Raw: "unix:@bus", Proto: agent.ProtoUnix, UnixPath: "bus", Abstract: true},
		},
	}
	for _, abi := range []int{7, 8, 9, 10} {
		h, _ := prepare(t, abi, rt)
		e, held := h.entry(sock)
		out, _ := h.entry(filepath.Join(root, "out"))
		if abi >= 9 {
			if !held || e.Kind != kindUnixSocket || e.Access != accessResolveUnix {
				t.Errorf("ABI %d: socket = %+v, %v", abi, e, held)
			}
			if out.Access&accessResolveUnix == 0 {
				t.Errorf("ABI %d: write entry lacks RESOLVE_UNIX", abi)
			}
		} else if held || out.Access&accessResolveUnix != 0 {
			t.Errorf("ABI %d: socket held %v, write access %#x", abi, held, out.Access)
		}
		if _, held := h.entry("bus"); held {
			t.Errorf("ABI %d: the abstract name is held", abi)
		}
	}
	rt.Net[0].UnixPath = filepath.Join(root, "missing.sock")
	if err := prepareErr(t, 9, rt, nil); !errors.Is(err, ErrPathVanished) {
		t.Errorf("missing socket at ABI 9: %v", err)
	}
	if _, err := prepareErrOK(t, 8, rt); err != nil {
		t.Errorf("missing socket below ABI 9 must not matter: %v", err)
	}
}

// prepareErrOK runs Prepare expecting success and closes the handle.
func prepareErrOK(t *testing.T, abi int, rt *agent.RuleTable) (*Handle, error) {
	t.Helper()
	h, err := New(Options{syscalls: &fakeSyscalls{abi: abi}}).Prepare(context.Background(), rt, Run{})
	if err != nil {
		return nil, err
	}
	_ = h.Close()
	return h, nil
}

// TestNoNetSectionHandlesNoUnixRight pins SEMANTICS §1's "no net: — deny nothing" for pathname sockets
// at ABI ≥ 9 under host_sockets: true (ADR 0070's opt-out): RESOLVE_UNIX is net:'s pathname-socket half (R21), so
// such a contract handles it nowhere — not in the ruleset's handled mask, and not on any rule, the write entry's
// included — while `net: {}` keeps it handled and granted under the write entry. Handled there, the kernel refused
// the agent's own connect to every socket outside a write entry, which the supervisor answers CONTINUE and Evaluate
// answers allow. TestUnixOnlyStateHandlesResolveUnix has the default, which handles it.
func TestNoNetSectionHandlesNoUnixRight(t *testing.T) {
	root := tempDir(t)
	mkTree(t, root, "out/")
	for _, abi := range []int{9, 10, 11} {
		for _, network := range []bool{false, true} {
			ct := contractWith(true, network)
			ct.HostSockets = true
			rt := &agent.RuleTable{
				Contract: ct,
				FS:       []agent.FSRule{fsRule(agent.FSWrite, filepath.Join(root, "out"))},
			}
			h, fake := prepare(t, abi, rt)
			handled := accessFS(fake.created[0].Handled_access_fs) & accessResolveUnix
			out, _ := h.entry(filepath.Join(root, "out"))
			if !network {
				if handled != 0 {
					t.Errorf("ABI %d, no net: handled fs mask %#x carries RESOLVE_UNIX", abi, fake.created[0].Handled_access_fs)
				}
				for _, p := range fake.paths {
					if accessFS(p.Access)&accessResolveUnix != 0 {
						t.Errorf("ABI %d, no net: rule on fd %d grants RESOLVE_UNIX (%#x)", abi, p.FD, p.Access)
					}
				}
				if out.Access&accessResolveUnix != 0 {
					t.Errorf("ABI %d, no net: write entry = %#x", abi, out.Access)
				}
				continue
			}
			if handled == 0 || out.Access&accessResolveUnix == 0 {
				t.Errorf("ABI %d, net: {}: handled %#x, write entry %#x: RESOLVE_UNIX must stay handled and granted",
					abi, fake.created[0].Handled_access_fs, out.Access)
			}
		}
	}
}

// TestUnixOnlyStateHandlesResolveUnix is ADR 0070 at tier landlock: a contract with no net: section and no
// host_sockets: true handles no net right (every IP destination is the contract's to allow), but from ABI 9 it handles
// RESOLVE_UNIX, granted under the write entry and on the runtime's own unix: grant (the DNS broker's socket), so the
// agent's own connect to a host daemon's socket is refused by the kernel behind the supervisor's relay; the abstract
// scope stays handled from ABI 6; and its filter notifies bind(2), so the supervisor records the run's own sockets.
func TestUnixOnlyStateHandlesResolveUnix(t *testing.T) {
	root := tempDir(t)
	mkTree(t, root, "out/", "dns/")
	broker := filepath.Join(root, "dns", "dns.sock")
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: broker, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	for _, abi := range []int{6, 8, 9, 10} {
		rt := &agent.RuleTable{
			Contract: contractWith(true, false),
			FS:       []agent.FSRule{fsRule(agent.FSWrite, filepath.Join(root, "out"))},
			Net: []agent.NetRule{{Raw: "unix:" + broker, Proto: agent.ProtoUnix, UnixPath: broker, Static: true,
				Verdict: agent.VerdictAllow, Runtime: agent.DNSBrokerGrant}},
		}
		if !rt.HostSocketsRefused() {
			t.Fatal("the table is not in the unix-only state")
		}
		h, fake := prepare(t, abi, rt)
		if fake.created[0].Handled_access_net != 0 {
			t.Errorf("ABI %d: handled net %#x, want none: IP stays unrestricted", abi, fake.created[0].Handled_access_net)
		}
		if fake.created[0].Scoped&uint64(scopeAbstractUnixSocket) == 0 {
			t.Errorf("ABI %d: scope %#x lacks the abstract-socket scope", abi, fake.created[0].Scoped)
		}
		handled := accessFS(fake.created[0].Handled_access_fs) & accessResolveUnix
		out, _ := h.entry(filepath.Join(root, "out"))
		bk, held := h.entry(broker)
		granted := held && bk.Access&accessResolveUnix != 0
		if abi >= 9 && (handled == 0 || out.Access&accessResolveUnix == 0 || !granted) {
			t.Errorf("ABI %d: handled %#x, write entry %#x, broker granted %v: RESOLVE_UNIX must be handled and granted", abi, fake.created[0].Handled_access_fs, out.Access, granted)
		}
		if !h.filterOpts.unixBinds {
			t.Errorf("ABI %d: the filter does not notify bind(2)", abi)
		}
	}
}
