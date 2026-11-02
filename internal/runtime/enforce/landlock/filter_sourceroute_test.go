// SPDX-License-Identifier: Apache-2.0

package landlock

import (
	"context"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// sourceRouteCases are setsockopt's level and option against the source-route arm (R11b): what it refuses, with the
// high halves of the 64-bit registers the kernel does not read, and what it leaves alone.
var sourceRouteCases = []struct {
	name          string
	level, option uint64
	want          uint32
}{
	{"IP_OPTIONS", unix.SOL_IP, unix.IP_OPTIONS, retEPERM},
	{"IP_OPTIONS, int truncation", uint64(1)<<32 | unix.SOL_IP, uint64(1)<<32 | unix.IP_OPTIONS, retEPERM},
	{"IPV6_RTHDR", unix.SOL_IPV6, unix.IPV6_RTHDR, retEPERM},
	{"IPV6_2292RTHDR", unix.SOL_IPV6, unix.IPV6_2292RTHDR, retEPERM},
	{"IPV6_2292PKTOPTIONS", unix.SOL_IPV6, unix.IPV6_2292PKTOPTIONS, retEPERM},
	{"IP_TTL", unix.SOL_IP, unix.IP_TTL, retAllow},
	{"IPV6_V6ONLY", unix.SOL_IPV6, unix.IPV6_V6ONLY, retAllow},
	{"IP_OPTIONS's number at SOL_IPV6", unix.SOL_IPV6, unix.IP_OPTIONS, retAllow},
	{"IPV6_RTHDR's number at SOL_IP", unix.SOL_IP, unix.IPV6_RTHDR, retAllow},
	{"SO_KEEPALIVE", unix.SOL_SOCKET, unix.SO_KEEPALIVE, retAllow},
	{"TCP_NODELAY", unix.SOL_TCP, unix.TCP_NODELAY, retAllow},
}

// preparedFilterOpts is the filterOpts Prepare builds at tier landlock for a contract with the given extra lines.
func preparedFilterOpts(t *testing.T, extra string) filterOpts {
	t.Helper()
	root := tempDir(t)
	mkTree(t, root, "work/", "home/", "config/")
	work := filepath.Join(root, "work")
	c, ds, err := agent.LoadBytes(filepath.Join(root, "config", "agent.yaml"),
		[]byte("version: 0\nname: route-filter\ncommand: [/bin/true]\nfs: {deny_read: []}\n"+extra), nil)
	if err != nil {
		t.Fatalf("load %v %v", err, ds)
	}
	rt, ds, err := agent.Compile(c, &config.Machine{}, agent.Offline(), agent.WithCwd(work),
		agent.WithHome(filepath.Join(root, "home")), agent.WithMountInfo(""), agent.WithTiers(backend.TierLandlock))
	if err != nil {
		t.Fatalf("compile %v %v", err, ds)
	}
	h, err := New(Options{syscalls: &fakeSyscalls{abi: 7}}).Prepare(context.Background(), rt, Run{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { h.Close() })
	return h.filterOpts
}

// checkSourceRouteArm runs every sourceRouteCases row through o's filter on both architectures: armed, each row's
// verdict; not, every row allowed.
func checkSourceRouteArm(t *testing.T, label string, o filterOpts, armed bool) {
	t.Helper()
	for _, arch := range []Arch{ArchX86_64, ArchARM64} {
		tab, err := tableFor(arch)
		if err != nil {
			t.Fatal(err)
		}
		for _, tc := range sourceRouteCases {
			want := tc.want
			if !armed {
				want = retAllow
			}
			if got := planeVerdict(t, arch, o, tab.Setsockopt, 3, tc.level, tc.option, 0x9876, 8); got != want {
				t.Errorf("%s %s setsockopt(%s) = %#x, want %#x", arch, label, tc.name, got, want)
			}
		}
		// The arm reloads the syscall number: a later notify arm still sees its own syscall.
		if got := planeVerdict(t, arch, o, tab.Notify[0].NR, 3, unix.SOL_IP, unix.IP_OPTIONS); got != retNotify {
			t.Errorf("%s %s: %s after the arm = %#x, want notify", arch, label, tab.Notify[0].Name, got)
		}
	}
}

// TestNetGateFilterRefusesSourceRouteOptions is ADR 0041 D6's source-route arm, on the filter Prepare builds from a
// compiled contract: when the gate scores `net` actions, setsockopt(IP_OPTIONS) and the IPv6 routing-header options
// are refused with EPERM on their scalar level and option, on both architectures. The supervisor's relay reads the
// socket's options before it connects or sends on the shared duplicate, but setsockopt was not trapped, so a
// sibling could add an LSRR/SSRR route or an IPv6 routing header between that read and the relayed call, and the
// first hop went to an address the gate never scored. A gate that scores no net action, and every other option,
// are left alone.
func TestNetGateFilterRefusesSourceRouteOptions(t *testing.T) {
	checkSourceRouteArm(t, "net gate", preparedFilterOpts(t, "gate:\n  rules:\n    - net to undeclared host: 90\n"), true)
	checkSourceRouteArm(t, "fs-only gate", preparedFilterOpts(t, "gate:\n  rules:\n    - 'fs.read matches \"*.env\"': 90\n"), false)
}

// TestNetSectionFilterRefusesSourceRouteOptions is GAPS C34's filter half: a run whose contract has a net: section
// gets the source-route arm with no gate at all. Before, only a net gate installed it, and under a net: section an
// admitted datagram the supervisor continues, or a connect it relays, left with whatever route the agent had set on
// the socket: the first hop went to an address in the route, which no entry admits and no tier decides (the
// supervisor and the root tiers' programs read the destination alone). A contract with neither a net: section nor a
// net gate decides no IP destination, and keeps the options.
func TestNetSectionFilterRefusesSourceRouteOptions(t *testing.T) {
	for _, tc := range []struct {
		name, extra string
		armed       bool
	}{
		{"a net: section", "net:\n  allow: [\"127.0.0.1:8080\"]\n", true},
		{"an empty net: section", "net: {}\n", true},
		{"no net: section", "", false},
		{"no net: section, host_sockets: true", "host_sockets: true\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := preparedFilterOpts(t, tc.extra)
			if o.sourceRoute != tc.armed {
				t.Fatalf("filterOpts.sourceRoute = %t, want %t", o.sourceRoute, tc.armed)
			}
			checkSourceRouteArm(t, tc.name, o, tc.armed)
		})
	}
}
