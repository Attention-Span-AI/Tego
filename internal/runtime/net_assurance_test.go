// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/runtime/enforce"
	"github.com/attention-span-ai/tego/internal/runtime/enforce/api"
	"github.com/attention-span-ai/tego/internal/runtime/launch"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

type networkHandle struct {
	fakeHandle
	g backend.NetworkGuarantees
}

func (h *networkHandle) NetworkGuarantees() backend.NetworkGuarantees { return h.g }

type networkBackend struct{ h *networkHandle }

func (b networkBackend) Tier() backend.Tier        { return backend.TierCgroup }
func (b networkBackend) Capabilities() backend.Set { return backend.Matrix(backend.TierCgroup) }
func (b networkBackend) Prepare(context.Context, *agent.RuleTable, enforce.RunRef) (api.Handle, error) {
	return b.h, nil
}

func TestKernelAssuranceRequiresCompleteRunProof(t *testing.T) {
	full := backend.NetworkGuarantees{TCPDestination: true, UDPDestination: true, UnixDestination: true, SocketImportsDenied: true, ListenersDenied: true, SocketFamilies: true}
	without := func(f func(*backend.NetworkGuarantees)) backend.NetworkGuarantees {
		g := full
		f(&g)
		return g
	}
	for _, tc := range []struct {
		name string
		g    backend.NetworkGuarantees
		ok   bool
	}{
		{"complete", full, true},
		{"no TCP", without(func(g *backend.NetworkGuarantees) { g.TCPDestination = false }), false},
		{"no UDP", without(func(g *backend.NetworkGuarantees) { g.UDPDestination = false }), false},
		{"no Unix even with no Unix entries", without(func(g *backend.NetworkGuarantees) { g.UnixDestination = false }), false},
		{"imports", without(func(g *backend.NetworkGuarantees) { g.SocketImportsDenied = false }), false},
		{"listeners", without(func(g *backend.NetworkGuarantees) { g.ListenersDenied = false }), false},
		// ADR 0018 PR 2 (A-0018-10): kernel assurance holds the run to the socket-family bound too.
		{"no socket-family hooks", without(func(g *backend.NetworkGuarantees) { g.SocketFamilies = false }), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &runner{rt: &agent.RuleTable{NetAssurance: agent.NetAssuranceKernel}, handle: &networkHandle{g: tc.g}}
			err := r.requireNetworkAssurance()
			if (err == nil) != tc.ok || err != nil && !errors.Is(err, ErrNetAssurance) {
				t.Fatalf("%v", err)
			}
		})
	}
	r := &runner{rt: &agent.RuleTable{NetAssurance: agent.NetAssuranceKernel}, handle: &fakeHandle{}}
	if !errors.Is(r.requireNetworkAssurance(), ErrNetAssurance) {
		t.Fatal("unreported mock/static tier claims kernel guarantee")
	}
}

func TestKernelAssuranceRefusesUnsupportedRequests(t *testing.T) {
	for _, tc := range []struct {
		name string
		rt   *agent.RuleTable
		tier backend.Tier
	}{
		{"Landlock port rights", &agent.RuleTable{NetAssurance: agent.NetAssuranceKernel}, backend.TierLandlock},
		{"observe", &agent.RuleTable{NetAssurance: agent.NetAssuranceKernel}, backend.TierObserve},
		{"io_uring", &agent.RuleTable{NetAssurance: agent.NetAssuranceKernel, Contract: &agent.Contract{Net: &agent.NetSection{}, IOUring: true}}, backend.TierCgroup},
		{"setuid", &agent.RuleTable{NetAssurance: agent.NetAssuranceKernel, Contract: &agent.Contract{Net: &agent.NetSection{}, Setuid: true}}, backend.TierCgroup},
		{"ICMP", &agent.RuleTable{NetAssurance: agent.NetAssuranceKernel, Net: []agent.NetRule{{Raw: "192.0.2.1:0", Proto: agent.ProtoInet}}}, backend.TierCgroup},
		{"Unix name too long", &agent.RuleTable{NetAssurance: agent.NetAssuranceKernel, Net: []agent.NetRule{{Raw: "unix:/x", Proto: agent.ProtoUnix, UnixPath: "/" + strings.Repeat("a", 108)}}}, backend.TierCgroup},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := validateNetworkRequest(tc.rt, Deps{Enforce: tierBackend{tier: tc.tier}}); !errors.Is(err, ErrNetAssurance) {
				t.Fatalf("%v", err)
			}
		})
	}
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	f := os.NewFile(uintptr(fds[0]), "socket")
	defer f.Close()
	defer unix.Close(fds[1])
	rt := &agent.RuleTable{NetAssurance: agent.NetAssuranceKernel}
	deps := Deps{Enforce: tierBackend{tier: backend.TierCgroup}, Stdio: Stdio{Out: f}}
	if err := validateNetworkRequest(rt, deps); !errors.Is(err, ErrNetAssurance) || !strings.Contains(err.Error(), "stdout is socket") {
		t.Fatalf("socket stdio: %v", err)
	}
	rt.NetAssurance = agent.NetAssuranceBestEffort
	if err := validateNetworkRequest(rt, deps); err != nil {
		t.Fatalf("best-effort changed: %v", err)
	}
	rt.NetAssurance = agent.NetAssuranceKernel
	f.Close()
	if err := validateNetworkRequest(rt, deps); !errors.Is(err, ErrNetAssurance) || !strings.Contains(err.Error(), "unknown") {
		t.Fatalf("unclassifiable stdio: %v", err)
	}
}

func TestRequestedNetworkControlsRequireActualRunProof(t *testing.T) {
	zero := uint64(0)
	bytes := agent.ByteSize(0)
	for _, tc := range []struct {
		name string
		rt   agent.RuleTable
		g    backend.NetworkGuarantees
	}{
		{"explicit empty ingress", agent.RuleTable{Ingress: []agent.IngressRuleCompiled{}}, backend.NetworkGuarantees{IngressSources: true}},
		{"zero bytes", agent.RuleTable{NetLimits: agent.NetworkLimits{Bytes: &bytes}}, backend.NetworkGuarantees{NetworkBytes: true}},
		{"zero datagrams", agent.RuleTable{NetLimits: agent.NetworkLimits{DatagramsPerSecond: &zero}}, backend.NetworkGuarantees{NetworkDatagrams: true}},
		{"zero connections", agent.RuleTable{NetLimits: agent.NetworkLimits{Connections: &zero}}, backend.NetworkGuarantees{NetworkConnections: true}},
		{"zero pending", agent.RuleTable{NetLimits: agent.NetworkLimits{PendingConnects: &zero}}, backend.NetworkGuarantees{NetworkPending: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &runner{rt: &tc.rt, handle: &networkHandle{}}
			if !errors.Is(r.requireNetworkAssurance(), ErrNetAssurance) {
				t.Fatal("requested control silently downgraded under best-effort destination assurance")
			}
			r.handle = &networkHandle{g: tc.g}
			if err := r.requireNetworkAssurance(); err != nil {
				t.Fatal(err)
			}
		})
	}
	full := backend.NetworkGuarantees{TCPDestination: true, UDPDestination: true, UnixDestination: true, SocketImportsDenied: true, ListenerBind: true, SocketFamilies: true}
	r := &runner{rt: &agent.RuleTable{NetAssurance: agent.NetAssuranceKernel, Listen: []agent.ListenRule{}}, handle: &networkHandle{g: full}}
	if err := r.requireNetworkAssurance(); err != nil {
		t.Fatalf("explicit listener controls still require client-only denial: %v", err)
	}
	full.ListenerBind = false
	full.ListenersDenied = true
	r.handle = &networkHandle{g: full}
	if !errors.Is(r.requireNetworkAssurance(), ErrNetAssurance) {
		t.Fatal("legacy listener-denied flag substitutes for explicit bind/listen proof")
	}
}

func TestMissingKernelAssuranceUnwindsBeforeChild(t *testing.T) {
	m, rt, root := startupFixture(t)
	rt.NetAssurance = agent.NetAssuranceKernel
	rt.Contract.Net = &agent.NetSection{}
	h := &networkHandle{}
	cg := &fakeCgroups{root: t.TempDir()}
	res, err := Run(context.Background(), rt, []string{"/bin/true"}, Deps{Config: m, Cgroups: cg, Enforce: networkBackend{h: h}, Cwd: root, Launcher: &launch.Launcher{Exe: filepath.Join(root, "must-never-start")}})
	if !errors.Is(err, ErrNetAssurance) || res.ExitCode != 125 {
		t.Fatalf("result %+v err %v", res, err)
	}
	if cg.created != 1 || cg.removed != 1 || h.closed != 1 || h.detached != 1 {
		t.Fatalf("cleanup cg=%+v handle=%+v", cg, h)
	}
	if left := leftBehind(t, filepath.Join(root, "runs")); len(left) != 0 {
		t.Fatalf("run state left: %v", left)
	}
}

func TestKernelAssuranceStdioAllowsOnlyOrdinaryStreams(t *testing.T) {
	root := t.TempDir()
	file, err := os.Create(filepath.Join(root, "out"))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	dir, err := os.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	device, err := os.Open("/dev/zero")
	if err != nil {
		t.Fatal(err)
	}
	defer device.Close()
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer read.Close()
	defer write.Close()
	fd, err := unix.Eventfd(0, unix.EFD_CLOEXEC)
	if err != nil {
		t.Fatal(err)
	}
	other := os.NewFile(uintptr(fd), "eventfd")
	defer other.Close()
	for _, tc := range []struct {
		name string
		file *os.File
		ok   bool
	}{
		{"default null", nil, true}, {"regular file", file, true}, {"pipe", write, true},
		{"directory", dir, false}, {"character device", device, false}, {"anonymous kernel descriptor", other, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rt := &agent.RuleTable{NetAssurance: agent.NetAssuranceKernel}
			deps := Deps{Enforce: tierBackend{tier: backend.TierCgroup}, Stdio: Stdio{Out: tc.file}}
			if err := validateNetworkRequest(rt, deps); (err == nil) != tc.ok {
				t.Fatalf("stdio=%s: %v want admitted=%v", tc.name, err, tc.ok)
			}
			rt.NetAssurance = agent.NetAssuranceBestEffort
			if err := validateNetworkRequest(rt, deps); err != nil {
				t.Fatalf("best-effort compatibility: %v", err)
			}
		})
	}
}

func TestNetworkCapabilityMetadataUsesAttachmentProof(t *testing.T) {
	r := newTestRunner(Deps{Enforce: tierBackend{tier: backend.TierCgroup, caps: backend.Matrix(backend.TierCgroup)}})
	r.rt = &agent.RuleTable{}
	r.handle = &networkHandle{g: backend.NetworkGuarantees{TCPDestination: true, UnixDestination: true, SocketImportsDenied: true, ListenersDenied: true}}
	line := r.capabilityLine("off")
	if !line[string(backend.CapTCPDestinationKernel)] || line[string(backend.CapUDPByDestination)] || !line[string(backend.CapUnixDestinationKernel)] {
		t.Fatalf("capabilities %v", line)
	}
	// The socket-family row is the run's attachments' too, never the tier column's (ADR 0018 PR 2).
	if line[string(backend.CapSocketFamilies)] {
		t.Fatalf("capabilities claim the socket-family bound with no attachment proof: %v", line)
	}
	g := r.networkGuaranteeLine()
	if !g["tcp"] || g["udp"] || !g["unix"] || !g["socket_imports_denied"] || !g["listeners_denied"] || g["socket_families"] {
		t.Fatalf("guarantees %v", g)
	}
	if _, ok := g["socket_families"]; !ok {
		t.Fatalf("run_start's net_guarantees has no socket_families key: %v", g)
	}
	r.handle = &networkHandle{g: backend.NetworkGuarantees{SocketFamilies: true}}
	if line := r.capabilityLine("off"); !line[string(backend.CapSocketFamilies)] {
		t.Fatalf("capabilities %v", line)
	}
	if g := r.networkGuaranteeLine(); !g["socket_families"] {
		t.Fatalf("guarantees %v", g)
	}
}
