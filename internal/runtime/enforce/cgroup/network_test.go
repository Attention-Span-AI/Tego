// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"testing"

	netbpf "golang.org/x/net/bpf"
	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

func TestNetworkGuaranteesRequireActualCompleteAttachments(t *testing.T) {
	keys := []string{bpf.ProgConnect4, bpf.ProgConnect6, bpf.ProgSendmsg4, bpf.ProgSendmsg6, bpf.ProgConnectUnix, bpf.ProgSendmsgUnix}
	full := map[string]bool{}
	for _, k := range keys {
		full[k] = true
	}
	for _, missing := range append([]string{""}, keys...) {
		a := map[string]bool{}
		for k, v := range full {
			a[k] = v
		}
		delete(a, missing)
		k := &bpfKernel{netAttached: a}
		g := k.networkGuarantees()
		wantTCP := missing != bpf.ProgConnect4 && missing != bpf.ProgConnect6
		wantUDP := wantTCP && missing != bpf.ProgSendmsg4 && missing != bpf.ProgSendmsg6
		wantUnix := missing != bpf.ProgConnectUnix && missing != bpf.ProgSendmsgUnix
		if g.TCPDestination != wantTCP || g.UDPDestination != wantUDP || g.UnixDestination != wantUnix {
			t.Fatalf("missing %q: %+v", missing, g)
		}
	}
	if g := (&bpfKernel{}).networkGuarantees(); g != (backend.NetworkGuarantees{}) {
		t.Fatalf("loaded/no links: %+v", g)
	}
	for _, attached := range []map[string]bool{nil, {"socket_connect": true}, {"socket_connect": true, "socket_sendmsg": true}} {
		h := &Handle{prepared: true, kern: &bpfKernel{}, plane: &fakePlane{unix: true, attached: attached}}
		g := h.NetworkGuarantees()
		if g.UnixDestination != (attached["socket_connect"] && attached["socket_sendmsg"]) {
			t.Fatalf("plane hooks %v: %+v", attached, g)
		}
		h.detached = true
		if h.NetworkGuarantees() != (backend.NetworkGuarantees{}) {
			t.Fatal("detached handle claims coverage")
		}
	}
}

// guaranteeInherited is an inherited tier-1 state that reports its network guarantees, as enforce/landlock's
// handle does.
type guaranteeInherited struct{ g backend.NetworkGuarantees }

func (guaranteeInherited) LandlockRuleset() (int, bool)                   { return -1, false }
func (guaranteeInherited) SeccompFilter() ([]netbpf.RawInstruction, bool) { return nil, false }
func (i guaranteeInherited) NetworkGuarantees() backend.NetworkGuarantees { return i.g }

// TestSocketFamiliesNeedTheFilterAndAKernelBackstop is ADR 0018's guarantee at tier cgroup (§5 R4): every socket
// the run makes, or turns another into, is one the allowlist admits. Without io_uring the inherited filter's socket
// arm decides socket(2) and socketpair(2) for every family, and setsockopt(2)'s TCP_ULP, and cgroup/sock_create every
// inet socket on any path; with io_uring admitted only the plane's socket_create sees an IORING_OP_SOCKET, of every
// family. Either way cgroup/setsockopt has to be attached: it alone sees io_uring's SOCKET_URING_OP_SETSOCKOPT, whose
// TCP_ULP "smc" turned an admitted TCP socket into AF_SMC in place (ADR 0018 (7)). A contract with no
// net: section bounds no socket (SEMANTICS §1), whatever is loaded.
func TestSocketFamiliesNeedTheFilterAndAKernelBackstop(t *testing.T) {
	sockCreate := map[string]bool{bpf.ProgConnect4: true, bpf.ProgConnect6: true, bpf.ProgSockCreate: true,
		bpf.ProgSetsockopt: true}
	noSockCreate := map[string]bool{bpf.ProgConnect4: true, bpf.ProgConnect6: true, bpf.ProgSetsockopt: true}
	noSetsockopt := map[string]bool{bpf.ProgConnect4: true, bpf.ProgConnect6: true, bpf.ProgSockCreate: true}
	planeSC := &fakePlane{attached: map[string]bool{"socket_create": true}}
	restricted := &agent.RuleTable{}
	open := &agent.RuleTable{Contract: &agent.Contract{}}
	for _, tc := range []struct {
		name      string
		inherited Inherited
		attached  map[string]bool
		plane     *fakePlane
		table     *agent.RuleTable
		want      bool
	}{
		{"filter arm and sock_create", guaranteeInherited{backend.NetworkGuarantees{SocketFamilies: true}}, sockCreate, nil, restricted, true},
		{"filter arm, sock_create not attached", guaranteeInherited{backend.NetworkGuarantees{SocketFamilies: true}}, noSockCreate, nil, restricted, false},
		{"sock_create with no filter arm", guaranteeInherited{}, sockCreate, nil, restricted, false},
		{"sock_create with no inherited state", nil, sockCreate, nil, restricted, false},
		{"io_uring admitted, the plane's socket_create", guaranteeInherited{}, sockCreate, planeSC, restricted, true},
		{"io_uring admitted, a plane without socket_create", guaranteeInherited{}, sockCreate, &fakePlane{}, restricted, false},
		{"filter arm, setsockopt not attached", guaranteeInherited{backend.NetworkGuarantees{SocketFamilies: true}}, noSetsockopt, nil, restricted, false},
		{"io_uring admitted, the plane's socket_create, setsockopt not attached", guaranteeInherited{}, noSetsockopt, planeSC, restricted, false},
		{"no net: section", guaranteeInherited{backend.NetworkGuarantees{SocketFamilies: true}}, sockCreate, planeSC, open, false},
	} {
		h := &Handle{prepared: true, kern: &bpfKernel{netAttached: tc.attached}, inherited: tc.inherited, table: tc.table}
		if tc.plane != nil {
			h.plane = tc.plane
		}
		if got := h.NetworkGuarantees().SocketFamilies; got != tc.want {
			t.Errorf("%s: SocketFamilies = %v, want %v", tc.name, got, tc.want)
		}
		if got := h.Capabilities().Has(backend.CapSocketFamilies); got != tc.want {
			t.Errorf("%s: the capability row = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// TestKernelDatagramsNameTheRefusingProgram is §5 R7's errno half for the supervisor (Handle.KernelDatagrams): EPERM
// for a unix name where cgroup/sendmsg_unix is attached, EACCES where only the plane's step-D hooks decide unix
// names, EPERM for UDP where sendmsg4 and sendmsg6 are attached, and 0 for a family nothing decides, for a contract
// with no net: section and for a handle that is detached.
func TestKernelDatagramsNameTheRefusingProgram(t *testing.T) {
	all := map[string]bool{}
	for _, k := range []string{bpf.ProgConnect4, bpf.ProgConnect6, bpf.ProgSendmsg4, bpf.ProgSendmsg6, bpf.ProgConnectUnix, bpf.ProgSendmsgUnix} {
		all[k] = true
	}
	inetOnly := map[string]bool{bpf.ProgConnect4: true, bpf.ProgConnect6: true, bpf.ProgSendmsg4: true, bpf.ProgSendmsg6: true}
	stepD := &fakePlane{unix: true, attached: map[string]bool{"socket_connect": true, "socket_sendmsg": true}}
	for _, tc := range []struct {
		name          string
		attached      map[string]bool
		plane         *fakePlane
		unrestricted  bool
		wantU, wantUD unix.Errno
	}{
		{"sendmsg_unix and sendmsg4/6", all, nil, false, unix.EPERM, unix.EPERM},
		{"step D below 6.7", inetOnly, stepD, false, unix.EACCES, unix.EPERM},
		{"the fanotify fallback below 6.7", inetOnly, nil, false, 0, unix.EPERM},
		{"a plane whose unix hooks are not attached", inetOnly, &fakePlane{unix: true}, false, 0, unix.EPERM},
		{"no program attached", nil, nil, false, 0, 0},
		{"no net: section", all, nil, true, 0, 0},
	} {
		h := &Handle{prepared: true, kern: &bpfKernel{netAttached: tc.attached}}
		if tc.plane != nil {
			h.plane = tc.plane
		}
		h.rules.Unrestricted = tc.unrestricted
		if u, d := h.KernelDatagrams(); u != tc.wantU || d != tc.wantUD {
			t.Errorf("%s: KernelDatagrams = %v, %v; want %v, %v", tc.name, u, d, tc.wantU, tc.wantUD)
		}
		h.detached = true
		if u, d := h.KernelDatagrams(); u != 0 || d != 0 {
			t.Errorf("%s: a detached handle answers %v, %v", tc.name, u, d)
		}
	}
}
