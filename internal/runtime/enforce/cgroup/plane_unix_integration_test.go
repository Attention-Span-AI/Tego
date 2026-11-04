// SPDX-License-Identifier: Apache-2.0

//go:build integration && tegobpf

package cgroup

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"

	ebpfbindings "github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/internal/policy/decide"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// TestPlaneUnixVerdictOnRealKernel is enforce-plane R14 through the backend (TIER3-PLAN T15): a tier-cgroup run in a
// plane mode on a kernel without cgroup/connect_unix (below 6.7) has its unix names decided by the plane's
// socket_connect and socket_sendmsg, from the rows and by the rule connect_unix uses on 6.7+, so
// TestUnixVerdictOnRealKernel's cells hold with EACCES where they hold with EPERM there: the agent's own connects and
// datagrams, the supervisor's /proc/self/fd relay from this launcher's cgroup, and the same name from any other.
// On 6.7+ the test answers the load's probe of BPF_CGROUP_UNIX_CONNECT as a kernel below 6.7 does, so the cells
// run the plane's hooks on every kernel; where the probe really answers so, the backend chose them unaided.
func TestPlaneUnixVerdictOnRealKernel(t *testing.T) {
	_, dir, u := planeUnixRun(t, "plane")
	unixKernelCells(t, dir, u, unix.EACCES)
}

// planeUnixRun is a prepared, attached and armed tier-cgroup run in the host's plane mode whose unix names the
// plane's socket_connect and socket_sendmsg decide (connect_unix withheld on 6.7+), over newUnixFixture(tag)'s
// table, with its cgroup directory open.
func planeUnixRun(t *testing.T, tag string) (*Handle, *os.File, *unixFixture) {
	return planeUnixRunWith(t, tag, nil)
}

func planeUnixRunWith(t *testing.T, tag string, configure func(*unixFixture, *agent.RuleTable)) (*Handle, *os.File, *unixFixture) {
	t.Helper()
	requireBPFCaps(t)
	if _, err := bpfHash(); err != nil {
		t.Skipf("this test binary carries no BPF objects: %v", err)
	}
	mode, build := hostPlane(t)
	if ok, err := unixConnectSupported(); err == nil && ok {
		was := unixConnectSupported
		unixConnectSupported = func() (bool, error) { return false, nil }
		t.Cleanup(func() { unixConnectSupported = was })
		t.Logf("this kernel has cgroup/connect_unix; the build is loaded as below 6.7, without it")
	}
	u := newUnixFixture(t, tag)
	rt := u.table()
	rt.Contract = &agent.Contract{Net: &agent.NetSection{}} // a net: section, and no exec: section
	if configure != nil {
		configure(u, rt)
	}
	rows, err := decide.CompilePlane(rt)
	if err != nil {
		t.Fatal(err)
	}
	hash := fmt.Sprintf("t15%s%09d", tag, os.Getpid())
	b := New(Options{Machine: machineLinger(0), BPFFS: DefaultBPFFS, StateDir: pinState(t), Hash: hash,
		Events: &sink{}, Plane: PlaneSetup{Mode: mode, Build: build}})
	held := maps.Clone(holdPaths(t, rows.Keyed...))
	parents := heldSet{}
	for _, n := range rows.Protected {
		dedicated := holdPaths(t, n.Parent)
		parents[n.Path] = dedicated[n.Parent]
	}
	b.opts.planeHeld = held.held
	b.opts.Inherit = func(context.Context, *agent.RuleTable, Run) (Inherited, error) {
		return unixPeerParents{parents}, nil
	}
	t.Cleanup(func() {
		if pins, err := newPinLayout(DefaultBPFFS, hash); err == nil {
			_ = pins.remove()
		}
	})
	rel, _, id := runCgroupUnderSelf(t, "unix"+tag)
	h, err := b.Prepare(context.Background(), rt, Run{ID: "t15-unix-" + tag, Agent: "a", CgroupID: id, CgroupPath: rel,
		CgroupMount: "/sys/fs/cgroup", PlaneRows: rows})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	t.Cleanup(func() {
		if err := h.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	if dp, why := h.PlaneChoice(); dp != string(mode) {
		t.Fatalf("the run decides in %s (%v), want the plane's %s mode", dp, why, mode)
	}
	if _, ok := h.kern.(*bpfKernel).progs[ebpfbindings.ProgConnectUnix]; ok {
		t.Fatal("connect_unix was loaded: the plane's unix hooks would decide every name a second time")
	}
	if !h.plane.decidesUnix() {
		t.Fatal("the plane did not load its unix hooks where connect_unix is absent")
	}
	if err := h.Attach(id); err != nil {
		t.Fatalf("Attach: %v", err)
	}
	if err := h.Arm(); err != nil {
		t.Fatalf("Arm: %v", err)
	}
	dir, err := os.Open(filepath.Join("/sys/fs/cgroup", rel))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = dir.Close() })
	return h, dir, u
}

// unixPeerParents supplies the dedicated parent-descriptor channel used by
// fillPlane; this direct-kernel fixture deliberately installs no agent filters.
type unixPeerParents struct{ parents heldSet }

func (unixPeerParents) LandlockRuleset() (int, bool)                { return -1, false }
func (unixPeerParents) SeccompFilter() ([]bpf.RawInstruction, bool) { return nil, false }
func (p unixPeerParents) PlaneListenParent(path string) (int, bool) { return p.parents.held(path) }

// No seccomp supervisor participates: an address accepted by the raw-name
// programs must still be refused on the actual native datagram peer.
func TestRootBuiltinRefusalsPeer(t *testing.T) {
	_, dir, u := planeUnixRunWith(t, "peer", func(u *unixFixture, rt *agent.RuleTable) {
		rt.FS = rt.FS[:1]
		ledger := filepath.Join(u.base, "ledger")
		if err := os.Mkdir(ledger, 0o755); err != nil {
			t.Fatal(err)
		}
		receiveUnixgram(t, filepath.Join(ledger, "ask.sock"))
		receiveUnixgram(t, filepath.Join(ledger, "ordinary.sock"))
		if err := os.Symlink(filepath.Join(ledger, "ask.sock"), filepath.Join(u.work, "ledger.dg")); err != nil {
			t.Fatal(err)
		}
		rt.Contract = &agent.Contract{HostSockets: true}
		rt.Builtins = &agent.BuiltinRefusals{Ledger: ledger, Runtime: []string{u.secret},
			Names:     []agent.BuiltinName{{Path: "builtin:peer", Parent: u.work, Name: "secret", Target: u.secret}},
			PeerNames: []agent.BuiltinName{{Path: "builtin-peer:ssh", Parent: u.secret, Name: "ssh-agent.socket"}}}
		rt.DenyWrite = []agent.FSRule{{Path: u.secret, Resolved: u.secret, Kind: agent.FSDenyWrite, BuiltinRule: agent.BuiltinHostIPC}}
		receiveUnixgram(t, filepath.Join(u.secret, "ssh-agent.socket"))
		for _, pair := range [][2]string{{u.secretDgram, filepath.Join(u.work, "hard.dg")}} {
			if err := os.Link(pair[0], pair[1]); err != nil {
				t.Fatal(err)
			}
		}
		receiveUnixgram(t, filepath.Join(u.secret, "nolink.dg"))
		if err := os.Symlink(filepath.Join(u.secret, "nolink.dg"), filepath.Join(u.work, "sym.dg")); err != nil {
			t.Fatal(err)
		}
		// Every name is explicitly allowed, including both aliases. The built-in
		// refusal must win on the bound inode, after the raw-name programs allow.
		for _, p := range []string{u.secretDgram, filepath.Join(u.work, "hard.dg"), filepath.Join(u.work, "sym.dg"), filepath.Join(u.secret, "ssh-agent.socket"), filepath.Join(u.work, "ledger.dg"), filepath.Join(ledger, "ask.sock"), filepath.Join(ledger, "ordinary.sock")} {
			rt.Net = append(rt.Net, agent.NetRule{Proto: agent.ProtoUnix, UnixPath: p, Verdict: agent.VerdictAllow, Static: true})
		}
	})
	ops := []string{"sendto " + u.secretDgram, "sendto " + filepath.Join(u.work, "hard.dg"), "sendto " + filepath.Join(u.work, "sym.dg"),
		"sendto hard.dg", "sendto /proc/" + fmt.Sprint(os.Getpid()) + "/root" + u.secretDgram,
		"sendto " + filepath.Join(u.work, "ledger.dg"), "sendto " + filepath.Join(u.base, "ledger/ask.sock"),
		"sendto " + filepath.Join(u.secret, "ssh-agent.socket"), "sendto " + u.workDgram, "sendto " + filepath.Join(u.base, "ledger/ordinary.sock")}
	got := runUnixHelper(t, dir, u.work, ops)
	for i, err := range got {
		if i < len(ops)-3 {
			if !errors.Is(err, unix.EACCES) && !errors.Is(err, unix.EPERM) {
				t.Errorf("%s: %v, want native refusal", ops[i], err)
			}
		} else if err != nil {
			t.Errorf("%s: %v", ops[i], err)
		}
	}
	rootBuiltinNameWidths(t)
}

// Replacing the protected directory after Prepare leaves its old inode pinned.
// Only the configured parent/name can refuse the new directory's peer. The raw
// socket spelling is an explicitly allowed short alias, so it cannot pass this
// test by matching the protected prefix or the old directory's FS row.
func rootBuiltinNameWidths(t *testing.T) {
	for _, width := range []int{7, 8, 9, 63, 64, 65, 107} {
		t.Run(fmt.Sprintf("name-bytes-%d", width), func(t *testing.T) {
			var protected string
			_, dir, u := planeUnixRunWith(t, fmt.Sprintf("p%03d", width), func(u *unixFixture, rt *agent.RuleTable) {
				protected = filepath.Join(u.work, strings.Repeat("p", width))
				if err := os.Mkdir(protected, 0o755); err != nil {
					t.Fatal(err)
				}
				configured := protected
				if width == 107 {
					configured = filepath.Join(u.work, "configured")
					if err := os.Symlink(protected, configured); err != nil {
						t.Fatal(err)
					}
				}
				rt.FS = rt.FS[:1]
				rt.Contract = &agent.Contract{HostSockets: true}
				rt.Builtins = &agent.BuiltinRefusals{Runtime: []string{configured, protected}, Names: []agent.BuiltinName{{
					Path: "builtin:" + configured, Parent: u.work, Name: filepath.Base(configured), Target: protected,
				}}}
				rt.DenyWrite = []agent.FSRule{{Path: protected, Resolved: protected, Kind: agent.FSDenyWrite, BuiltinRule: agent.BuiltinHostIPC}}
				rt.Net = []agent.NetRule{{Proto: agent.ProtoUnix, UnixPath: filepath.Join(u.work, "alias.dg"), Verdict: agent.VerdictAllow, Static: true},
					{Proto: agent.ProtoUnix, UnixPath: u.workDgram, Verdict: agent.VerdictAllow, Static: true}}
			})
			if err := os.Rename(protected, protected+".old"); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(protected, 0o755); err != nil {
				t.Fatal(err)
			}
			fd, err := unix.Open(protected, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = unix.Close(fd) })
			// The proc spelling fits sun_path even for a 107-byte ancestor.
			receiveUnixgram(t, fmt.Sprintf("/proc/self/fd/%d/dg", fd))
			alias := filepath.Join(u.work, "alias.dg")
			if err := os.Symlink(filepath.Join(protected, "dg"), alias); err != nil {
				t.Fatal(err)
			}
			got := runUnixHelper(t, dir, u.work, []string{"sendto " + alias, "sendto " + u.workDgram})
			if !errors.Is(got[0], unix.EACCES) && !errors.Is(got[0], unix.EPERM) {
				t.Errorf("%d-byte protected name through alias: %v, want native refusal", width, got[0])
			}
			if got[1] != nil {
				t.Errorf("ordinary peer: %v", got[1])
			}
		})
	}
}
