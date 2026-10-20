// SPDX-License-Identifier: Apache-2.0

//go:build integration && tegobpf

package cgroup

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"

	ebpfbindings "github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// approvalReapHelperEnv carries TestApprovalReapHelper's cgroup path, cgroup id and state directory.
const approvalReapHelperEnv = "TEGO_APPROVAL_REAP_HELPER"

// TestApprovalGrantsReapedWithTheirDeadLauncher is the reaper's half of the one-connect grants (supervisor R11c,
// enforce-cgroup-observe R7): a launcher killed with an abstract-name grant
// (tego_unix_approvals) and a TCP grant (tego_connect_approvals) of its slot in the pinned maps leaves them to the
// reaper, and PurgeRun, once the run's cgroup is gone, purges both with the slot and frees it. purgeDeadSlots loads
// the pinned maps itself, so a map left out of its list keeps a dead slot's rows; TestUnixApprovalRowsPurgedOnRealMaps
// calls purgeSlot on a live handle's maps, which hold every map, and could not see that. The TCP grants were left so.
// The slot's network-control config and counters (tego_net_control, tego_net_stats) and a net timeline row are
// written beside the grants and must go with them too: no other test reads those maps after
// the reaper.
func TestApprovalGrantsReapedWithTheirDeadLauncher(t *testing.T) {
	if !ebpfbindings.Available() {
		t.Skip("built without the compiled objects; add -tags tegobpf")
	}
	if err := checkBPFFS(DefaultBPFFS); err != nil {
		t.Skipf("%v", err)
	}
	requireBPFCaps(t)
	rel := fmt.Sprintf("/tego-it-askreap-%d", os.Getpid())
	full := filepath.Join("/sys/fs/cgroup", rel)
	if err := os.Mkdir(full, 0o755); err != nil {
		t.Skipf("cannot create a cgroup for the run at %s: %v", full, err)
	}
	t.Cleanup(func() { _ = os.Remove(full) })
	id, err := cgroupIDOfPath("/sys/fs/cgroup", rel)
	if err != nil {
		t.Fatalf("cgroup id: %v", err)
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	state := pinState(t)
	launcher := exec.Command(self, "-test.run=^TestApprovalReapHelper$")
	launcher.Env = append(os.Environ(), approvalReapHelperEnv+"="+strings.Join([]string{rel, strconv.FormatUint(id, 10), state}, "|"))
	if _, err := launcher.StdinPipe(); err != nil {
		t.Fatal(err)
	}
	stdout, err := launcher.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	launcher.Stderr = os.Stderr
	launcher.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	if err := launcher.Start(); err != nil {
		t.Fatalf("start the launcher: %v", err)
	}
	killed := false
	t.Cleanup(func() {
		if !killed {
			_ = launcher.Process.Kill()
		}
		_ = launcher.Wait()
	})
	line, err := bufio.NewReader(stdout).ReadString('\n')
	var slot, gen uint32
	if n, serr := fmt.Sscanf(strings.TrimSpace(line), "attached %d %d", &slot, &gen); serr != nil || n != 2 {
		t.Fatalf("the launcher did not attach the run: %q, %v", line, err)
	}

	hash := mustBPFHash(t)
	pins, err := newPinLayout(DefaultBPFFS, hash)
	if err != nil {
		t.Fatal(err)
	}
	pinned := func(name string) *ebpf.Map {
		m, err := ebpf.LoadPinnedMap(filepath.Join(pins.Maps, name), nil)
		if err != nil {
			t.Fatalf("the build's %s: %v", name, err)
		}
		t.Cleanup(func() { _ = m.Close() })
		return m
	}
	unixGrants, tcpGrants := pinned(ebpfbindings.MapUnixApprovals), pinned(ebpfbindings.MapConnectApprovals)
	uk, uv, err := ebpfbindings.UnixApproval(slot, gen, 0xdead, []byte("tego-it-askreap"), 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := unixGrants.Update(&uk, &uv, ebpf.UpdateAny); err != nil {
		t.Fatalf("write the launcher's unix grant: %v", err)
	}
	tk := ebpfbindings.ConnectApprovalKey{RunIdx: slot, Gen: gen, Cookie: 0xbeef, Family: unix.AF_INET, Proto: unix.IPPROTO_TCP, Port: 443}
	tv := ebpfbindings.ConnectCredit{Credit: 1, DeadlineNS: 1}
	if err := tcpGrants.Update(&tk, &tv, ebpf.UpdateAny); err != nil {
		t.Fatalf("write the launcher's TCP grant: %v", err)
	}
	// A UDP grant (GrantDatagram, supervisor R13d) shares the map and goes with the slot alike.
	uk4 := ebpfbindings.ConnectApprovalKey{RunIdx: slot, Gen: gen, Cookie: 0xbeef, Family: unix.AF_INET, Proto: unix.IPPROTO_UDP, Port: 53}
	if err := tcpGrants.Update(&uk4, &tv, ebpf.UpdateAny); err != nil {
		t.Fatalf("write the launcher's UDP grant: %v", err)
	}
	// The slot's network-control rows (populateNetworkControl's config and counters) and a net timeline row, which
	// purgeSlot purges with the grants: each map is the reaper's to load.
	controls, stats, timeline := pinned(ebpfbindings.MapNetControl), pinned(ebpfbindings.MapNetStats), pinned(ebpfbindings.MapNetTimeline)
	control := ebpfbindings.NetControl{Gen: gen, Connections: 1}
	if err := controls.Update(&slot, &control, ebpf.UpdateAny); err != nil {
		t.Fatalf("write the launcher's network-control row: %v", err)
	}
	var stat ebpfbindings.NetStats
	if err := stats.Update(&slot, &stat, ebpf.UpdateAny); err != nil {
		t.Fatalf("write the launcher's network counters: %v", err)
	}
	lk := ebpfbindings.NetTimelineKey{RunIdx: slot, Index: 1}
	lv := ebpfbindings.NetTimeline{Count: 1}
	if err := timeline.Update(&lk, &lv, ebpf.UpdateAny); err != nil {
		t.Fatalf("write the launcher's net timeline row: %v", err)
	}

	if err := launcher.Process.Kill(); err != nil {
		t.Fatalf("kill the launcher: %v", err)
	}
	killed = true
	_ = launcher.Wait()
	if err := os.Remove(full); err != nil {
		t.Fatalf("remove the run's cgroup: %v", err)
	}
	res, err := PurgeRun(PurgeOptions{StateDir: state, Hash: hash, RunID: "it-askreap", CgroupID: id})
	if err != nil {
		t.Fatalf("PurgeRun once the launcher and its cgroup are gone: %+v, %v", res, err)
	}
	if !slices.Contains(res.Slots, slot) {
		t.Fatalf("PurgeRun freed slots %v, not the dead launcher's %d", res.Slots, slot)
	}
	if err := unixGrants.Lookup(&uk, &uv); !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Errorf("the dead launcher's unix grant survived the reaper: %v", err)
	}
	if err := tcpGrants.Lookup(&tk, &tv); !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Errorf("the dead launcher's TCP grant survived the reaper: %v", err)
	}
	if err := tcpGrants.Lookup(&uk4, &tv); !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Errorf("the dead launcher's UDP grant survived the reaper: %v", err)
	}
	if err := controls.Lookup(&slot, &control); !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Errorf("the dead launcher's network-control row survived the reaper: %v", err)
	}
	if err := stats.Lookup(&slot, &stat); !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Errorf("the dead launcher's network counters survived the reaper: %v", err)
	}
	if err := timeline.Lookup(&lk, &lv); !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Errorf("the dead launcher's net timeline row survived the reaper: %v", err)
	}
}

// TestApprovalReapHelper is the launcher half of TestApprovalGrantsReapedWithTheirDeadLauncher: it prepares and
// attaches a run in the cgroup it is given, prints its slot and gen, and waits to be killed. It does nothing in a
// normal run.
func TestApprovalReapHelper(t *testing.T) {
	spec := os.Getenv(approvalReapHelperEnv)
	if spec == "" {
		t.Skip("helper process only")
	}
	f := strings.Split(spec, "|")
	id, _ := strconv.ParseUint(f[1], 10, 64)
	rt := &agent.RuleTable{Tier: backend.TierCgroup, Record: agent.RecordFull,
		Net: []agent.NetRule{{Raw: "unix:@tego-it-askreap", Proto: agent.ProtoUnix, UnixPath: "tego-it-askreap", Abstract: true,
			Verdict: agent.VerdictAllow, Static: true}}}
	b := New(Options{Machine: machineLinger(0), StateDir: f[2], Events: &sink{}})
	h, err := b.Prepare(context.Background(), rt, Run{ID: "it-askreap", Agent: "a", CgroupID: id, CgroupPath: f[0]})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if err := h.Attach(id); err != nil {
		t.Fatalf("Attach: %v", err)
	}
	fmt.Printf("attached %d %d\n", h.slot, h.gen)
	// Never returns normally: the test kills this process, which is the case under test.
	_, _ = os.Stdin.Read(make([]byte, 1))
}
