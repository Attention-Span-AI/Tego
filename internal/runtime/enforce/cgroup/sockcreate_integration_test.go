// SPDX-License-Identifier: Apache-2.0

//go:build integration

package cgroup

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sys/unix"

	ebpfbindings "github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// ADR 0018 PR 2's attach cells (docs/p0/enforce-cgroup-observe.md §5 R4, R5; v73 roadmap SOCK-ATTACH): a tier-2 run's
// Attach puts cgroup/sock_create on the run's cgroup beside the CGROUP_SOCK_ADDR programs, pins it with them, and
// writes the owner storage it reads its run from (the ping flag and the generation). The helpers are this test binary
// re-executed into the run's cgroup with no seccomp filter, which stands for any path to inet_create the filter
// misses; the program's own internal/bpf cells hold its C to ADR 0018 (1)'s table, these hold the run's wiring.

// sockTriple is one socket(2): family, type and protocol as the kernel takes them.
type sockTriple struct{ family, typ, protocol int32 }

const (
	ipprotoSCTP, ipprotoUDPLite, ipprotoMPTCP, ipprotoSMC = 132, 136, 262, 256
	afVsock                                               = 40
)

func (c sockTriple) String() string { return fmt.Sprintf("%d/%d/%d", c.family, c.typ, c.protocol) }

func parseSockTriple(s string) (sockTriple, error) {
	var c sockTriple
	_, err := fmt.Sscanf(s, "%d/%d/%d", &c.family, &c.typ, &c.protocol)
	return c, err
}

// create makes the socket and closes it, and returns socket(2)'s error.
func (c sockTriple) create() error {
	fd, err := unix.Socket(int(c.family), int(c.typ)|unix.SOCK_CLOEXEC, int(c.protocol))
	if err == nil {
		_ = unix.Close(fd)
	}
	return err
}

func (c sockTriple) inet() bool { return c.family == unix.AF_INET || c.family == unix.AF_INET6 }

// sockCells are the protocols ADR 0018 names as outside the rules (SCTP stream and seqpacket, UDP-Lite, MPTCP 262,
// IPPROTO_SMC 256), what it admits (TCP and UDP with protocol 0 and spelled out, ping sockets with an ICMP entry),
// and families the program never sees (unix, netlink, AF_VSOCK: the residual of ADR 0018 (5)).
func sockCells() []sockTriple {
	var cells []sockTriple
	for _, f := range []int32{unix.AF_INET, unix.AF_INET6} {
		cells = append(cells,
			sockTriple{f, unix.SOCK_STREAM, 0}, sockTriple{f, unix.SOCK_STREAM, unix.IPPROTO_TCP},
			sockTriple{f, unix.SOCK_DGRAM, 0}, sockTriple{f, unix.SOCK_DGRAM, unix.IPPROTO_UDP},
			sockTriple{f, unix.SOCK_STREAM, ipprotoSCTP}, sockTriple{f, unix.SOCK_SEQPACKET, ipprotoSCTP},
			sockTriple{f, unix.SOCK_DGRAM, ipprotoUDPLite}, sockTriple{f, unix.SOCK_STREAM, ipprotoMPTCP},
			sockTriple{f, unix.SOCK_STREAM, ipprotoSMC})
	}
	return append(cells,
		sockTriple{unix.AF_INET, unix.SOCK_DGRAM, unix.IPPROTO_ICMP}, sockTriple{unix.AF_INET6, unix.SOCK_DGRAM, unix.IPPROTO_ICMPV6},
		sockTriple{unix.AF_UNIX, unix.SOCK_STREAM, 0}, sockTriple{unix.AF_UNIX, unix.SOCK_DGRAM, 0},
		sockTriple{unix.AF_NETLINK, unix.SOCK_RAW, 0}, sockTriple{afVsock, unix.SOCK_STREAM, 0})
}

// refusable is the first triple of protocols the program refuses that this kernel creates outside every run, or
// false: a kernel without SCTP, UDP-Lite, MPTCP and SMC leaves the program nothing to refuse.
func refusable() (sockTriple, bool) {
	for _, c := range []sockTriple{{unix.AF_INET, unix.SOCK_DGRAM, ipprotoUDPLite}, {unix.AF_INET, unix.SOCK_STREAM, ipprotoMPTCP},
		{unix.AF_INET, unix.SOCK_STREAM, ipprotoSCTP}, {unix.AF_INET, unix.SOCK_STREAM, ipprotoSMC}} {
		if c.create() == nil {
			return c, true
		}
	}
	return sockTriple{}, false
}

func targetsOf(cells []sockTriple) []string {
	out := make([]string, len(cells))
	for i, c := range cells {
		out[i] = c.String()
	}
	return out
}

// openPingSockets opens ping sockets to every group for the test (net.ipv4.ping_group_range), so a ping cell reaches
// inet_create's hook rather than ping_init_sock's own EACCES; it reports whether it could.
func openPingSockets(t *testing.T) bool {
	t.Helper()
	const pingRange = "/proc/sys/net/ipv4/ping_group_range"
	old, err := os.ReadFile(pingRange)
	if err != nil {
		return false
	}
	if err := os.WriteFile(pingRange, []byte("0 2147483647"), 0); err != nil {
		t.Logf("ping sockets stay closed here (%v): the ping cells take the kernel's own refusal", err)
		return false
	}
	t.Cleanup(func() { _ = os.WriteFile(pingRange, old, 0) })
	return true
}

// sockRing reads the run's own ring at its slot (runRing), drained of what an earlier run at the slot left in it.
func sockRing(t *testing.T, h *Handle) *ringbuf.Reader {
	t.Helper()
	rd, err := ringbuf.NewReader(runRing(t, h))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rd.Close() })
	for {
		rd.SetDeadline(time.Now().Add(50 * time.Millisecond))
		if _, err := rd.Read(); err != nil {
			return rd
		}
	}
}

// sockRecords reads the run's sock_create records of its own generation until the ring is quiet, and expects n of
// them. A record of another kind is skipped: the program's records are what this counts.
func sockRecords(t *testing.T, h *Handle, rd *ringbuf.Reader, n int) []ebpfbindings.SockEvent {
	t.Helper()
	var out []ebpfbindings.SockEvent
	for {
		wait := 2 * time.Second
		if len(out) >= n {
			wait = 200 * time.Millisecond
		}
		rd.SetDeadline(time.Now().Add(wait))
		rec, err := rd.Read()
		if errors.Is(err, os.ErrDeadlineExceeded) {
			break
		}
		if err != nil {
			t.Fatalf("read the run's ring: %v", err)
		}
		hdr, err := ebpfbindings.DecodeHeader(rec.RawSample)
		if err != nil {
			t.Fatalf("a record on the run's ring: %v", err)
		}
		if hdr.Gen != h.gen {
			continue // an earlier run's at this slot
		}
		if ebpfbindings.Kind(hdr.Kind) != ebpfbindings.KindSockCreate {
			continue
		}
		e, err := ebpfbindings.Decode[ebpfbindings.SockEvent](rec.RawSample)
		if err != nil {
			t.Fatalf("a sock_create record: %v", err)
		}
		out = append(out, e)
	}
	if len(out) != n {
		t.Errorf("%d sock_create records of the run's generation, want %d: %+v", len(out), n, out)
	}
	return out
}

// wantSockRecord checks one refusal's record: the attachment's run (its cgroup, slot and generation), never the
// caller's, and the triple as the kernel holds it.
func wantSockRecord(t *testing.T, e ebpfbindings.SockEvent, h *Handle, id uint64, c sockTriple) {
	t.Helper()
	hd := e.Hdr
	if ebpfbindings.Verdict(hd.Verdict) != ebpfbindings.VerdictRefused || ebpfbindings.ReasonCode(hd.Reason) != ebpfbindings.ReasonNetNotAllowed ||
		hd.RunIdx != h.Slot() || hd.Gen != h.gen || hd.CgroupID != id {
		t.Errorf("%s: header %+v; want refused net-not-allowed for slot %d gen %d cgroup %d", c, hd, h.Slot(), h.gen, id)
	}
	if e.Family != c.family || e.Type != c.typ || e.Protocol != c.protocol {
		t.Errorf("record names %d/%d/%d, want %s", e.Family, e.Type, e.Protocol, c)
	}
}

// inetRule allows one loopback port; port 0 is SEMANTICS §5's ICMP destination, which admits ping sockets.
func inetRule(port int) agent.NetRule {
	return agent.NetRule{Raw: fmt.Sprintf("127.0.0.1:%d", port), Port: port, Proto: agent.ProtoInet, Verdict: agent.VerdictAllow,
		IPs: []netip.Addr{netip.MustParseAddr("127.0.0.1")}, Static: true}
}

// TestSockCreateIsAttachedAndRefusesOutsideTheAllowlist is the run's half of ADR 0018 PR 2: Attach attaches and pins
// cgroup/sock_create with the run's links and writes the owner's ping flag and generation, so every inet socket of
// the run outside the allowlist is the kernel's EPERM with exactly one record on the run's own ring, stamped with the
// run's slot, generation and cgroup: SCTP, UDP-Lite, MPTCP 262 (not TCP: the whole protocol is compared) and SMC 256
// (not protocol 0) wherever this kernel has them. TCP and UDP are made; a ping socket only with an ICMP entry; unix,
// netlink and AF_VSOCK answer as they do outside (the residual the program cannot see). Attach pins
// cgroup/setsockopt too (ADR 0018 (7)), so TCP_ULP of any name, "smc" and "tls" among them, is EPERM with one
// record naming it, and the socket stays AF_INET.
func TestSockCreateIsAttachedAndRefusesOutsideTheAllowlist(t *testing.T) {
	requireRealPrepare(t) // here, not in the subtests' realRun, so a build without the objects skips this test alone
	ping := openPingSockets(t)
	for _, icmp := range []bool{false, true} {
		t.Run(fmt.Sprintf("icmp=%v", icmp), func(t *testing.T) {
			rules := []agent.NetRule{inetRule(443)}
			if icmp {
				rules = append(rules, inetRule(0))
			}
			rt := &agent.RuleTable{Net: rules, Tier: backend.TierCgroup, Record: agent.RecordFull}
			h, dir, id := realRun(t, fmt.Sprintf("sockcreate-%v", icmp), rt)

			k := h.kern.(*bpfKernel)
			var owner ebpfbindings.NetOwner
			if err := k.maps[ebpfbindings.MapNetOwners].Lookup(&id, &owner); err != nil {
				t.Fatalf("the run's owner storage: %v", err)
			}
			wantFlags := uint32(0)
			if icmp {
				wantFlags = ebpfbindings.NetOwnerICMP
			}
			if owner.CgroupID != id || owner.RunIdx != h.Slot() || owner.Gen != h.gen || owner.Gen == 0 || owner.Flags != wantFlags {
				t.Fatalf("owner storage %+v; want cgroup %d slot %d gen %d flags %#x", owner, id, h.Slot(), h.gen, wantFlags)
			}
			if !k.netAttached[ebpfbindings.ProgSockCreate] || !h.programGuarantees().SocketFamilies {
				t.Fatalf("cgroup/sock_create is not among the run's attachments: %v", k.netAttached)
			}
			for _, name := range ebpfbindings.SocketPrograms {
				if !k.netAttached[name] {
					t.Fatalf("%s is not among the run's attachments: %v", name, k.netAttached)
				}
				if _, err := os.Stat(filepath.Join(k.runLinks, name)); err != nil {
					t.Fatalf("the %s link is not pinned with the run's links: %v", name, err)
				}
			}

			rd := sockRing(t, h)
			cells := sockCells()
			got := runNetHelper(t, dir, "socket", targetsOf(cells))
			var refused []sockTriple
			named := map[int32]bool{}
			for i, c := range cells {
				outside := c.create()
				switch {
				case outside != nil || !c.inet():
					if errnoOf(got[i]) != errnoOf(outside) {
						t.Errorf("%s: %v inside the run, %v outside: the program cannot have decided it", c, got[i], outside)
					}
				case ebpfbindings.SocketAllowed(c.family, c.typ, c.protocol, icmp):
					if got[i] != nil {
						t.Errorf("%s: %v, the allowlist admits it", c, got[i])
					}
				default:
					if !errors.Is(got[i], unix.EPERM) {
						t.Errorf("%s: %v, want EPERM from cgroup/sock_create", c, got[i])
						continue
					}
					refused = append(refused, c)
					named[c.protocol] = true
				}
			}
			recs := sockRecords(t, h, rd, len(refused))
			for i := range recs {
				if i < len(refused) {
					wantSockRecord(t, recs[i], h, id, refused[i])
				}
			}
			if len(refused) == 0 {
				t.Fatal("this kernel created none of SCTP, UDP-Lite, MPTCP and SMC outside the run: nothing was refused")
			}
			var lacks []string
			for _, p := range []struct {
				n    int32
				name string
			}{{ipprotoSCTP, "SCTP"}, {ipprotoUDPLite, "UDP-Lite"}, {ipprotoMPTCP, "MPTCP"}, {ipprotoSMC, "SMC"}} {
				if !named[p.n] {
					lacks = append(lacks, p.name)
				}
			}
			t.Logf("%d refusals, one record each; this kernel lacks %v outside the run; ping sockets open: %v", len(refused), lacks, ping)

			ulps := []string{"smc", "tls", "abcdefghijklmnopq"}
			for i, err := range runNetHelper(t, dir, "ulp", ulps) {
				if !errors.Is(err, unix.EPERM) {
					t.Errorf("TCP_ULP %q in the run: %v, want EPERM from cgroup/setsockopt", ulps[i], err)
				}
			}
			for i, e := range sockoptRecords(t, h, rd, len(ulps)) {
				if i < len(ulps) {
					wantSockoptRecord(t, e, h, id, ulps[i])
				}
			}
		})
	}
}

// sockoptRecords reads the run's cgroup/setsockopt records of its own generation until the ring is quiet, and expects
// n of them, as sockRecords does for cgroup/sock_create's.
func sockoptRecords(t *testing.T, h *Handle, rd *ringbuf.Reader, n int) []ebpfbindings.SockoptEvent {
	t.Helper()
	var out []ebpfbindings.SockoptEvent
	for {
		wait := 2 * time.Second
		if len(out) >= n {
			wait = 200 * time.Millisecond
		}
		rd.SetDeadline(time.Now().Add(wait))
		rec, err := rd.Read()
		if errors.Is(err, os.ErrDeadlineExceeded) {
			break
		}
		if err != nil {
			t.Fatalf("read the run's ring: %v", err)
		}
		hdr, err := ebpfbindings.DecodeHeader(rec.RawSample)
		if err != nil {
			t.Fatalf("a record on the run's ring: %v", err)
		}
		if hdr.Gen != h.gen || ebpfbindings.Kind(hdr.Kind) != ebpfbindings.KindSockopt {
			continue
		}
		e, err := ebpfbindings.Decode[ebpfbindings.SockoptEvent](rec.RawSample)
		if err != nil {
			t.Fatalf("a sockopt record: %v", err)
		}
		out = append(out, e)
	}
	if len(out) != n {
		t.Errorf("%d sockopt records of the run's generation, want %d: %+v", len(out), n, out)
	}
	return out
}

// wantSockoptRecord checks one TCP_ULP refusal's record: the attachment's run, never the caller's, the option, and
// the name's first bytes as the kernel copied them (SetsockoptString passes the name without its NUL).
func wantSockoptRecord(t *testing.T, e ebpfbindings.SockoptEvent, h *Handle, id uint64, name string) {
	t.Helper()
	hd := e.Hdr
	if ebpfbindings.Verdict(hd.Verdict) != ebpfbindings.VerdictRefused || ebpfbindings.ReasonCode(hd.Reason) != ebpfbindings.ReasonNetNotAllowed ||
		hd.RunIdx != h.Slot() || hd.Gen != h.gen || hd.CgroupID != id {
		t.Errorf("TCP_ULP %q: header %+v; want refused net-not-allowed for slot %d gen %d cgroup %d", name, hd, h.Slot(), h.gen, id)
	}
	want := name
	if len(want) > ebpfbindings.ULPNameMax {
		want = want[:ebpfbindings.ULPNameMax]
	}
	got := string(e.Name[:min(int(e.Optlen), ebpfbindings.ULPNameMax)])
	if e.Level != unix.SOL_TCP || e.Optname != unix.TCP_ULP || e.Optlen != int32(len(name)) || got != want {
		t.Errorf("record names level %d option %d optlen %d name %q; want TCP_ULP, %d, %q", e.Level, e.Optname, e.Optlen,
			got, len(name), want)
	}
}

// TestSockCreateRunsAreANDedWhenNested is §5 R4 for one run's cgroup beneath another's: the kernel runs every
// program on the path from the socket's cgroup up, each with its own attachment's storage, and ANDs them. A ping
// socket the inner run's ICMP entry admits is refused by the outer run, whose contract names none, and only the
// outer run records it; a protocol both refuse is one record on each run's ring, each with its own run's identity.
func TestSockCreateRunsAreANDedWhenNested(t *testing.T) {
	requireRealPrepare(t)
	ping := openPingSockets(t)
	b := New(Options{Machine: machineLinger(0), StateDir: pinState(t), Events: &sink{}})
	outerRel, outerID := runCgroup(t, "sc-outer")
	innerRel := outerRel + "/inner"
	if err := os.Mkdir(filepath.Join("/sys/fs/cgroup", innerRel), 0o755); err != nil {
		t.Fatalf("make the inner run's cgroup: %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(filepath.Join("/sys/fs/cgroup", innerRel)) })
	innerID, err := cgroupIDOfPath("/sys/fs/cgroup", innerRel)
	if err != nil {
		t.Fatal(err)
	}
	prepare := func(name, rel string, id uint64, rules []agent.NetRule) *Handle {
		h, err := b.Prepare(context.Background(), &agent.RuleTable{Net: rules, Tier: backend.TierCgroup, Record: agent.RecordFull},
			Run{ID: "it-" + name, Agent: "a", CgroupID: id, CgroupPath: rel})
		if err != nil {
			t.Fatalf("Prepare %s: %v", name, err)
		}
		t.Cleanup(func() {
			if err := h.Close(); err != nil {
				t.Errorf("Close %s: %v", name, err)
			}
		})
		if err := h.Attach(id); err != nil {
			t.Fatalf("Attach %s: %v", name, err)
		}
		return h
	}
	outer := prepare("sc-outer", outerRel, outerID, []agent.NetRule{inetRule(443)})
	inner := prepare("sc-inner", innerRel, innerID, []agent.NetRule{inetRule(443), inetRule(0)})
	outerRing, innerRing := sockRing(t, outer), sockRing(t, inner)
	dir, err := os.Open(filepath.Join("/sys/fs/cgroup", innerRel))
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()

	tcp := sockTriple{unix.AF_INET, unix.SOCK_STREAM, 0}
	if got := runNetHelper(t, dir, "socket", []string{tcp.String()}); got[0] != nil {
		t.Fatalf("a TCP socket in the inner run: %v", got[0])
	}
	pingCell := sockTriple{unix.AF_INET, unix.SOCK_DGRAM, unix.IPPROTO_ICMP}
	if ping && pingCell.create() == nil {
		if got := runNetHelper(t, dir, "socket", []string{pingCell.String()}); !errors.Is(got[0], unix.EPERM) {
			t.Fatalf("a ping socket in the inner run, which admits it, beneath the outer, which does not: %v, want EPERM", got[0])
		}
		if recs := sockRecords(t, outer, outerRing, 1); len(recs) == 1 {
			wantSockRecord(t, recs[0], outer, outerID, pingCell)
		}
		sockRecords(t, inner, innerRing, 0)
	} else {
		t.Log("ping sockets are closed here; the AND is shown on a protocol both runs refuse only")
	}
	c, ok := refusable()
	if !ok {
		t.Fatal("this kernel created none of SCTP, UDP-Lite, MPTCP and SMC: nothing to refuse")
	}
	if got := runNetHelper(t, dir, "socket", []string{c.String()}); !errors.Is(got[0], unix.EPERM) {
		t.Fatalf("%s in the inner run: %v, want EPERM", c, got[0])
	}
	if recs := sockRecords(t, inner, innerRing, 1); len(recs) == 1 {
		wantSockRecord(t, recs[0], inner, innerID, c)
	}
	if recs := sockRecords(t, outer, outerRing, 1); len(recs) == 1 {
		wantSockRecord(t, recs[0], outer, outerID, c)
	}
}

// legacyExclusive attaches a stand-in program of attach type typ to the cgroup at path the legacy way, with no
// flags (BPF_PROG_ATTACH with neither BPF_F_ALLOW_MULTI nor BPF_F_ALLOW_OVERRIDE, bpftool's default), and detaches
// it at cleanup. A cgroup beneath it can then take no other program of that type (hierarchy_allows_attach).
func legacyExclusive(t *testing.T, path string, typ ebpf.AttachType) {
	t.Helper()
	ptype, ok := map[ebpf.AttachType]ebpf.ProgramType{ebpf.AttachCGroupInetSockCreate: ebpf.CGroupSock,
		ebpf.AttachCGroupSetsockopt: ebpf.CGroupSockopt}[typ]
	if !ok {
		ptype = ebpf.CGroupSockAddr
	}
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{Name: "tego_legacy", Type: ptype, AttachType: typ, License: "GPL",
		Instructions: asm.Instructions{asm.Mov.Imm(asm.R0, 1), asm.Return()}})
	if err != nil {
		t.Fatalf("load a stand-in %v program: %v", typ, err)
	}
	t.Cleanup(func() { _ = prog.Close() })
	dir, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = dir.Close() })
	if err := link.RawAttachProgram(link.RawAttachProgramOptions{Target: int(dir.Fd()), Program: prog, Attach: typ}); err != nil {
		t.Fatalf("legacy-attach a stand-in %v program to %s: %v", typ, path, err)
	}
	t.Cleanup(func() {
		if err := link.RawDetachProgram(link.RawDetachProgramOptions{Target: int(dir.Fd()), Program: prog, Attach: typ}); err != nil {
			t.Errorf("detach the stand-in %v program: %v", typ, err)
		}
	})
}

// TestAttachNamesALegacyExclusiveProgramAbove is §6 E36 as a run meets them: another manager's
// program attached above the run's cgroup without BPF_F_ALLOW_MULTI refuses the run's link of that attach type, and
// Attach fails with ErrCgroupAttachConflict naming the program and the cause (AttachConflictHint, the words doctor's
// D7 row gives too), for connect4, the first program attached, and for sock_create and setsockopt, the last, which the
// CGROUP_SOCK_ADDR batch's success does not imply. The handle's Close leaves no link behind on the run's cgroup.
func TestAttachNamesALegacyExclusiveProgramAbove(t *testing.T) {
	requireRealPrepare(t)
	for _, tc := range []struct {
		name string
		typ  ebpf.AttachType
		prog string
	}{
		{"connect4", ebpf.AttachCGroupInet4Connect, ebpfbindings.ProgConnect4},
		{"sock_create", ebpf.AttachCGroupInetSockCreate, ebpfbindings.ProgSockCreate},
		{"setsockopt", ebpf.AttachCGroupSetsockopt, ebpfbindings.ProgSetsockopt},
	} {
		t.Run(tc.name, func(t *testing.T) {
			parentRel, _ := runCgroup(t, "legacy-"+tc.name)
			legacyExclusive(t, filepath.Join("/sys/fs/cgroup", parentRel), tc.typ)
			rel := parentRel + "/run"
			full := filepath.Join("/sys/fs/cgroup", rel)
			if err := os.Mkdir(full, 0o755); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Remove(full) })
			id, err := cgroupIDOfPath("/sys/fs/cgroup", rel)
			if err != nil {
				t.Fatal(err)
			}
			b := New(Options{Machine: machineLinger(0), StateDir: pinState(t), Events: &sink{}})
			h, err := b.Prepare(context.Background(), &agent.RuleTable{Net: []agent.NetRule{inetRule(443)}, Tier: backend.TierCgroup,
				Record: agent.RecordFull}, Run{ID: "it-legacy-" + tc.name, Agent: "a", CgroupID: id, CgroupPath: rel})
			if err != nil {
				t.Fatalf("Prepare: %v", err)
			}
			err = h.Attach(id)
			if !errors.Is(err, ErrCgroupAttachConflict) {
				t.Fatalf("Attach beneath a legacy exclusive %s program = %v, want ErrCgroupAttachConflict", tc.name, err)
			}
			for _, want := range []string{tc.prog, AttachConflictHint(full)} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("the refusal does not name %q: %v", want, err)
				}
			}
			if err := h.Close(); err != nil {
				t.Errorf("Close: %v", err)
			}
			// A link whose pin was its last reference is freed once bpffs frees the pin's inode, after an RCU grace
			// period (5.14 shows it for a moment after Close), so its program is waited for, not seen at once.
			for _, typ := range []ebpf.AttachType{ebpf.AttachCGroupInet4Connect, ebpf.AttachCGroupInetSockCreate,
				ebpf.AttachCGroupSetsockopt} {
				ids := attachedProgs(t, full, typ)
				for deadline := time.Now().Add(5 * time.Second); len(ids) != 0 && time.Now().Before(deadline); {
					time.Sleep(50 * time.Millisecond)
					ids = attachedProgs(t, full, typ)
				}
				if len(ids) != 0 {
					t.Errorf("5 s after Close the run's cgroup still holds %v programs %v", typ, ids)
				}
			}
		})
	}
}

// attachedProgs lists the programs attached directly to the cgroup at path for one attach type.
func attachedProgs(t *testing.T, path string, typ ebpf.AttachType) []ebpf.ProgramID {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	res, err := link.QueryPrograms(link.QueryOptions{Target: int(f.Fd()), Attach: typ})
	if err != nil {
		t.Fatalf("query %s for %v: %v", path, typ, err)
	}
	var ids []ebpf.ProgramID
	for _, p := range res.Programs {
		ids = append(ids, p.ID)
	}
	return ids
}
