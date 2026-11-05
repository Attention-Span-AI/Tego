// SPDX-License-Identifier: Apache-2.0

package doctor

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"

	bpfobj "github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/internal/platform/startphase"
	"github.com/attention-span-ai/tego/internal/runtime/cgroup"
	cgroupenforce "github.com/attention-span-ai/tego/internal/runtime/enforce/cgroup"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// ErrPrograms is a D7 load test that could not be performed at all (no BTF, no privilege).
var ErrPrograms = errors.New("doctor: program load test unavailable")

// probeCgroupPrefix names the throwaway cgroup D7 attaches its cgroup programs to. It holds no
// process, so a program attached to it for the length of the probe cannot affect anything.
const probeCgroupPrefix = ".tego-doctor-progs-"

// hookKind is how a hook is reached.
type hookKind int

const (
	hookFEntry        hookKind = iota // BPF_PROG_TYPE_TRACING, BPF_TRACE_FENTRY on a kernel function
	hookFExit                         // BPF_PROG_TYPE_TRACING, BPF_TRACE_FEXIT on a kernel function (ADR 0016)
	hookRawTP                         // BPF_PROG_TYPE_TRACING, BPF_TRACE_RAW_TP on a BTF tracepoint
	hookCgroupAddr                    // BPF_PROG_TYPE_CGROUP_SOCK_ADDR on a cgroup
	hookUprobe                        // BPF_PROG_TYPE_KPROBE, a uprobe on a library symbol (capture)
	hookUretprobe                     // BPF_PROG_TYPE_KPROBE, a uretprobe on a library symbol (capture)
	hookTracepoint                    // BPF_PROG_TYPE_TRACEPOINT, a syscall result
	hookCgroupSKB                     // packet admission and accounting
	hookSockOps                       // TCP lifecycle
	hookCgroupSock                    // socket creation, binds and release (BPF_PROG_TYPE_CGROUP_SOCK)
	hookCgroupSockopt                 // socket options (BPF_PROG_TYPE_CGROUP_SOCKOPT)
)

// hook is one attach point D7 tests.
type hook struct {
	// Name is how the C program's SEC() spells it, so a failure names something greppable.
	Name string
	// Tier is the tier that needs it.
	Tier backend.Tier
	kind hookKind
	// attachTo is the kernel symbol; btfName is the type name that proves it exists in BTF.
	attachTo   string
	btfName    string
	attachType ebpf.AttachType
	// since is the release the attach point arrived in, "" when it is as old as the mechanism.
	since Version
	// optional marks a hook its tier runs without on a kernel older than since: the backend leaves the
	// hook's program out of the load there, and what it would decide stays with the inherited tier-1
	// path (enforce-cgroup-observe.md §5 R7). On a kernel that has the attach point an optional hook
	// gates its tier like any other, because the backend loads its program there and a refusal fails
	// the run's Prepare.
	optional bool
	// capabilityOnly is required only by an explicit optional network control.
	// Its actual load/attach result is reported, but cannot demote legacy runs.
	capabilityOnly bool
	// object and program name the embedded program that runs at this hook in production, and D7
	// loads that program rather than a stand-in (R27 D7, "a fresh load of the embedded object"): the
	// verifier judges a program, not an attach point, so a hook that takes a two-instruction program
	// can still refuse the real one. Both are empty for a hook no object carries yet — tier 3's, whose
	// C is not written (internal/bpf/gen.go).
	object  bpfobj.Object
	program string
	// symbols are a capture row's candidate library symbols, tried in order: the first the library
	// exports is the one capture itself would hook (capture-derive.md R2: SSL_write_ex2, else
	// SSL_write_ex).
	symbols []string
}

// hooks lists every tier-2 attach point, in the order doctor reports them: every program of the three tier-2
// objects — trace_proc's record path, cgroup_track's descendant tracking and cgroup_net's eight socket-address
// hooks (docs/p0/enforce-cgroup-observe.md §2.1, §5 R1) — so a program a run loads is a program D7 has loaded.
// Tier 3's rows are the decision plane's, one per decide.bpf.c hook per mode, which the plane probe loads and
// exercises as one set (plane.go, planeprobe.go; docs/p0/enforce-plane.md R21). *Amended (T8):* the six
// hand-listed lsm/* rows, tested with a minimal program because no object carried them, are gone.
var hooks = []hook{
	{Name: "fexit/security_file_open", Tier: backend.TierCgroup, kind: hookFExit,
		attachTo: "security_file_open", btfName: "security_file_open", attachType: ebpf.AttachTraceFExit,
		object: bpfobj.ObjectTraceProc, program: bpfobj.ProgFileOpen},
	{Name: "fexit/security_path_unlink", Tier: backend.TierCgroup, kind: hookFExit,
		attachTo: "security_path_unlink", btfName: "security_path_unlink", attachType: ebpf.AttachTraceFExit,
		object: bpfobj.ObjectTraceProc, program: bpfobj.ProgPathUnlink},
	{Name: "fexit/security_path_rename", Tier: backend.TierCgroup, kind: hookFExit,
		attachTo: "security_path_rename", btfName: "security_path_rename", attachType: ebpf.AttachTraceFExit,
		object: bpfobj.ObjectTraceProc, program: bpfobj.ProgPathRename},
	{Name: "fexit/security_path_mkdir", Tier: backend.TierCgroup, kind: hookFExit,
		attachTo: "security_path_mkdir", btfName: "security_path_mkdir", attachType: ebpf.AttachTraceFExit,
		object: bpfobj.ObjectTraceProc, program: bpfobj.ProgPathMkdir},
	{Name: "fexit/security_path_mknod", Tier: backend.TierCgroup, kind: hookFExit,
		attachTo: "security_path_mknod", btfName: "security_path_mknod", attachType: ebpf.AttachTraceFExit,
		object: bpfobj.ObjectTraceProc, program: bpfobj.ProgPathMknod},
	{Name: "fexit/security_path_rmdir", Tier: backend.TierCgroup, kind: hookFExit,
		attachTo: "security_path_rmdir", btfName: "security_path_rmdir", attachType: ebpf.AttachTraceFExit,
		object: bpfobj.ObjectTraceProc, program: bpfobj.ProgPathRmdir},
	{Name: "fexit/security_path_link", Tier: backend.TierCgroup, kind: hookFExit,
		attachTo: "security_path_link", btfName: "security_path_link", attachType: ebpf.AttachTraceFExit,
		object: bpfobj.ObjectTraceProc, program: bpfobj.ProgPathLink},
	{Name: "fexit/security_path_symlink", Tier: backend.TierCgroup, kind: hookFExit,
		attachTo: "security_path_symlink", btfName: "security_path_symlink", attachType: ebpf.AttachTraceFExit,
		object: bpfobj.ObjectTraceProc, program: bpfobj.ProgPathSymlink},
	{Name: "fexit/security_path_truncate", Tier: backend.TierCgroup, kind: hookFExit,
		attachTo: "security_path_truncate", btfName: "security_path_truncate", attachType: ebpf.AttachTraceFExit,
		object: bpfobj.ObjectTraceProc, program: bpfobj.ProgPathTruncate},
	{Name: "fexit/security_file_truncate", Tier: backend.TierCgroup, kind: hookFExit, since: Version{6, 2, 0}, optional: true,
		attachTo: "security_file_truncate", btfName: "security_file_truncate", attachType: ebpf.AttachTraceFExit,
		object: bpfobj.ObjectTraceProc, program: bpfobj.ProgFileTruncate},
	{Name: "fentry/security_socket_connect", Tier: backend.TierCgroup, kind: hookFEntry,
		attachTo: "security_socket_connect", btfName: "security_socket_connect", attachType: ebpf.AttachTraceFEntry,
		object: bpfobj.ObjectTraceProc, program: bpfobj.ProgSocketConnect},
	{Name: "tp_btf/sched_process_exec", Tier: backend.TierCgroup, kind: hookRawTP,
		attachTo: "sched_process_exec", btfName: "btf_trace_sched_process_exec", attachType: ebpf.AttachTraceRawTp,
		object: bpfobj.ObjectTraceProc, program: bpfobj.ProgSchedExec},
	{Name: "tp_btf/sched_process_exit", Tier: backend.TierCgroup, kind: hookRawTP,
		attachTo: "sched_process_exit", btfName: "btf_trace_sched_process_exit", attachType: ebpf.AttachTraceRawTp,
		object: bpfobj.ObjectTraceProc, program: bpfobj.ProgSchedExit},
	{Name: "tp_btf/cgroup_mkdir", Tier: backend.TierCgroup, kind: hookRawTP,
		attachTo: "cgroup_mkdir", btfName: "btf_trace_cgroup_mkdir", attachType: ebpf.AttachTraceRawTp,
		object: bpfobj.ObjectCgroupTrack, program: bpfobj.ProgCgroupMkdir},
	{Name: "tp_btf/cgroup_rmdir", Tier: backend.TierCgroup, kind: hookRawTP,
		attachTo: "cgroup_rmdir", btfName: "btf_trace_cgroup_rmdir", attachType: ebpf.AttachTraceRawTp,
		object: bpfobj.ObjectCgroupTrack, program: bpfobj.ProgCgroupRmdir},
	{Name: "cgroup/connect4", Tier: backend.TierCgroup, kind: hookCgroupAddr,
		attachType: ebpf.AttachCGroupInet4Connect, object: bpfobj.ObjectCgroupNet, program: bpfobj.ProgConnect4},
	{Name: "cgroup/connect6", Tier: backend.TierCgroup, kind: hookCgroupAddr,
		attachType: ebpf.AttachCGroupInet6Connect, object: bpfobj.ObjectCgroupNet, program: bpfobj.ProgConnect6},
	{Name: "cgroup/sendmsg4", Tier: backend.TierCgroup, kind: hookCgroupAddr,
		attachType: ebpf.AttachCGroupUDP4Sendmsg, object: bpfobj.ObjectCgroupNet, program: bpfobj.ProgSendmsg4},
	{Name: "cgroup/sendmsg6", Tier: backend.TierCgroup, kind: hookCgroupAddr,
		attachType: ebpf.AttachCGroupUDP6Sendmsg, object: bpfobj.ObjectCgroupNet, program: bpfobj.ProgSendmsg6},
	{Name: "cgroup/bind4", Tier: backend.TierCgroup, kind: hookCgroupAddr,
		attachType: ebpf.AttachCGroupInet4Bind, object: bpfobj.ObjectCgroupNet, program: bpfobj.ProgBind4},
	{Name: "cgroup/bind6", Tier: backend.TierCgroup, kind: hookCgroupAddr,
		attachType: ebpf.AttachCGroupInet6Bind, object: bpfobj.ObjectCgroupNet, program: bpfobj.ProgBind6},
	{Name: "cgroup/connect_unix", Tier: backend.TierCgroup, kind: hookCgroupAddr,
		attachType: ebpf.AttachCgroupUnixConnect, since: Version{6, 7, 0}, optional: true,
		object: bpfobj.ObjectCgroupNet, program: bpfobj.ProgConnectUnix},
	{Name: "cgroup/sendmsg_unix", Tier: backend.TierCgroup, kind: hookCgroupAddr,
		attachType: ebpf.AttachCgroupUnixSendmsg, since: Version{6, 7, 0}, optional: true,
		object: bpfobj.ObjectCgroupNet, program: bpfobj.ProgSendmsgUnix},
	{Name: "tracepoint/syscalls/sys_exit_execve", Tier: backend.TierCgroup, kind: hookTracepoint,
		attachTo: "syscalls/sys_exit_execve", optional: true,
		object: bpfobj.ObjectTraceProc, program: bpfobj.ProgExecResult},
	{Name: "tracepoint/syscalls/sys_exit_execveat", Tier: backend.TierCgroup, kind: hookTracepoint,
		attachTo: "syscalls/sys_exit_execveat", optional: true,
		object: bpfobj.ObjectTraceProc, program: bpfobj.ProgExecatResult},
	{Name: "tracepoint/syscalls/sys_exit_bind", Tier: backend.TierCgroup, kind: hookTracepoint, capabilityOnly: true,
		attachTo: "syscalls/sys_exit_bind", object: bpfobj.ObjectTraceProc, program: bpfobj.ProgBindResult},
	{Name: "tracepoint/syscalls/sys_exit_listen", Tier: backend.TierCgroup, kind: hookTracepoint, capabilityOnly: true,
		attachTo: "syscalls/sys_exit_listen", object: bpfobj.ObjectTraceProc, program: bpfobj.ProgListenResult},
	{Name: "fexit/io_bind", Tier: backend.TierCgroup, kind: hookFExit, since: Version{6, 11, 0}, optional: true, capabilityOnly: true,
		attachTo: "io_bind", btfName: "io_bind", attachType: ebpf.AttachTraceFExit,
		object: bpfobj.ObjectTraceProc, program: bpfobj.ProgURingBindResult},
	{Name: "fexit/io_listen", Tier: backend.TierCgroup, kind: hookFExit, since: Version{6, 11, 0}, optional: true, capabilityOnly: true,
		attachTo: "io_listen", btfName: "io_listen", attachType: ebpf.AttachTraceFExit,
		object: bpfobj.ObjectTraceProc, program: bpfobj.ProgURingListenResult},
	{Name: "cgroup/post_bind4", Tier: backend.TierCgroup, kind: hookCgroupSock, capabilityOnly: true,
		attachType: ebpf.AttachCGroupInet4PostBind, object: bpfobj.ObjectCgroupNet, program: bpfobj.ProgPostBind4},
	{Name: "cgroup/post_bind6", Tier: backend.TierCgroup, kind: hookCgroupSock, capabilityOnly: true,
		attachType: ebpf.AttachCGroupInet6PostBind, object: bpfobj.ObjectCgroupNet, program: bpfobj.ProgPostBind6},
	{Name: "cgroup_skb/ingress", Tier: backend.TierCgroup, kind: hookCgroupSKB, capabilityOnly: true,
		attachType: ebpf.AttachCGroupInetIngress, object: bpfobj.ObjectCgroupNet, program: bpfobj.ProgNetIngress},
	{Name: "cgroup_skb/egress", Tier: backend.TierCgroup, kind: hookCgroupSKB, capabilityOnly: true,
		attachType: ebpf.AttachCGroupInetEgress, object: bpfobj.ObjectCgroupNet, program: bpfobj.ProgNetEgress},
	{Name: "sockops", Tier: backend.TierCgroup, kind: hookSockOps, capabilityOnly: true,
		attachType: ebpf.AttachCGroupSockOps, object: bpfobj.ObjectCgroupNet, program: bpfobj.ProgNetSockOps},
	// cgroup/sock_create (ADR 0018 PR 2) is required: every run with a net: section attaches it beside connect4
	// (A-0018-1, A-0018-6), and its attach type and bpf_link attach are below the floor.
	{Name: "cgroup/sock_create", Tier: backend.TierCgroup, kind: hookCgroupSock,
		attachType: ebpf.AttachCGroupInetSockCreate, object: bpfobj.ObjectCgroupNet, program: bpfobj.ProgSockCreate},
	// cgroup/setsockopt (ADR 0018 (7)) is required for the same reasons: every run with a net: section attaches it
	// beside cgroup/sock_create, and BPF_CGROUP_SETSOCKOPT (5.3) and its bpf_link attach are below the floor.
	{Name: "cgroup/setsockopt", Tier: backend.TierCgroup, kind: hookCgroupSockopt,
		attachType: ebpf.AttachCGroupSetsockopt, object: bpfobj.ObjectCgroupNet, program: bpfobj.ProgSetsockopt},
	{Name: "cgroup/sock_release", Tier: backend.TierCgroup, kind: hookCgroupSock, capabilityOnly: true,
		attachType: ebpf.AttachCgroupInetSockRelease, object: bpfobj.ObjectCgroupNet, program: bpfobj.ProgNetRelease},
}

// captureHooks are capture's rows (R27 D7): every program of uprobe_ssl, the object capture attaches
// to an agent's libssl (docs/p0/capture-derive.md R1-R3). They are not in hooks and carry no tier, so
// no tier derivation reads them (derive.go keeps a tier's own rows only). SSL_read's return probe is
// tested on SSL_read; in production the same program also sits on SSL_read_ex's return.
var captureHooks = []hook{
	{Name: "uprobe/SSL_write", kind: hookUprobe, object: bpfobj.ObjectUprobeSSL, program: bpfobj.ProgSSLWrite,
		symbols: bpfobj.SSLEntryPrograms[bpfobj.ProgSSLWrite]},
	{Name: "uprobe/SSL_write_ex", kind: hookUprobe, object: bpfobj.ObjectUprobeSSL, program: bpfobj.ProgSSLWriteEx,
		symbols: bpfobj.SSLEntryPrograms[bpfobj.ProgSSLWriteEx]},
	{Name: "uprobe/SSL_read", kind: hookUprobe, object: bpfobj.ObjectUprobeSSL, program: bpfobj.ProgSSLRead,
		symbols: bpfobj.SSLEntryPrograms[bpfobj.ProgSSLRead]},
	{Name: "uprobe/SSL_read_ex", kind: hookUprobe, object: bpfobj.ObjectUprobeSSL, program: bpfobj.ProgSSLReadEx,
		symbols: bpfobj.SSLEntryPrograms[bpfobj.ProgSSLReadEx]},
	{Name: "uretprobe/SSL_read", kind: hookUretprobe, object: bpfobj.ObjectUprobeSSL,
		program: bpfobj.ProgSSLReadReturn, symbols: bpfobj.SSLEntryPrograms[bpfobj.ProgSSLRead]},
	{Name: "uprobe/SSL_free", kind: hookUprobe, object: bpfobj.ObjectUprobeSSL, program: bpfobj.ProgSSLFree,
		symbols: bpfobj.SSLEntryPrograms[bpfobj.ProgSSLFree]},
}

// HookResult is one attach point's answer.
type HookResult struct {
	Hook string `json:"hook"`
	// Tier is the tier that needs the hook, absent on a capture row.
	Tier backend.Tier `json:"tier,omitempty"`
	// Capture marks a row of capture's uprobe_ssl rather than of a tier. It has no BTF attach point
	// (a uprobe sits at a file offset), and a failing one never fails D7 or gates a tier: it is
	// reported on D7's line and in capture.model_traffic's matrix note (R27 D7).
	Capture        bool `json:"capture,omitempty"`
	CapabilityOnly bool `json:"capability_only,omitempty"`
	// Target is the system libssl D7 found for capture's rows, "" when it found none. It is set whether or
	// not the row's program loaded, so a row that failed to load still says a library was there; Attached
	// says whether the row attached to it.
	Target string `json:"target,omitempty"`
	// LoadOnly marks a capture row whose attach was not tried: no system libssl was found, or the one
	// found exports none of the row's symbols, which capture would then not hook either.
	LoadOnly bool `json:"load_only,omitempty"`
	// Object is the embedded object whose program runs at this hook, "" when no object carries it
	// yet (tier 3, until its C is written).
	Object string `json:"object,omitempty"`
	// StandIn marks a hook D7 tested with a minimal program of the hook's type instead of the
	// program that runs there: no object carries the hook yet, or this binary does not carry the
	// hook's object (an untagged build, or uprobe_ssl on an architecture it is not compiled for). The
	// answer is then the kernel's attach point alone; whether this binary
	// can build the tier at all is the tier derivation's question (enforce.Buildable), not D7's.
	StandIn bool `json:"stand_in,omitempty"`
	// BTF reports whether the kernel's own BTF declares the attach point (I2's pre-load check).
	BTF bool `json:"btf"`
	// Loaded and Attached report how far bpf(BPF_PROG_LOAD) and the attach (bpf(BPF_LINK_CREATE), or
	// a capture row's uprobe perf_event_open) got. Both objects are doctor's own and are closed before
	// Run returns; nothing is ever pinned (I7).
	Loaded   bool `json:"loaded"`
	Attached bool `json:"attached"`
	// Absent marks an optional hook this machine cannot use: a missing attach
	// point, or an unavailable optional exec-outcome perf link. Its tier runs
	// without it; Loaded and Attached retain the actual probe facts.
	Absent bool `json:"absent,omitempty"`
	// Reader is the build of the hook's object that D7 loaded, for an object compiled once per reader
	// (bpf.HasReaders: trace_proc): "rdonly" or "probe", the build a run loads on this kernel (bpf.KernelReader).
	// ReaderWhy says what chose it. Both are absent for an object with one build.
	Reader    string `json:"reader,omitempty"`
	ReaderWhy string `json:"reader_why,omitempty"`
	// Lockdown marks a row not loaded because lockdown=confidentiality refuses the probe build's reads and this
	// kernel's BTF lacks what the rdonly build calls: no build of the object loads here (ReaderChoice.Loadable).
	Lockdown bool   `json:"lockdown,omitempty"`
	Detail   string `json:"detail,omitempty"`

	// The fields below are a plane row's (docs/p0/enforce-plane.md R21): one decide.bpf.c hook in one mode.
	// Plane is the mode; a plane row has no Tier, because the plane gates tiers through PlaneState, not D7.
	Plane bpfobj.PlaneMode `json:"plane,omitempty"`
	// Function is the kernel function the program attaches to (bpf_lsm_<hook> or security_<fn>), and Arity its
	// parameter count in this kernel's BTF (the prototype check).
	Function string `json:"function,omitempty"`
	Arity    int    `json:"arity,omitempty"`
	// Decides is the hook's body refusing (bpf.PlaneHook.Decides): its probe syscall must be refused in the
	// scratch cgroup, where a stub's must pass.
	Decides bool `json:"decides,omitempty"`
	// Ran is the program's run count moving across the probe syscalls (BPF run statistics).
	Ran bool `json:"ran,omitempty"`
	// Inside and Outside are the probe syscall's outcome in the scratch cgroup under the probe row and from
	// doctor outside every run: passed, refused, or failed: <error>.
	Inside  string `json:"inside,omitempty"`
	Outside string `json:"outside,omitempty"`
}

// OK reports whether the hook is fully usable. A capture row has no BTF attach point to resolve,
// so it is asked to load and attach only.
func (h HookResult) OK() bool {
	if h.Capture {
		return h.Loaded && h.Attached
	}
	if h.Plane != "" {
		if h.Absent {
			return true // an optional hook this kernel predates: its rule is another hook's here (enforce-plane R3)
		}
		want := planePassed
		if h.Decides {
			want = planeRefused
		}
		return h.BTF && h.Loaded && h.Attached && h.Ran && h.Inside == want && h.Outside == planePassed
	}
	return h.BTF && h.Loaded && h.Attached
}

// captureFailed reports whether a capture row found a fault, as opposed to an attach it had no
// library or symbol to try.
func captureFailed(h HookResult) bool { return !h.Loaded || (!h.Attached && !h.LoadOnly) }

// memlockOnce raises the locked-memory limit once per process (raiseMemlock); on 5.11+ BPF memory is charged to
// the cgroup instead and this is a no-op.
var memlockOnce sync.Once

// tierHooks is the rows of hooks that tier t needs, in doctor's order.
func tierHooks(t backend.Tier) []hook {
	var out []hook
	for _, h := range hooks {
		if h.Tier == t {
			out = append(out, h)
		}
	}
	return out
}

// probeHooks is D7 over the given tier rows and capture rows. `tego run` at reach cgroup hands it tier 2's
// rows alone (ForRun): tier 3's and capture's rows gate nothing that run can select or explain, and each is
// a program load of its own. The system libssl is looked for only when there is a capture row to attach.
func probeHooks(root bool, uid int, kernel Version, tier, capture []hook) (Result, []HookResult) {
	if !root {
		return Result{ID: CheckPrograms,
			Detail: "requires root to test (bpf(BPF_PROG_LOAD) needs CAP_BPF; this kernel disables unprivileged BPF)",
			Fix:    "re-run as root: " + sudoDoctor(), Skipped: true}, nil
	}
	spec, err := loadKernelSpec()
	if err != nil {
		return Result{ID: CheckPrograms, Detail: fmt.Sprintf("%v: %v", ErrPrograms, err),
			Fix: "boot a kernel built with CONFIG_DEBUG_INFO_BTF=y"}, nil
	}
	memlockOnce.Do(raiseMemlock)

	cg, cgErr := newScratchCgroup(uid)
	if cg != nil {
		defer cg.remove()
	}
	results := make([]HookResult, 0, len(tier)+len(capture))
	for _, h := range tier {
		results = append(results, testHook(h, spec, cg, cgErr, kernel))
	}
	if len(capture) > 0 {
		lib := systemLibSSL(libsslDirs())
		for _, h := range capture {
			results = append(results, testCaptureHook(h, spec, lib, bpfobj.Load))
		}
	}
	return programsVerdict(results), results
}

// programsVerdict is D7's Result over its hook results. It is pure so the wording can be held to what
// the hooks found without a kernel that fails in the way a branch describes.
//
// Capture's rows are summed up on the same line and never fail it: capture is not a tier's
// requirement, and a D7 that failed on them would put a capture remedy on the tier fix line
// (derive.go's fix reads D7's) ahead of the one the next tier needs.
func programsVerdict(results []HookResult) Result {
	var failed, absent, unavailable []string
	var capture []HookResult
	var capabilities []HookResult
	notInBinary, kernelGap, lockdown := false, false, false
	readers := map[string]string{} // object -> "<reader> build (<why>)"
	var readerObjects []string
	tierRows := 0
	for _, r := range results {
		if r.Capture {
			capture = append(capture, r)
			continue
		}
		if r.Plane != "" {
			continue // the plane's clause is planeSummary's, and a plane mode fails no tier through D7
		}
		if r.CapabilityOnly {
			capabilities = append(capabilities, r)
			continue
		}
		if r.Absent {
			if r.Loaded {
				unavailable = append(unavailable, r.Hook)
			} else {
				absent = append(absent, r.Hook)
			}
			continue
		}
		tierRows++
		if r.Reader != "" && readers[r.Object] == "" {
			readers[r.Object] = fmt.Sprintf("%s build (%s)", r.Reader, r.ReaderWhy)
			readerObjects = append(readerObjects, r.Object)
		}
		lockdown = lockdown || r.Lockdown
		if !r.OK() {
			failed = append(failed, r.Hook)
			// A program of this build that the verifier refused at an attach point the kernel has is
			// the one failure a kernel with "the listed hooks" does not cure.
			kernelGap = kernelGap || !(r.BTF && !r.Loaded && !r.StandIn && r.Object != "")
		}
		notInBinary = notInBinary || (r.StandIn && r.Object != "")
	}
	detail := fmt.Sprintf("%d of %d hooks load and attach", tierRows-len(failed), tierRows)
	if len(absent) > 0 {
		detail += fmt.Sprintf("; this kernel predates %s, which the tier runs without",
			strings.Join(absent, " "))
	}
	if len(unavailable) > 0 {
		detail += "; optional exec outcome links unavailable: " + strings.Join(unavailable, " ") + "; supervisor decides every exec (no fast handover); a failed exec's errno is not recorded"
	}
	// Said on the line, not only in --json, so a hook that took a stand-in is never read as the
	// program that runs there having loaded.
	if notInBinary {
		detail += "; this binary carries no BPF objects, so the tier-2 hooks were tested with a minimal program"
	}
	// Which build of an object compiled per reader was tested, and why: the one a run loads here (bpf.Load).
	for _, o := range readerObjects {
		if lockdown {
			detail += fmt.Sprintf("; %s has no build this kernel loads under lockdown=confidentiality", o)
			continue
		}
		detail += fmt.Sprintf("; %s is its %s", o, readers[o])
	}
	detail += captureSummary(capture)
	if len(capabilities) > 0 {
		passed := 0
		for _, row := range capabilities {
			if row.OK() {
				passed++
			}
		}
		detail += fmt.Sprintf("; optional network controls: %d of %d hooks load and attach", passed, len(capabilities))
	}
	if len(failed) == 0 {
		return Result{ID: CheckPrograms, OK: true, Detail: detail}
	}
	fix := "boot a kernel with the listed hooks, or pin a lower tier in the machine config"
	if lockdown {
		fix = "lockdown=confidentiality refuses the probe reads tier 2's record makes on a kernel without " +
			"bpf_rdonly_cast and bpf_loop in its BTF: boot without lockdown=confidentiality (integrity keeps the " +
			"tier), or a kernel with both (6.2+, RHEL 9.8), or pin a lower tier in the machine config"
	} else if !kernelGap {
		fix = "this kernel's verifier refuses the listed programs of this build: boot a kernel that accepts " +
			"them or report the verifier's lines as a tego bug, or pin a lower tier in the machine config"
	}
	return Result{ID: CheckPrograms, Detail: detail + "; missing: " + strings.Join(failed, " "), Fix: fix}
}

// captureSummary is capture's clause of D7's line: how many uprobe_ssl programs loaded and attached,
// where, and which failed. It says when the attach was not tested and why — no system libssl, or no
// program that loaded to attach — and when a minimal program stood in, so none of them reads as the
// capture programs having attached, and a kernel or verifier fault never reads as a missing library.
func captureSummary(rows []HookResult) string {
	if len(rows) == 0 {
		return ""
	}
	var failed, notExported []string
	attached, loaded, standIn, target := 0, 0, false, ""
	for _, r := range rows {
		standIn = standIn || r.StandIn
		if r.Target != "" {
			target = r.Target
		}
		if r.Loaded {
			loaded++
		}
		switch {
		case r.OK():
			attached++
		case captureFailed(r):
			failed = append(failed, r.Hook)
		case r.Target != "":
			notExported = append(notExported, r.Hook)
		}
	}
	var out string
	switch {
	case target != "" && loaded == 0:
		out = fmt.Sprintf("; capture (uprobe_ssl, no tier): 0 of %d programs load, attach at %s not tested "+
			"(no program loaded to attach)", len(rows), target)
	case target != "":
		out = fmt.Sprintf("; capture (uprobe_ssl, no tier): %d of %d programs load and attach at %s",
			attached, len(rows), target)
	default:
		out = fmt.Sprintf("; capture (uprobe_ssl, no tier): %d of %d programs load, attach not tested (no "+
			"system libssl found)", loaded, len(rows))
	}
	if len(notExported) > 0 {
		out += ", not exported there: " + strings.Join(notExported, " ")
	}
	if standIn {
		out += ", tested with a minimal program (this binary carries no uprobe_ssl object)"
	}
	if len(failed) > 0 {
		out += ", failed: " + strings.Join(failed, " ") + " (capture cannot use its uprobes here; this " +
			"does not fail D7)"
	}
	return out
}

// kernelReader is the build choice of an object compiled once per reader; bpf.KernelReader, the one bpf.Load
// follows, in production. A variable so the lockdown row can be driven without such a kernel.
var kernelReader = bpfobj.KernelReader

// objectLoader returns a fresh CollectionSpec for one embedded object; bpf.Load in production.
type objectLoader func(bpfobj.Object) (*ebpf.CollectionSpec, error)

// unixSupported is the backend's own probe of BPF_CGROUP_UNIX_CONNECT. A variable so a test can give both answers.
var unixSupported = cgroupenforce.UnixConnectSupported

// Shared with the runtime loader; variables let tests establish a present event
// with an unsafe context without privilege or the host's tracefs layout.
var execResultTracepointAvailable = bpfobj.ExecResultTracepointAvailable
var validateSyscallResultContext = bpfobj.ValidateSyscallResultContext

// optionalAbsent reports whether the kernel lacks an optional hook, by the test the backend runs before it loads
// (cgroup's dropTraceWhereAbsent: the function is in the kernel's BTF; dropUnixWhereUnsupported: a program with
// the attach type loads). An unreadable BTF is not absence: the backend then tries the program, so the row is
// left to the BTF check that follows.
func optionalAbsent(h hook, spec *btf.Spec) (absent bool, why string, err error) {
	if h.kind == hookTracepoint {
		return !execResultTracepointAvailable(strings.TrimPrefix(h.attachTo, "syscalls/")), "syscall tracepoint " + h.attachTo + " is unavailable; exec decisions remain with the supervisor", nil
	}
	if h.kind == hookCgroupAddr {
		ok, err := unixSupported()
		if err != nil {
			return false, "", err
		}
		return !ok, "the kernel does not accept " + h.Name + " programs", nil
	}
	if spec == nil {
		return false, "", nil
	}
	if hookInBTF(spec, h) != nil {
		return true, h.btfName + " is not in the kernel's BTF", nil
	}
	return false, "", nil
}

// testHook runs one hook's BTF check, load and link against this binary's own objects.
func testHook(h hook, spec *btf.Spec, cg *scratchCgroup, cgErr error, kernel Version) HookResult {
	return testHookWith(h, spec, cg, cgErr, kernel, bpfobj.Load)
}

// testHookWith is testHook with the object source supplied, so the answers for a binary without the
// objects, or an object that lacks the hook's program, can be driven in any build.
func testHookWith(h hook, spec *btf.Spec, cg *scratchCgroup, cgErr error, kernel Version, load objectLoader) HookResult {
	out := HookResult{Hook: h.Name, Tier: h.Tier, Object: string(h.object), CapabilityOnly: h.capabilityOnly}
	if h.object != "" && bpfobj.HasReaders(h.object) {
		c := kernelReader()
		out.Reader, out.ReaderWhy = string(c.Reader), c.Why
		if !c.Loadable() {
			// Said before any load: the probe build's load would fail with the verifier's "cannot use helper",
			// which names neither lockdown nor the build that would have loaded.
			out.BTF = true
			out.Lockdown = true
			out.Detail = fmt.Sprintf("lockdown=confidentiality refuses bpf_probe_read_kernel, which %s's probe build "+
				"calls, and %s, which its rdonly build needs", h.object, c.Why)
			return out
		}
	}
	if h.optional {
		// Absent comes from the test the backend applies, never from the version: a distribution backports either
		// way (ADR 0038's RHEL 9), and `since` is only the upstream release named in the advice.
		absent, why, err := optionalAbsent(h, spec)
		if err != nil {
			out.Detail = "probe: " + err.Error()
			return out
		}
		if absent {
			out.Absent = true
			if h.since == (Version{}) {
				out.Detail = why
			} else {
				out.Detail = fmt.Sprintf("%s (upstream needs kernel >= %s, this is %s); tier %s runs without it",
					why, h.since, kernel, h.Tier)
			}
			return out
		}
	} else if h.since != (Version{}) && !kernel.AtLeast(h.since) {
		out.Detail = fmt.Sprintf("needs kernel >= %s, this is %s", h.since, kernel)
		return out
	}
	if h.btfName != "" && spec == nil {
		out.Detail = "the kernel's BTF is unavailable, so the attach point cannot be resolved"
		return out
	}
	if h.btfName != "" {
		if err := hookInBTF(spec, h); err != nil {
			out.Detail = fmt.Sprintf("%s is not in the kernel's BTF: %v", h.btfName, err)
			return out
		}
	}
	out.BTF = true
	if err := validateSyscallResultContext(h.program); err != nil {
		// Unknown outcome layouts are an admission failure even for listener
		// capability rows: a version or successful no-op probe cannot vouch
		// for these reads. Keep the reason in the tier/run refusal.
		out.CapabilityOnly = false
		out.Detail = "load: " + err.Error()
		return out
	}

	// A timed test build reports the hook's load, attach and detach as probe.hook.<hook>.* and the program's verifier
	// statistics (enforce-plane §10.1's cold attribution); a product build times nothing.
	phase := "probe.hook." + h.Name
	endLoad := startphase.Begin(nil, phase+".load")
	prog, standIn, err := loadHookProgram(h, spec, load)
	endLoad()
	out.StandIn = standIn
	if err != nil {
		out.Detail = "load: " + verifierTail(err)
		return out
	}
	defer func() { _ = prog.Close() }()
	out.Loaded = true
	bpfobj.ReportProgram(phase, prog)

	endAttach := startphase.Begin(nil, phase+".attach")
	var l link.Link
	switch h.kind {
	case hookFEntry, hookFExit, hookRawTP:
		l, err = link.AttachTracing(link.TracingOptions{Program: prog, AttachType: h.attachType})
	case hookTracepoint:
		l, err = link.Tracepoint("syscalls", strings.TrimPrefix(h.attachTo, "syscalls/"), prog, nil)
	case hookCgroupAddr, hookCgroupSKB, hookSockOps, hookCgroupSock, hookCgroupSockopt:
		path, perr := probeCgroupPath(cg, cgErr)
		if perr != nil {
			out.Detail = "attach: no probe cgroup: " + perr.Error()
			return out
		}
		l, err = link.AttachCgroup(link.CgroupOptions{Path: path, Attach: h.attachType, Program: prog})
		if err != nil {
			return cgroupAttachFailure(h, out, err, path)
		}
	}
	endAttach()
	if err != nil {
		return hookAttachFailure(h, out, err)
	}
	endDetach := startphase.Begin(nil, phase+".detach")
	cerr := l.Close()
	endDetach()
	if cerr != nil {
		out.Detail = "detach: " + cerr.Error()
		return out
	}
	out.Attached = true
	return out
}

// cgroupAttachFailure is a cgroup row's attach failure. An EPERM names its likely cause in the words a run's own
// Attach refusal uses (cgroupenforce.AttachConflictHint, §6 E36): D7 attaches to a scratch cgroup in
// the subtree runs live in, so a non-overridable program above it, which would refuse every run's links, fails
// the row here first.
func cgroupAttachFailure(h hook, out HookResult, err error, path string) HookResult {
	out = hookAttachFailure(h, out, err)
	if errors.Is(err, unix.EPERM) {
		out.Detail += "; " + cgroupenforce.AttachConflictHint(path)
	}
	return out
}

func hookAttachFailure(h hook, out HookResult, err error) HookResult {
	out.Detail = "attach: " + verifierTail(err)
	if h.optional && h.kind == hookTracepoint && bpfobj.ExecResultAttachUnavailable(h.program, err) {
		out.Absent = true
		out.Attached = false
		out.Detail += "; optional exec outcome link unavailable; supervisor decides every exec (no fast handover); a failed exec's errno is not recorded"
	}
	return out
}

// libTarget is the system libssl D7 attaches capture's rows to, or why there is none.
type libTarget struct {
	path string
	err  error
}

// testCaptureHook runs one capture row: load uprobe_ssl's program with its maps unpinned, as a tier
// hook's is, then attach it to lib at the first of the row's symbols the library exports. The attach
// is the perf_event_open on the uprobe PMU that capture makes, scoped to doctor's own pid: doctor maps
// no libssl, so the kernel places no breakpoint in any process for the length of the probe, where an
// unscoped uprobe would place one in every process on the host that maps the library.
func testCaptureHook(h hook, kernelBTF *btf.Spec, lib libTarget, load objectLoader) HookResult {
	out := HookResult{Hook: h.Name, Object: string(h.object), Capture: true}
	// Recorded before the load, because whether there is a library is independent of whether this kernel
	// loads the program: captureSummary says "no system libssl found" only when none was.
	if lib.err == nil {
		out.Target = lib.path
	}
	prog, standIn, err := loadHookProgram(h, kernelBTF, load)
	out.StandIn = standIn
	if err != nil {
		out.Detail = "load: " + verifierTail(err)
		return out
	}
	defer func() { _ = prog.Close() }()
	out.Loaded = true
	if lib.err != nil {
		out.LoadOnly = true
		out.Detail = "attach not tested: " + lib.err.Error()
		return out
	}
	ex, err := link.OpenExecutable(lib.path)
	if err != nil {
		out.Detail = "attach: " + err.Error()
		return out
	}
	opts := captureUprobeOptions()
	for _, sym := range h.symbols {
		var l link.Link
		if h.kind == hookUretprobe {
			l, err = ex.Uretprobe(sym, prog, opts)
		} else {
			l, err = ex.Uprobe(sym, prog, opts)
		}
		if errors.Is(err, link.ErrNoSymbol) {
			continue
		}
		if err != nil {
			out.Detail = fmt.Sprintf("attach at %s: %s", sym, verifierTail(err))
			return out
		}
		if cerr := l.Close(); cerr != nil {
			out.Detail = "detach: " + cerr.Error()
			return out
		}
		out.Attached = true
		out.Detail = "attached at " + sym
		return out
	}
	out.LoadOnly = true
	out.Detail = fmt.Sprintf("attach not tested: %s exports none of %s", lib.path, strings.Join(h.symbols, ", "))
	return out
}

// captureUprobeOptions scopes a capture row's attach to doctor's own pid (R27 D7). Unscoped, the uprobe PMU
// places the breakpoint in every process on the host that maps the library, live agents included, for the
// length of the probe; doctor maps no libssl, so scoped to itself it places none.
func captureUprobeOptions() *link.UprobeOptions { return &link.UprobeOptions{PID: os.Getpid()} }

// libsslName is the SONAME shape capture's library discovery matches (capture-derive.md R4;
// internal/runtime/capture/uprobe's libsslName): libssl.so, libssl.so.3, libssl.so.1.1.
var libsslName = regexp.MustCompile(`^libssl\.so(\.[0-9]+)*$`)

// multiarchTriplet is the Debian multiarch directory name of this binary's architecture, "" where
// it has none this probe knows.
var multiarchTriplet = map[string]string{"amd64": "x86_64-linux-gnu", "arm64": "aarch64-linux-gnu"}[runtime.GOARCH]

// libsslDirs lists where distributions install libssl, in the order D7 looks: Fedora, RHEL and SUSE's
// lib64, Debian's multiarch directory for this architecture (not another architecture's, whose libssl
// the agent would not map), Arch and Alpine's /usr/lib, the same under an unmerged /lib, then
// /usr/local.
func libsslDirs() []string {
	dirs := []string{"/usr/lib64"}
	if multiarchTriplet != "" {
		dirs = append(dirs, "/usr/lib/"+multiarchTriplet)
	}
	dirs = append(dirs, "/usr/lib", "/lib64")
	if multiarchTriplet != "" {
		dirs = append(dirs, "/lib/"+multiarchTriplet)
	}
	return append(dirs, "/lib", "/usr/local/lib64", "/usr/local/lib")
}

// systemLibSSL finds the libssl D7 attaches capture's rows to: the first regular file named like a
// libssl in the first of dirs that has one, the highest-sorting name first so libssl.so.3 comes
// before the libssl.so development link. Any one answers D7's question, which is whether this
// kernel loads and attaches capture's programs at all; which library an agent maps is capture's own
// per-process discovery (R4), which doctor does not repeat.
func systemLibSSL(dirs []string) libTarget {
	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		var names []string
		for _, e := range entries {
			if libsslName.MatchString(e.Name()) {
				names = append(names, e.Name())
			}
		}
		sort.Sort(sort.Reverse(sort.StringSlice(names)))
		for _, name := range names {
			path := filepath.Join(dir, name)
			if fi, err := os.Stat(path); err == nil && fi.Mode().IsRegular() {
				return libTarget{path: path}
			}
		}
	}
	return libTarget{err: fmt.Errorf("no system libssl found in %s", strings.Join(dirs, " "))}
}

// hookInBTF is I2's pre-load check: the kernel's BTF declares the attach point as the kind of type
// it is, a function for fentry and LSM (bpf_lsm_<hook>) and the btf_trace_<tracepoint> typedef for a
// BTF tracepoint. btf.Spec.TypeByName fills a pointer to the concrete type it is asked for, and
// refuses a pointer to a nil Type interface for every name ("points to a nil Type"), which is how
// this check once reported every such hook absent on a kernel that has them all.
func hookInBTF(spec *btf.Spec, h hook) error {
	if h.kind == hookRawTP {
		var td *btf.Typedef
		return spec.TypeByName(h.btfName, &td)
	}
	var fn *btf.Func
	return spec.TypeByName(h.btfName, &fn)
}

// loadHookProgram loads the program D7 tests at one hook: the object's own program, or a minimal one
// (standIn) when this binary carries no objects. A binary without
// them still has a kernel worth describing, and the tier it cannot build is reported by the tier
// derivation (enforce.Buildable) rather than once per hook here.
func loadHookProgram(h hook, kernelBTF *btf.Spec, load objectLoader) (prog *ebpf.Program, standIn bool, err error) {
	spec, err := load(h.object)
	if errors.Is(err, bpfobj.ErrNotGenerated) {
		prog, err = ebpf.NewProgram(minimalProgram(h))
		return prog, true, err
	}
	if err != nil {
		return nil, false, err
	}
	if spec.Programs[h.program] == nil {
		return nil, false, fmt.Errorf("object %s has no program %s", h.object, h.program)
	}
	// Every map the objects declare is LIBBPF_PIN_BY_NAME, and a pinned map of this build is the one a
	// live run is using. Unpinned, each is D7's own and dies with the program that references it
	// (I7, §6 E28).
	for _, m := range spec.Maps {
		m.Pinning = ebpf.PinNone
	}
	opts := &ebpf.CollectionOptions{Programs: bpfobj.LoadOptions()} // the zero options outside a timed test build
	if kernelBTF != nil {
		opts.Programs.KernelTypes = kernelBTF
	}
	prog, err = loadOneProgram(spec, h.program, opts)
	return prog, false, err
}

// loadOneProgram loads one program of a collection with only the maps it references. LoadAndAssign
// is cilium/ebpf's lazy loader — NewCollection would create every map of the object for every hook,
// an 8 MiB ring buffer among them, and fail every hook of an object for one program the verifier
// refuses — and it takes the program's name from a struct tag, so the struct is built for that name.
func loadOneProgram(spec *ebpf.CollectionSpec, name string, opts *ebpf.CollectionOptions) (*ebpf.Program, error) {
	typ := reflect.StructOf([]reflect.StructField{{
		Name: "Program",
		Type: reflect.TypeFor[*ebpf.Program](),
		Tag:  reflect.StructTag(`ebpf:"` + name + `"`),
	}})
	v := reflect.New(typ)
	if err := spec.LoadAndAssign(v.Interface(), opts); err != nil {
		// The verifier's own words name the instruction or BTF field that failed (E31); the
		// struct-assignment wrapping around them names nothing an operator can act on.
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			return nil, fmt.Errorf("program %s: %w", name, ve)
		}
		return nil, err
	}
	prog, _ := v.Elem().Field(0).Interface().(*ebpf.Program)
	if prog == nil {
		return nil, fmt.Errorf("program %s: the loader returned none", name)
	}
	return prog, nil
}

// minimalProgram is the stand-in D7 loads at a hook with no program to load: it returns the hook type's
// neutral value — 0 (allow) for tracing and LSM, and 1 for the CGROUP_SOCK_ADDR family, whose
// neutral value is 1 (docs/p0/enforce-cgroup-observe.md R1).
func minimalProgram(h hook) *ebpf.ProgramSpec {
	ret := int32(0)
	if h.kind == hookCgroupAddr || h.kind == hookCgroupSKB || h.kind == hookCgroupSock || h.kind == hookCgroupSockopt {
		ret = 1
	}
	ps := &ebpf.ProgramSpec{
		Name:         "tego_probe",
		License:      "GPL", // a tracing or LSM program is refused at load without a GPL licence
		Instructions: asm.Instructions{asm.Mov.Imm(asm.R0, ret), asm.Return()},
	}
	switch h.kind {
	case hookFEntry, hookFExit, hookRawTP:
		ps.Type, ps.AttachType, ps.AttachTo = ebpf.Tracing, h.attachType, h.attachTo
	case hookCgroupAddr:
		ps.Type, ps.AttachType = ebpf.CGroupSockAddr, h.attachType
	case hookCgroupSKB:
		ps.Type, ps.AttachType = ebpf.CGroupSKB, h.attachType
	case hookSockOps:
		ps.Type, ps.AttachType = ebpf.SockOps, h.attachType
	case hookCgroupSock:
		ps.Type, ps.AttachType = ebpf.CGroupSock, h.attachType
	case hookCgroupSockopt:
		ps.Type, ps.AttachType = ebpf.CGroupSockopt, h.attachType
	case hookUprobe, hookUretprobe:
		ps.Type = ebpf.Kprobe
	case hookTracepoint:
		ps.Type = ebpf.TracePoint
	}
	return ps
}

// probeCgroupPath is the cgroup a CGROUP_SOCK_ADDR program is attached to, or why there is none. A
// caller may hold neither a cgroup nor an error — testHook is also driven with both nil — and that
// has to be an answer, not a nil dereference in the middle of a root doctor run.
func probeCgroupPath(cg *scratchCgroup, cgErr error) (string, error) {
	switch {
	case cgErr != nil:
		return "", cgErr
	case cg == nil:
		return "", errors.New("none was made")
	}
	return cg.path, nil
}

// verifierTail shortens a verifier rejection to its last lines, which name the failing instruction
// or the missing BTF field (E31).
func verifierTail(err error) string {
	const maxLines = 3
	msg := err.Error()
	lines := strings.Split(strings.TrimRight(msg, "\n"), "\n")
	if len(lines) <= maxLines {
		return strings.Join(lines, "; ")
	}
	return "... " + strings.Join(lines[len(lines)-maxLines:], "; ")
}

// scratchCgroup is the throwaway cgroup D7 attaches its cgroup programs to.
type scratchCgroup struct{ path string }

// newScratchCgroup makes an empty cgroup under the subtree delegated to the invoking uid — the same
// subtree D3 confirmed is writable, not root's own, so `sudo tego doctor` probes where a run would
// actually live. It holds no process, so an attached program cannot affect anything while the probe
// runs.
func newScratchCgroup(uid int) (*scratchCgroup, error) {
	fs, err := cgroup.Detect(uid)
	if err != nil {
		return nil, err
	}
	path, err := makeScratchDir(fs.Root(), probeCgroupPrefix)
	if err != nil {
		return nil, err
	}
	return &scratchCgroup{path: path}, nil
}

// remove deletes the probe cgroup; a failure is not worth reporting, since the next boot clears it.
func (c *scratchCgroup) remove() { _ = os.Remove(c.path) }

// bpfLSMRuns is D6's functional half (docs/ARCHITECTURE.md §10): attach a counting BPF LSM program
// to file_open, open a throwaway file, and require the counter to have moved. Activation is silent —
// a program attaches whether or not bpf is an active LSM and then never runs — so only this answers
// the question. It creates no inode-storage map, which on kernels below 7.1.4 would corrupt
// inode->i_security while BPF LSM is inactive.
func bpfLSMRuns() (bool, error) {
	memlockOnce.Do(raiseMemlock)
	counter, err := ebpf.NewMap(&ebpf.MapSpec{Name: "tego_probe", Type: ebpf.Array, KeySize: 4, ValueSize: 8, MaxEntries: 1})
	if err != nil {
		return false, fmt.Errorf("create the probe counter: %w", err)
	}
	defer func() { _ = counter.Close() }()

	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Name:       "tego_probe",
		Type:       ebpf.LSM,
		AttachType: ebpf.AttachLSMMac,
		AttachTo:   "file_open",
		License:    "GPL",
		Instructions: asm.Instructions{
			// key = 0 on the stack
			asm.StoreImm(asm.RFP, -4, 0, asm.Word),
			asm.LoadMapPtr(asm.R1, counter.FD()),
			asm.Mov.Reg(asm.R2, asm.RFP),
			asm.Add.Imm(asm.R2, -4),
			asm.FnMapLookupElem.Call(),
			asm.JEq.Imm(asm.R0, 0, "out"),
			asm.LoadImm(asm.R1, 1, asm.DWord),
			asm.StoreXAdd(asm.R0, asm.R1, asm.DWord),
			// Always allow: a non-zero return from an LSM program denies the operation.
			asm.Mov.Imm(asm.R0, 0).WithSymbol("out"),
			asm.Return(),
		},
	})
	if err != nil {
		return false, fmt.Errorf("load the counting program: %s", verifierTail(err))
	}
	defer func() { _ = prog.Close() }()

	l, err := link.AttachLSM(link.LSMOptions{Program: prog})
	if err != nil {
		return false, fmt.Errorf("attach to file_open: %w", err)
	}
	defer func() { _ = l.Close() }()

	f, err := os.Open(os.DevNull)
	if err != nil {
		return false, fmt.Errorf("open %s: %w", os.DevNull, err)
	}
	_ = f.Close()

	var n uint64
	if err := counter.Lookup(uint32(0), &n); err != nil {
		return false, fmt.Errorf("read the probe counter: %w", err)
	}
	return n > 0, nil
}
