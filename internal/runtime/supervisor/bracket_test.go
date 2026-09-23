// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"encoding/binary"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// execveAtNR is this architecture's execveat number.
func execveAtNR() int32 {
	if nativeAuditArch() == auditArchARM {
		return nrARMExecveAt
	}
	return nrX86ExecveAt
}

// symlinkAtNR is this architecture's symlinkat number.
func symlinkAtNR() int32 {
	if nativeAuditArch() == auditArchARM {
		return nrARMSymlinkAt
	}
	return nrX86SymlinkAt
}

// TestExecveAtEmptyPathIsBracketed is R2 with no exception for record-only handlers.
//
// execveat(fd, "", argv, envp, AT_EMPTY_PATH) names the binary by descriptor alone, so the path comes
// from readlink("/proc/<pid>/fd/<dirfd>"). That branch reached the readlink with no ID_VALID before it
// and none after — the only liveness test was an `if n.gone` that nothing in the branch had set. Every
// other path read in the package brackets on both sides, because /proc is keyed by a pid and only
// ID_VALID, keyed by the notification id, says that pid is still the task that trapped rather than a
// reused one (E3). Unbracketed, a dead notification still had its /proc read and still produced an exec
// event, naming whatever binary the reusing process happened to hold on that descriptor number.
func TestExecveAtEmptyPathIsBracketed(t *testing.T) {
	f := newFake()
	f.stale[7] = true // the trapping thread is already gone when the handler runs
	f.links["/proc/4242/fd/5"] = "/bin/sh"
	l, sink := newTestLoop(t, f, testPolicy(nil, nil, nil))

	// argv is NULL, so nothing after the path read reaches an ID_VALID of its own: the pre-read check is
	// the only thing standing between a stale notification and a recorded exec.
	l.handle(notifFor(execveAtNR(), 4242, 5, 0, 0, 0, uint64(unix.AT_EMPTY_PATH)))

	if f.readlinks != 0 {
		t.Errorf("read /proc/<pid>/fd/<dirfd> %d times for a notification the kernel had already reported gone (R2, E3)", f.readlinks)
	}
	if evs := sink.all(); len(evs) != 0 {
		t.Errorf("recorded %d exec events for a dead notification: %+v", len(evs), evs[0])
	}
}

// TestExecIdentityIsBracketed is R2 and E3 for the exec line's identity: Tgid and the two ProcStat reads are
// keyed by the bare tid, after the last ID_VALID of the path and argv reads. A task SIGKILLed and reaped there,
// its tid reused, gave the line another process's exec_id and parent_exec_id. The identity is now trusted only
// with an ID_VALID after it; a notification gone by then is not answered and writes no line.
func TestExecIdentityIsBracketed(t *testing.T) {
	f := newFake()
	f.links["/proc/4242/fd/5"] = "/usr/bin/python3"
	f.stats[4242] = procStat{ppid: 1, start: 99}
	l, sink := newTestLoop(t, f, testPolicy(nil, nil, nil))
	l.k = &staleAfterStatKernel{fakeKernel: f}

	l.handle(notifFor(execveAtNR(), 4242, 5, 0, 0, 0, uint64(unix.AT_EMPTY_PATH)))

	if f.respCount() != 0 {
		got, _ := f.lastResp()
		t.Errorf("answered %+v for a notification whose id went stale across the identity reads (R19)", got)
	}
	if evs := sink.all(); len(evs) != 0 {
		t.Errorf("recorded %d exec events with an identity read across the target's death (R2): %+v", len(evs), evs[0])
	}
}

// staleAfterStatKernel makes the notification go stale the moment ProcStat has read the task.
type staleAfterStatKernel struct{ *fakeKernel }

func (k *staleAfterStatKernel) ProcStat(pid int) (int, uint64, error) {
	ppid, start, err := k.fakeKernel.ProcStat(pid)
	k.mu.Lock()
	k.stale[7] = true
	k.mu.Unlock()
	return ppid, start, err
}

// TestExecveAtEmptyPathStillRecordsALiveExec is the other half: the bracket must not cost the record of
// an exec whose notification is live.
func TestExecveAtEmptyPathStillRecordsALiveExec(t *testing.T) {
	f := newFake()
	f.links["/proc/4242/fd/5"] = "/usr/bin/python3"
	f.stats[4242] = procStat{ppid: 1, start: 99}
	l, sink := newTestLoop(t, f, testPolicy(nil, nil, nil))

	l.handle(notifFor(execveAtNR(), 4242, 5, 0, 0, 0, uint64(unix.AT_EMPTY_PATH)))

	ev := sink.one(t)
	var p execPayload
	if err := ev.DecodePayload(&p); err != nil {
		t.Fatalf("payload: %v", err)
	}
	if p.Path != "/usr/bin/python3" {
		t.Errorf("path = %q, want the binary the descriptor names", p.Path)
	}
}

// TestSymlinkTargetIsRebracketed is R2's second half — "re-checked with another ID_VALID immediately
// before the data is trusted" — for the one read that had the pre-check and not the post-check.
//
// recordSymlink reads the created link path (bracketed on both sides by reader.path) and then the link's
// target with a bare cstring: one ID_VALID before it, none after. A target that dies during that read
// left the bytes read out of a pid that may already belong to another process, and they went straight
// into the event's path2 with a CONTINUE answered for a notification that was no longer there.
//
// staleAfter places the death exactly inside that bracket: the three checks the link path and the
// pre-read need are answered live, and the fourth — the re-check this fix adds — is the first to report
// the id gone.
func TestSymlinkTargetIsRebracketed(t *testing.T) {
	const targetAddr, linkAddr = 0x30000, 0x31000
	f := newFake()
	f.put(targetAddr, []byte("/etc/shadow\x00"))
	f.put(linkAddr, []byte("/work/link\x00"))
	f.staleAfter = 3
	l, sink := newTestLoop(t, f, testPolicy(nil, nil, nil))

	l.handle(notifFor(symlinkAtNR(), 4242, targetAddr, argCWD, linkAddr))

	if f.respCount() != 0 {
		got, _ := f.lastResp()
		t.Errorf("answered %+v for a notification whose id went stale mid-read (R19)", got)
	}
	if evs := sink.all(); len(evs) != 0 {
		t.Errorf("recorded %d events from bytes read across the target's death (R2)", len(evs))
	}
}

// TestSymlinkStillRecordsALiveLink guards the same handler's normal path against the added check.
func TestSymlinkStillRecordsALiveLink(t *testing.T) {
	const targetAddr, linkAddr = 0x30000, 0x31000
	f := newFake()
	f.put(targetAddr, []byte("/etc/shadow\x00"))
	f.put(linkAddr, []byte("/work/link\x00"))
	l, sink := newTestLoop(t, f, testPolicy(nil, nil, nil))

	l.handle(notifFor(symlinkAtNR(), 4242, targetAddr, argCWD, linkAddr))

	if got, _ := f.lastResp(); got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE == 0 {
		t.Fatalf("response = %+v, want CONTINUE (R17)", got)
	}
	if len(sink.all()) != 1 {
		t.Fatalf("events = %d, want one", len(sink.all()))
	}
}

// TestRelativePathDirfdReadlinkIsRebracketed is R2's second half for the last unbracketed read in the
// package: the dirfd readlink inside reader.resolve.
//
// A relative pathname argument is only a path once it is joined to its dirfd's directory, and that
// directory comes from readlink("/proc/<pid>/cwd") or "/proc/<pid>/fd/<n>" — addressed by the bare pid the
// notification carried. reader.path bracketed the *memory* read of the pathname on both sides and then
// left the /proc read after the last check, so a target that died inside that window had its base
// directory taken from whatever process reused the pid, concatenated with the agent's relative path, and
// appended to the run's ledger as a path the agent never touched. seccomp_unotify(2) names the same
// hazard for /proc/tid/mem: "the memory of the wrong process in the event that the target terminates and
// its ID is recycled by another (unrelated) thread". E9 covers dirfd *number* reuse by the live target and
// E3 covers pid reuse for a memory read; this is the pid-reuse variant of the readlink (E9b).
//
// staleAfter places the death exactly inside that bracket: the two checks reader.path's own memory read
// needs are answered live, and the third — the re-check this fix adds after the readlink — is the first
// to report the id gone.
func TestRelativePathDirfdReadlinkIsRebracketed(t *testing.T) {
	const pathAddr = 0x40000
	f := newFake()
	f.put(pathAddr, cstr("out.txt"))
	f.links["/proc/4242/cwd"] = "/work"
	f.staleAfter = 2
	l, sink := newTestLoop(t, f, testPolicy(nil, nil, nil))

	l.handle(notifFor(openAtNRForTest(), 4242, argCWD, pathAddr, uint64(unix.O_WRONLY|unix.O_CREAT)))

	if f.respCount() != 0 {
		got, _ := f.lastResp()
		t.Errorf("answered %+v for a notification whose id went stale across the dirfd readlink (R19)", got)
	}
	if evs := sink.all(); len(evs) != 0 {
		t.Errorf("recorded %d events from a path rooted in a pid that may already belong to another process (R2, E3): %+v", len(evs), evs[0])
	}
}

// TestRelativePathStillResolvesForALiveTarget guards the normal path against the added check: the
// re-check costs one ioctl on a relative path and must not cost the record.
func TestRelativePathStillResolvesForALiveTarget(t *testing.T) {
	const pathAddr = 0x40000
	f := newFake()
	f.put(pathAddr, cstr("out.txt"))
	f.links["/proc/4242/cwd"] = "/work"
	l, sink := newTestLoop(t, f, testPolicy(nil, nil, nil))

	l.handle(notifFor(openAtNRForTest(), 4242, argCWD, pathAddr, uint64(unix.O_WRONLY|unix.O_CREAT)))

	if got, _ := f.lastResp(); got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE == 0 {
		t.Fatalf("response = %+v, want CONTINUE (R15)", got)
	}
	ev := sink.one(t)
	var p record.FSPayload
	if err := ev.DecodePayload(&p); err != nil {
		t.Fatalf("payload: %v", err)
	}
	if p.Path != "/work/out.txt" {
		t.Errorf("path = %q, want the relative name joined to the dirfd's directory (R6)", p.Path)
	}
}

// openAtNRForTest is this architecture's openat number. It carries the ForTest suffix because the
// package's arch tables are the normative source (R1, I8) and this is only a test's view of them.
func openAtNRForTest() int32 {
	if nativeAuditArch() == auditArchARM {
		return nrARMOpenAt
	}
	return nrX86OpenAt
}

// TestSignalScopeReadsAreBracketed is R2 for the signal-scope arm (R33): F_SETOWN_EX's and FIOSETOWN's
// owner are read from the target's memory and kill(0)'s group from /proc/<tid>/stat, all keyed by the bare
// tid the notification carried. With no ID_VALID around them, a trapping thread that died and whose tid was
// reused had a stranger's memory or group decided on, and the refused line carried that foreign target.
// Stale before the handler runs: nothing is read. Stale across the reads: nothing is answered or recorded.
func TestSignalScopeReadsAreBracketed(t *testing.T) {
	const agent, launcher, ownerAt = 100, 50, 0x1000
	fcntl, kill := int32(nrX86Fcntl), int32(nrX86Kill)
	if nativeAuditArch() == auditArchARM {
		fcntl, kill = nrARMFcntl, nrARMKill
	}
	setownEx := make([]byte, 8)
	binary.LittleEndian.PutUint32(setownEx, 1)
	binary.LittleEndian.PutUint32(setownEx[4:], launcher)
	fioOwner := make([]byte, 4)
	binary.LittleEndian.PutUint32(fioOwner, launcher)
	for _, tc := range []struct {
		name  string
		owner []byte
		n     func() *notif
	}{
		{"F_SETOWN_EX", setownEx, func() *notif { return notifFor(fcntl, agent, 3, unix.F_SETOWN_EX, ownerAt) }},
		{"FIOSETOWN", fioOwner, func() *notif { return notifFor(ioctlNR(), agent, 3, ioctlFIOSETOWN, ownerAt) }},
		{"kill(0)", nil, func() *notif { return notifFor(kill, agent, 0, 9) }},
	} {
		for _, when := range []string{"before", "across"} {
			t.Run(tc.name+" stale "+when, func(t *testing.T) {
				f := newFake()
				f.cgroups = map[int]string{agent: "/run.scope", launcher: "/other.scope"}
				f.pgrps = map[int]int{agent: launcher, launcher: launcher}
				if tc.owner != nil {
					f.put(ownerAt, tc.owner)
				}
				if when == "before" {
					f.stale[7] = true
				} else {
					f.staleAfter = 1 // the pre-read check is live; the re-check after the reads is not
				}
				pol := testPolicy(nil, nil, nil)
				pol.Cgroup = "/run.scope"
				l, sink := newTestLoop(t, f, pol)
				l.handle(tc.n())
				if when == "before" && (f.memReads != 0 || f.groupScans != 0) {
					t.Errorf("read %d memory ranges and scanned groups %d times for a dead notification (R2, E3)",
						f.memReads, f.groupScans)
				}
				if f.respCount() != 0 {
					got, _ := f.lastResp()
					t.Errorf("answered %+v for a notification whose id went stale (R19)", got)
				}
				if evs := sink.all(); len(evs) != 0 {
					t.Errorf("recorded %d events decided on data read from a reusable tid (R2): %+v", len(evs), evs[0])
				}
			})
		}
	}
}

// TestTCPULPNameReadIsBracketed is R2 and I1 for setsockopt(TCP_ULP)'s refused line (ADR 0018 (7)): the ULP's name is
// read from the target's memory for the line alone, which I1 brackets as it does a read for a decision. Read with no
// ID_VALID around it, a trapping thread that died and whose pid was reused had a stranger's bytes written into the
// line as the name it asked for. Stale before the handler runs: nothing is read. Stale across the read: nothing is
// answered or recorded.
func TestTCPULPNameReadIsBracketed(t *testing.T) {
	const at = 0x7000
	nr := int32(nrX86Setsockopt)
	if nativeAuditArch() == auditArchARM {
		nr = nrARMSetsockopt
	}
	for _, when := range []string{"before", "across"} {
		t.Run("stale "+when, func(t *testing.T) {
			f := newFake()
			f.put(at, []byte("smc\x00"))
			if when == "before" {
				f.stale[7] = true
			} else {
				f.staleAfter = 1 // the pre-read check is live; the re-check after the read is not
			}
			l, sink := newTestLoop(t, f, testPolicy(nil, nil, nil))
			l.handle(notifFor(nr, 4242, 3, unix.SOL_TCP, unix.TCP_ULP, at, 4))
			if when == "before" && f.memReads != 0 {
				t.Errorf("read the target's memory %d times for a dead notification (R2, E3)", f.memReads)
			}
			if f.respCount() != 0 {
				got, _ := f.lastResp()
				t.Errorf("answered %+v for a notification whose id went stale (R19)", got)
			}
			if evs := sink.all(); len(evs) != 0 {
				t.Errorf("recorded %d events naming bytes read from a reusable pid (R2, I1): %+v", len(evs), evs[0])
			}
		})
	}
}
