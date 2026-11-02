// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/liveblock"
	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/internal/runtime/ask"
	"github.com/attention-span-ai/tego/internal/runtime/deputy"
	"github.com/attention-span-ai/tego/pkg/policy/gate"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// inProcessDeputy is the open deputy's work done in this process: the production walk (DeputyPin) from the test's
// own thread, and the deputy's reopen of the pin. It stands for the deputy where only the loop's decisions are under
// test; the real deputy, in the run's domain, is the integration tests' (held_integration_test.go).
type inProcessDeputy struct {
	tid    int
	mu     sync.Mutex
	opened []int // the flags of every open asked for
	pins   int   // how many pins were asked for
	// openErr, when set, is what every open fails with, as the kernel answered the deputy's open in the run.
	openErr error
	// pinErr, when set, is what every pin fails with, before any walk.
	pinErr error
	// beforeOpen and afterOpen, when set, run around the deputy's open of the pin (and leaf): what a sibling of the
	// task does between the pin and the open, or between the open and the loop's identity check.
	beforeOpen, afterOpen func(pin int, leaf string)
	// afterPin, when set, runs once the deputy's walk pinned something: what a sibling does before the loop reads the
	// pin.
	afterPin func()
	// swapTo, when set, is the pathname the deputy's walk takes in place of the one the loop copied: what a sibling's
	// rewrite of the pathname between the loop's copy and the deputy's lookup makes the kernel see.
	swapTo string
	// slowPin, when set, runs before the pin as a reply that is late does (a lookup stalled on a mount): then the
	// caller's wait is asked, and a false answer abandons the pin, as deputy.Client's receive does.
	slowPin func()
}

func (d *inProcessDeputy) Pin(q deputy.PinQuery, wait func() bool) (deputy.Pinned, error) {
	d.mu.Lock()
	d.pins++
	d.mu.Unlock()
	if d.pinErr != nil {
		return deputy.Pinned{FD: -1}, d.pinErr
	}
	if d.slowPin != nil {
		d.slowPin()
		if wait != nil && !wait() {
			return deputy.Pinned{FD: -1}, deputy.ErrAbandoned
		}
	}
	q.TID, q.TGID = d.tid, os.Getpid()
	if d.swapTo != "" {
		q.Path = d.swapTo
	}
	p, err := DeputyPin(q)
	if err == nil && d.afterPin != nil {
		d.afterPin()
	}
	return p, err
}

func (d *inProcessDeputy) PinOpenStart(deputy.PinQuery, int) (*deputy.Pending, error) {
	return nil, errors.New("no overlapped pin in process")
}

func (d *inProcessDeputy) Open(pin int, leaf string, flags int, mode uint32, _ int, _ func() bool) (int, error) {
	d.mu.Lock()
	d.opened = append(d.opened, flags)
	d.mu.Unlock()
	if d.openErr != nil {
		return -1, d.openErr
	}
	if d.beforeOpen != nil {
		d.beforeOpen(pin, leaf)
	}
	var fd int
	var err error
	if leaf != "" {
		fd, err = unix.Openat(pin, leaf, flags|unix.O_NOFOLLOW|unix.O_CLOEXEC, mode)
	} else {
		fd, err = unix.Open("/proc/self/fd/"+strconv.Itoa(pin), flags&^unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	}
	if err == nil && d.afterOpen != nil {
		d.afterOpen(pin, leaf)
	}
	return fd, err
}

func (d *inProcessDeputy) Outstanding() int64 { return 0 }

// heldAskKernel is askReadKernel (the real alternate open, a fake notification and delivery) with a held open's
// delivery and the task's identity read from the test's own thread.
type heldAskKernel struct {
	*askReadKernel
	heldDelivered []string // the contents of each held descriptor delivered
}

func (k *heldAskKernel) DeliverHeld(_ uint64, fd int, _ int) (int, error) {
	buf := make([]byte, 256)
	n, _ := unix.Pread(fd, buf, 0)
	k.sent()
	k.mu.Lock()
	defer k.mu.Unlock()
	k.heldDelivered = append(k.heldDelivered, string(buf[:max(n, 0)]))
	return 11, nil
}

func (k *heldAskKernel) TaskIdentity(int) (sys.TaskCreds, int, error) {
	return sysKernel{}.TaskIdentity(k.tid)
}

// heldAskFixture is a directory with a file the read gate scores into the ask range, a stand-in and a deny_read
// directory, and a loop at tier landlock with an open deputy.
type heldAskFixture struct {
	dir, target, standIn, denied string
	f                            *fakeKernel
	k                            *heldAskKernel
	dep                          *inProcessDeputy
	pol                          *Policy
	addr                         uint64
	planeAttrs                   bool                   // Options.PlaneAttrs: a decision plane decides the run
	snapshot                     func(path string) bool // Options.DenyReadSnapshot
	live                         func() *liveblock.Set  // Options.LiveBlocks
}

func newHeldAskFixture(t *testing.T) *heldAskFixture {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	x := &heldAskFixture{dir: dir, target: filepath.Join(dir, "token"), standIn: filepath.Join(dir, "stand-in"), denied: filepath.Join(dir, "vault")}
	if err := os.Mkdir(x.denied, 0o700); err != nil {
		t.Fatal(err)
	}
	for p, body := range map[string]string{x.target: "real secret", x.standIn: "fake credentials", filepath.Join(x.denied, "key"): "never"} {
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	tid := selfTask(t)
	x.f = newFake()
	x.k = &heldAskKernel{askReadKernel: &askReadKernel{fakeKernel: x.f, tid: tid}}
	x.dep = &inProcessDeputy{tid: tid}
	x.pol = testPolicy(nil, []agent.FSRule{{Path: x.denied, Resolved: x.denied, Kind: agent.FSDenyRead, Raw: x.denied}}, nil)
	x.pol.Rules.Tier = backend.TierLandlock
	x.pol.Rules.Workdir = dir
	x.pol.Rules.Gate = testGate(t, gate.ReadMatches, "token", 60).WithHeldCompletion()
	x.pol.Rules.AskConfig = &agent.AskConfig{Hold: agent.AskHoldConnect, Timeout: agent.Duration(time.Minute), MaxPending: 4}
	x.pol.Rules.OwnState = []string{filepath.Join(dir, "own")}
	x.pol.Rules.ContractPath = filepath.Join(dir, "contract", "agent.yaml")
	return x
}

func (x *heldAskFixture) loop(t *testing.T, answer func(ask.Request) ask.Decision) (*Loop, *testSink, *[]ask.Request) {
	t.Helper()
	var asked []ask.Request
	sink := &testSink{}
	l, err := New(testListener(), x.pol, sink, Options{kernel: x.k, openDeputy: x.dep, PlaneAttrs: x.planeAttrs, DenyReadSnapshot: x.snapshot, LiveBlocks: x.live, Ask: func(_ context.Context, req ask.Request) (ask.Decision, error) {
		asked = append(asked, req)
		return answer(req), nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(l.closeAskScopes)
	return l, sink, &asked
}

func (x *heldAskFixture) open(t *testing.T, l *Loop, path string, flags int) *notif {
	t.Helper()
	x.addr += 0x2000
	x.f.put(0x10000+x.addr, cstr(path))
	n := notifFor(nrFor(t, "openat"), 42, argCWD, 0x10000+x.addr, uint64(flags))
	l.handle(n)
	return n
}

// heldLine decodes one fs line's path, alternate_for, gate_facts and fd_delivered.
type heldLine struct {
	Path         string `json:"path"`
	AlternateFor string `json:"alternate_for"`
	GateFacts    string `json:"gate_facts"`
	FDDelivered  bool   `json:"fd_delivered"`
}

func decodeHeldLine(t *testing.T, ev *record.Event) heldLine {
	t.Helper()
	var p heldLine
	if err := json.Unmarshal(ev.Payload, &p); err != nil {
		t.Fatalf("payload %s: %v", ev.Payload, err)
	}
	return p
}

// Under gate.completion: held a read the gate scores into the ask range is held on the object the deputy pinned and
// asked about with an alternate's check, as a hold of the loop's own pin is (ADR 0057): an approval has the deputy
// open the target, and an alternate delivers the person's file in its place, read-only, never opened by the deputy,
// its line naming the stand-in with the target it stands for and gate_facts held_object; an alternate that fails its
// checks refuses the open on the pinned object, and nothing is delivered.
func TestHeldGateAskTakesAnAlternate(t *testing.T) {
	t.Run("approved", func(t *testing.T) {
		x := newHeldAskFixture(t)
		l, sink, asked := x.loop(t, func(ask.Request) ask.Decision { return ask.Decision{Approved: true, By: "uid:1 pid:2"} })
		n := x.open(t, l, x.target, unix.O_RDONLY|unix.O_CLOEXEC)
		if len(*asked) != 1 || (*asked)[0].Target != x.target || (*asked)[0].Alternates == nil {
			t.Fatalf("requests %+v: want one ask of the pinned target, taking an alternate", *asked)
		}
		if len(x.dep.opened) != 1 || len(x.k.heldDelivered) != 1 || x.k.heldDelivered[0] != "real secret" || !n.answered {
			t.Fatalf("deputy opens %v, delivered %q, answered %v: want the target opened by the deputy and delivered", x.dep.opened, x.k.heldDelivered, n.answered)
		}
		evs := sink.all()
		if len(evs) != 1 || evs[0].Authority != record.AuthorityHuman || evs[0].Verdict != record.VerdictAllow {
			t.Fatalf("lines %+v", evs)
		}
		if p := decodeHeldLine(t, evs[0]); p.Path != x.target || p.GateFacts != gateFactsHeld {
			t.Fatalf("approved line %s: want the target, gate_facts held_object", evs[0].Payload)
		}
	})
	t.Run("alternate", func(t *testing.T) {
		x := newHeldAskFixture(t)
		l, sink, asked := x.loop(t, func(req ask.Request) ask.Decision {
			if req.Alternates == nil {
				return ask.Decision{Reason: ask.ReasonDenied}
			}
			if resolved, err := req.Alternates.Check(altOf(t, x.standIn)); err != nil || resolved != x.standIn {
				t.Errorf("the check refused a good stand-in: %q %v", resolved, err)
			}
			return alternateDecision(t, x.standIn)
		})
		n := x.open(t, l, x.target, unix.O_RDONLY|unix.O_CLOEXEC)
		if len(*asked) != 1 {
			t.Fatalf("asked %d times", len(*asked))
		}
		if len(x.dep.opened) != 0 || len(x.k.heldDelivered) != 0 {
			t.Fatalf("the deputy opened %v and %q was delivered as held: an alternate never opens the target", x.dep.opened, x.k.heldDelivered)
		}
		if len(x.k.delivered) != 1 || x.k.delivered[0] != "fake credentials" || x.k.accmode[0] != unix.O_RDONLY || !n.answered {
			t.Fatalf("delivered %q mode %v answered %v: want the stand-in, read-only", x.k.delivered, x.k.accmode, n.answered)
		}
		evs := sink.all()
		if len(evs) != 1 || evs[0].Authority != record.AuthorityHuman || evs[0].Verdict != record.VerdictAllow {
			t.Fatalf("lines %+v", evs)
		}
		if p := decodeHeldLine(t, evs[0]); p.Path != x.standIn || p.AlternateFor != x.target || p.GateFacts != gateFactsHeld || !p.FDDelivered {
			t.Fatalf("the alternate's line %s: want the stand-in for the target, held_object, delivered", evs[0].Payload)
		}
	})
	// The gate scores the person's file as the agent's own open of it would be scored (alternateCheck):
	// one it refuses is refused by the check at answer time, and again when it is delivered, so a held ask's alternate is
	// no way past a gate rule that a hold of the loop's own pin keeps.
	t.Run("alternate the gate refuses", func(t *testing.T) {
		x := newHeldAskFixture(t)
		pem := filepath.Join(x.dir, "stand-in.pem")
		if err := os.WriteFile(pem, []byte("a key"), 0o600); err != nil {
			t.Fatal(err)
		}
		g, err := gate.New([]gate.Rule{{Predicate: gate.ReadMatches, Argument: "token", Score: 60}, {Predicate: gate.ReadMatches, Argument: "*.pem", Score: 90}}, 50, 80)
		if err != nil {
			t.Fatal(err)
		}
		x.pol.Rules.Gate = g.WithHeldCompletion()
		checked := false
		l, sink, _ := x.loop(t, func(req ask.Request) ask.Decision {
			if req.Alternates != nil {
				if _, err := req.Alternates.Check(altOf(t, pem)); err == nil {
					t.Errorf("the check took %s, a file the gate refuses", pem)
				}
				checked = true
			}
			return alternateDecision(t, pem)
		})
		x.open(t, l, x.target, unix.O_RDONLY)
		if !checked {
			t.Fatal("the request carried no alternate check")
		}
		if len(x.dep.opened) != 0 || len(x.k.heldDelivered) != 0 || len(x.k.delivered) != 0 {
			t.Fatalf("delivered %q / %q: an alternate the gate refuses is never delivered", x.k.heldDelivered, x.k.delivered)
		}
		res, _ := x.f.lastResp()
		evs := sink.all()
		if res.Error != -int32(unix.EACCES) || len(evs) != 1 || evs[0].Verdict != record.VerdictRefused || evs[0].Reason != record.ReasonAskUnavailable {
			t.Fatalf("answer %+v lines %+v: want EACCES, refused ask-unavailable", res, evs)
		}
	})
	t.Run("bad alternate", func(t *testing.T) {
		x := newHeldAskFixture(t)
		l, sink, _ := x.loop(t, func(ask.Request) ask.Decision { return alternateDecision(t, filepath.Join(x.denied, "key")) })
		n := x.open(t, l, x.target, unix.O_RDONLY)
		if len(x.dep.opened) != 0 || len(x.k.heldDelivered) != 0 || len(x.k.delivered) != 0 {
			t.Fatalf("delivered %q / %q after an alternate inside a deny_read", x.k.heldDelivered, x.k.delivered)
		}
		res, _ := x.f.lastResp()
		evs := sink.all()
		if res.Error != -int32(unix.EACCES) || len(evs) != 1 || evs[0].Verdict != record.VerdictRefused || evs[0].Reason != record.ReasonAskUnavailable {
			t.Fatalf("answer %+v lines %+v: want EACCES, refused ask-unavailable", res, evs)
		}
		if p := decodeHeldLine(t, evs[0]); p.Path != x.target || p.GateFacts != gateFactsHeld {
			t.Fatalf("the refusal's line %s: want the pinned target, held_object", evs[0].Payload)
		}
		_ = n
	})
}

// TestHeldOpenKernelErrnoExplainedByIdentity (GAPS C38): a decision plane keys some files at
// their own inodes (an fs.deny_write file entry, a linked file beneath a directory entry, RuleTable.DenyWriteLinked),
// so it refuses a write-open of a hard link to one made before the run, whose own path the model allows. The deputy's
// open meets that EACCES, and the open's one line names the refusal as the row keyed at that inode answers it,
// refused under the entry, where it kept the floor's allow with syscall_ret -13 and named no rule. Where no plane
// decides the run, the same EACCES stays unexplained.
func TestHeldOpenKernelErrnoExplainedByIdentity(t *testing.T) {
	for _, tc := range []struct {
		name          string
		plane, linked bool
		want          string // the refusal's rule, "" for the floor's allow
	}{
		{"file entry, plane", true, false, "fs.deny_write[./conf.yml]"},
		{"linked file, plane", true, true, "fs.deny_write[./deploy/]"},
		{"file entry, no plane", false, false, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			x := newHeldAskFixture(t)
			x.planeAttrs = tc.plane
			x.pol.Rules.Tier = backend.TierBPFLSM
			x.pol.Rules.FS = append(x.pol.Rules.FS, agent.FSRule{Path: x.dir, Resolved: x.dir, Kind: agent.FSWrite, Raw: x.dir, Access: agent.AccessWriteSet})
			file := filepath.Join(x.dir, "conf.yml")
			rule := agent.FSRule{Kind: agent.FSDenyWrite, Path: file, Resolved: file, Raw: "./conf.yml", Unenforced: true}
			if tc.linked {
				deploy := filepath.Join(x.dir, "deploy")
				if err := os.Mkdir(deploy, 0o755); err != nil {
					t.Fatal(err)
				}
				file = filepath.Join(deploy, "a")
				rule = agent.FSRule{Kind: agent.FSDenyWrite, Path: deploy, Resolved: deploy, Raw: "./deploy/", Unenforced: true}
				x.pol.Rules.DenyWriteLinked = []string{file}
			}
			x.pol.Rules.DenyWrite = []agent.FSRule{rule}
			alias := filepath.Join(x.dir, "alias")
			if err := os.WriteFile(file, []byte("conf"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Link(file, alias); err != nil {
				t.Fatal(err)
			}
			x.pol.Rules.Gate = testGate(t, gate.WriteOutsideWorktree, "", 90).WithHeldCompletion()
			x.dep.openErr = unix.EACCES
			l, sink, _ := x.loop(t, func(ask.Request) ask.Decision { return ask.Decision{} })
			x.open(t, l, alias, unix.O_WRONLY)
			if res, _ := x.f.lastResp(); res.Error != -int32(unix.EACCES) || len(x.dep.opened) != 1 {
				t.Fatalf("answer %+v, deputy opens %v: want the deputy's one open and its EACCES", res, x.dep.opened)
			}
			evs := sink.all()
			if len(evs) != 1 {
				t.Fatalf("lines %+v: want one", evs)
			}
			if tc.want == "" && (evs[0].Verdict != record.VerdictAllow || evs[0].Reason != "") {
				t.Fatalf("line %+v: want the floor's allow, no refusal reason", evs[0])
			}
			if tc.want != "" && (evs[0].Verdict != record.VerdictRefused || evs[0].Rule != tc.want || evs[0].Reason == "") {
				t.Fatalf("line %+v: want refused under %s", evs[0], tc.want)
			}
			var p struct {
				heldLine
				SyscallRet *int64 `json:"syscall_ret"`
			}
			if err := json.Unmarshal(evs[0].Payload, &p); err != nil || p.SyscallRet == nil || *p.SyscallRet != -int64(unix.EACCES) || p.Path != alias {
				t.Fatalf("line %s: want %s, syscall_ret -13", evs[0].Payload, alias)
			}
		})
	}
}

// An errno the deputy's open met in the run is the task's answer and the line's syscall_ret, and its verdict follows
// the recorder's rule for a kernel refusal (decide.ChainFS): an EACCES or EPERM the tier's model does not explain (the
// file's permission bits, a host LSM, a run mechanism this loop's names diverged from) keeps the floor's allow and
// names no contract refusal, as a write-open's ENOSPC does; one the model explains is that mechanism's refusal, under
// the model's rule. At tier bpflsm the plane refuses a write-open beneath a deny_read nested in a write entry (nearest
// wins), where the floor this loop shares with the copied path allows it.
func TestHeldOpenKernelErrnoIsTheResultNotARefusal(t *testing.T) {
	for _, tc := range []struct {
		name      string
		errno     unix.Errno
		flags     int
		tier      backend.Tier
		nested    bool
		refusedBy string // the model's rule when it explains the refusal, "" for the floor's allow
	}{
		{"read EACCES", unix.EACCES, unix.O_RDONLY, backend.TierLandlock, false, ""},
		{"read EPERM", unix.EPERM, unix.O_RDONLY | unix.O_NOATIME, backend.TierLandlock, false, ""},
		{"write ENOSPC", unix.ENOSPC, unix.O_WRONLY, backend.TierLandlock, false, ""},
		{"write EACCES unexplained at bpflsm", unix.EACCES, unix.O_WRONLY, backend.TierBPFLSM, false, ""},
		{"write EACCES the plane explains", unix.EACCES, unix.O_WRONLY, backend.TierBPFLSM, true, "fs.deny_read"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			x := newHeldAskFixture(t)
			x.pol.Rules.Tier = tc.tier
			x.pol.Rules.FS = append(x.pol.Rules.FS, agent.FSRule{Path: x.dir, Resolved: x.dir, Kind: agent.FSWrite, Raw: x.dir, Access: agent.AccessWriteSet})
			path := x.standIn
			if tc.nested {
				nested := filepath.Join(x.dir, "keys")
				if err := os.Mkdir(nested, 0o700); err != nil {
					t.Fatal(err)
				}
				path = filepath.Join(nested, "k")
				if err := os.WriteFile(path, []byte("k"), 0o600); err != nil {
					t.Fatal(err)
				}
				x.pol.Rules.FS = append(x.pol.Rules.FS, agent.FSRule{Path: nested, Resolved: nested, Kind: agent.FSDenyRead, Raw: nested})
			}
			x.pol.Rules.Gate = testGate(t, gate.ReadMatches, "*.env", 90).WithHeldCompletion()
			if tc.flags&unix.O_ACCMODE != unix.O_RDONLY {
				x.pol.Rules.Gate = testGate(t, gate.WriteOutsideWorktree, "", 90).WithHeldCompletion()
			}
			x.dep.openErr = tc.errno
			l, sink, asked := x.loop(t, func(ask.Request) ask.Decision { return ask.Decision{} })
			x.open(t, l, path, tc.flags)
			if len(*asked) != 0 || len(x.dep.opened) != 1 {
				t.Fatalf("asked %d, deputy opens %v: want one open, no ask", len(*asked), x.dep.opened)
			}
			res, _ := x.f.lastResp()
			if res.Error != -int32(tc.errno) {
				t.Fatalf("answer %+v, want the kernel's %v", res, tc.errno)
			}
			evs := sink.all()
			if len(evs) != 1 {
				t.Fatalf("lines %+v: want one", evs)
			}
			if tc.refusedBy == "" && (evs[0].Verdict != record.VerdictAllow || evs[0].Reason != "" || evs[0].Authority == record.AuthorityGate) {
				t.Fatalf("line %+v: want the floor's allow, no refusal reason", evs[0])
			}
			if tc.refusedBy != "" && (evs[0].Verdict != record.VerdictRefused || !strings.HasPrefix(evs[0].Rule, tc.refusedBy) || evs[0].Reason == "") {
				t.Fatalf("line %+v: want the model's refusal under %s", evs[0], tc.refusedBy)
			}
			var p struct {
				heldLine
				SyscallRet *int64 `json:"syscall_ret"`
			}
			if err := json.Unmarshal(evs[0].Payload, &p); err != nil || p.SyscallRet == nil || *p.SyscallRet != -int64(tc.errno) || p.Path != path || p.GateFacts != gateFactsHeld {
				t.Fatalf("line %s: want %s, held_object, syscall_ret -%d", evs[0].Payload, path, tc.errno)
			}
		})
	}
}

// A deputy that cannot answer refuses the held open held-unavailable (ADR 0041 D4), whatever socket error its client
// names: the race job's held race answered an agent's read-open ECONNRESET, the reset of a request socket its dead
// deputy left, and wrote it as an allowed open with that syscall_ret. The client's error was ErrUnavailable wrapping
// the errno, which this loop took for the walk's or the kernel's answer.
func TestHeldOpenDeputyUnavailableIsRefusedNotItsErrno(t *testing.T) {
	broke := fmt.Errorf("%w: receive: %w", deputy.ErrUnavailable, unix.ECONNRESET)
	for _, at := range []string{"pin", "open"} {
		t.Run(at, func(t *testing.T) {
			x := newHeldAskFixture(t)
			x.pol.Rules.FS = append(x.pol.Rules.FS, agent.FSRule{Path: x.dir, Resolved: x.dir, Kind: agent.FSWrite, Raw: x.dir, Access: agent.AccessWriteSet})
			x.pol.Rules.Gate = testGate(t, gate.ReadMatches, "*.env", 90).WithHeldCompletion()
			if at == "pin" {
				x.dep.pinErr = broke
			} else {
				x.dep.openErr = broke
			}
			l, sink, _ := x.loop(t, func(ask.Request) ask.Decision { return ask.Decision{} })
			x.open(t, l, x.standIn, unix.O_RDONLY)
			if res, _ := x.f.lastResp(); res.Error != -int32(refusalErrno) {
				t.Fatalf("answer %+v, want the held-unavailable refusal's %v, never the client's socket errno", res, refusalErrno)
			}
			evs := sink.all()
			if len(evs) != 1 || evs[0].Verdict != record.VerdictRefused || evs[0].Rule != ruleHeldUnavailable {
				t.Fatalf("lines %+v: want one refused %s", evs, ruleHeldUnavailable)
			}
			// At least: a notification over the soft ceiling counts one too (finish), as one under -race can be.
			if n := l.metrics.anomalies.Load(); n < 1 {
				t.Fatalf("anomalies %d, want the deputy's failure counted", n)
			}
		})
	}
}
