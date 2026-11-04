// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"

	"errors"
	"fmt"

	"os"
	"slices"

	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/attention-span-ai/tego/internal/doctor"
	"github.com/attention-span-ai/tego/internal/platform/proc"
	"github.com/attention-span-ai/tego/internal/platform/startphase"

	"github.com/attention-span-ai/tego/internal/runtime/cgroup"

	"github.com/attention-span-ai/tego/internal/runtime/deputy"
	"github.com/attention-span-ai/tego/internal/runtime/enforce/api"
	"github.com/attention-span-ai/tego/internal/runtime/launch"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// startChild is §4.1 steps 5-7: the subreaper flag, clone3 into the run cgroup, and the notify fd
// handed over through pidfd_getfd. The child is blocked on its ack read when this returns (R5).
func (r *runner) startChild(ctx context.Context) error {
	r.launcher = r.deps.Launcher
	if r.launcher == nil {
		r.launcher = &launch.Launcher{}
	}
	if err := r.launcher.SetSubreaper(); err != nil {
		return fmt.Errorf("runtime: %w", err)
	}
	spec, err := r.childSpec()
	if err != nil {
		return err
	}
	deputyEnd := -1
	if r.wantsDeputy() {
		l, stage, err := deputy.Socketpair()
		if err != nil {
			if err := r.deputyUnavailable(err); err != nil {
				return err
			}
		} else {
			deputyEnd = l
			spec.Deputy = os.NewFile(uintptr(stage), "deputy-stage")
		}
	}
	endStage := startphase.Begin(nil, "stage")
	child, err := r.launcher.Start(ctx, spec, r.cg.Dir())
	if spec.Deputy != nil {
		_ = spec.Deputy.Close() // the stage holds its own copy, and the deputy the only one once started
	}
	if err != nil {
		if deputyEnd >= 0 {
			_ = syscall.Close(deputyEnd)
		}
		return fmt.Errorf("runtime: start child: %w", err)
	}
	r.child = child
	fd, err := child.WaitNotifyFD(ctx)
	endStage()
	if err != nil {
		if deputyEnd >= 0 {
			_ = syscall.Close(deputyEnd)
		}
		return fmt.Errorf("runtime: notify fd: %w", r.stagePidsCap(err))
	}
	r.notifyFD = fd
	if deputyEnd >= 0 {
		// The stage reported only once the deputy said hello, or once it reported the deputy did not start, so the
		// hello (or the report) is already on the socket: the timeout only bounds a stage that closed it unwritten.
		c, err := deputy.Hello(deputyEnd, deputyHelloTimeout)
		if err != nil {
			_ = syscall.Close(deputyEnd)
			if err := r.deputyUnavailable(err); err != nil {
				return err
			}
		} else {
			r.deputy = c
			r.keepDeputy()
			if r.deps.Warn != nil {
				state, err := doctor.ReadLSMState()
				r.warnHeldLabel([]byte(strings.Join(state.Modules, ",")), err)
			}
		}
	}
	return r.arm()
}

// deputyHelloTimeout bounds the launcher's read of the open deputy's hello after the stage has reported.
const deputyHelloTimeout = 5 * time.Second

// keepDeputy names the open deputy, this process's child (CLONE_PARENT), for as long as the run lasts: the run's
// reaper leaves its zombie unreaped (launch.Child.KeepUnreaped), so the agent, which can end the deputy, cannot have
// its pid given to a later process of the run while the kernel recorder drops the deputy's records, and its start time
// is read now, before anything can reap it, so the recorder can tell its records from another process's
// (SetSkipProcess). closeDeputy reaps it once the run's last other process is gone.
func (r *runner) keepDeputy() {
	pid := r.deputy.PID()
	if r.child != nil {
		r.child.KeepUnreaped(pid)
	}
	id, err := proc.New().Identity(pid)
	if err != nil {
		r.log.Warn("run: the open deputy's start time could not be read; the recorder names it by its pid alone", "pid", pid, "err", err)
		return
	}
	r.deputyStart = id.StartBootNS
}

// wantsDeputy reports whether this run starts the open deputy: its contract chose gate.completion: held with an fs
// gate rule that can score to allow or above, or the run holds its reads at its tier (fs.reads, ADR 0069;
// RuleTable.NeedsOpenDeputy), and its tier installs a listener filter for the supervisor (no observe run, which
// enforces nothing).
func (r *runner) wantsDeputy() bool {
	if !r.rt.NeedsOpenDeputy() || r.handle == nil || recordsOnly(r.handle) {
		return false
	}
	_, ok := r.handle.SeccompFilter()
	return ok
}

// ErrHeldReadsUnavailable is a run that holds its reads (fs.reads, ADR 0069) whose open deputy did not start: no
// read could be completed on the object it reached, so a deny_read inside a write entry would be readable. The run is
// refused before run_start, exit 125 (fail closed); fs.reads: direct runs it with the target unenforced instead.
var ErrHeldReadsUnavailable = errors.New("runtime: the run holds its reads and the open deputy did not start")

// deputyUnavailable is the launch probe's answer to a deputy that did not start. A run that holds its reads is
// refused (ErrHeldReadsUnavailable): unlike a gate's cells, which ADR 0041 discloses as best effort, held reads are
// what makes a deny_read inside a write entry hold, and a run without them would read the secret. Otherwise it is the
// degrade (ADR 0041, Consequences): a contract that chose held completion whose deputy did not start runs with its
// held-open cells best effort, listed in run_start best_effort, and is told so; nothing is silently continued that
// the contract asked to hold.
func (r *runner) deputyUnavailable(err error) error {
	if r.rt.ReadsHeld() {
		return fmt.Errorf("%w (%v): fs.reads %s at tier %s holds every read open; set fs.reads: direct to run with a deny_read "+
			"inside a write entry readable, or keep secrets outside writable folders", ErrHeldReadsUnavailable, err, r.rt.Reads.Mode, r.rt.Tier)
	}
	r.log.Warn("run: the open deputy did not start; held opens stay best effort", "err", err)
	if r.deps.Warn != nil {
		r.deps.Warn(WarnHeldUnavailable, fmt.Sprintf("gate.completion: held: the open deputy did not start (%v); the gate's fs opens are "+
			"decided on copied syscall facts for this run, best effort, as run_start best_effort records", err))
	}
	return nil
}

// taskLabellingLSMs are the LSMs that label each task, a label an exec can change: an AppArmor profile's attachment, a
// SELinux domain transition, a Smack label.
var taskLabellingLSMs = []string{"apparmor", "selinux", "smack"}

// warnHeldLabel prints heldLabelWarning's text for the active LSM list lsm (or the error reading it), if any, under
// its own code, held-label: it is a disclosure of how held opens are decided on this host, not a flag that turned
// enforcement off, so it no longer shares [unenforced] with --observe.
func (r *runner) warnHeldLabel(lsm []byte, err error) {
	if r.deps.Warn == nil {
		return
	}
	if w := heldLabelWarning(r.heldBy(), lsm, err); w != "" {
		if strings.Contains(","+strings.TrimSpace(string(lsm))+",", ",apparmor,") {
			assume := r.rt != nil && r.rt.Contract != nil && r.rt.Contract.FS != nil && r.rt.Contract.FS.AppArmorAssumeRootNamespace
			if assume {
				w += "; fs.apparmor_assume_root_namespace: true accepts hidden-ancestor risk when namespace depth is unreadable; run_start.best_effort records apparmor/assumed-root-namespace"
			} else if _, e := os.ReadFile("/sys/kernel/security/apparmor/.ns_level"); e != nil {
				w += fmt.Sprintf("; AppArmor namespace depth is unreadable (%v): file completions return EACCES / Permission denied (held-label-unavailable); expose readable securityfs from the root AppArmor policy namespace, or have the container administrator accept hidden-ancestor risk with fs.apparmor_assume_root_namespace: true", e)
			}
		}
		r.deps.Warn(WarnHeldLabel, w)
	}
}

// heldBy names, for the run's warnings, the contract key that makes it hold opens through the open deputy:
// gate.completion: held, fs.reads when the run holds its reads (ADR 0069), or both.
func (r *runner) heldBy() string {
	var by []string
	if r.rt.GateOpensHeld() {
		by = append(by, "gate.completion: held")
	}
	if r.rt.ReadsHeld() {
		by = append(by, "fs.reads: "+string(r.rt.Reads.Mode))
	}
	if len(by) == 0 {
		return "gate.completion: held"
	}
	return strings.Join(by, " and ")
}

// heldLabelWarning explains ADR 0041 D2's fail-closed label comparison in plain
// words. A run holding only reads names a file read; gate completion also covers
// write opens. The full account is in OPERATIONS, held opens.
func heldLabelWarning(by string, lsm []byte, err error) string {
	what := "file open that tego checks and makes"
	if strings.HasPrefix(by, "fs.reads:") && !strings.Contains(by, "gate.completion") {
		what = "file read that tego checks and opens"
	}
	if err != nil {
		return fmt.Sprintf("the host's security modules could not be read (%v); a %s for the agent is refused when its security labels cannot be verified; permit lsm_list_modules in the outer seccomp filter or expose readable /sys/kernel/security/lsm", err, what)
	}
	var names, holds []string
	for _, name := range strings.Split(strings.TrimSpace(string(lsm)), ",") {
		name = strings.TrimSpace(name)
		d, ok := lsmDisplay[name]
		if !ok || !slices.Contains(taskLabellingLSMs, name) || slices.Contains(names, d[0]) {
			continue
		}
		names = append(names, d[0])
		holds = append(holds, d[0]+" "+d[1])
	}
	if len(names) == 0 {
		return ""
	}
	if slices.Contains(names, "Smack") {
		return fmt.Sprintf("on %s a %s for the agent is refused because Smack's process-specific rules cannot be verified across processes", strings.Join(names, "/"), what)
	}
	note := fmt.Sprintf("on %s a %s for the agent requires the same %s as the process opening the file; a different or unreadable label refuses it", strings.Join(names, "/"), what, strings.Join(holds, " or "))
	if slices.Contains(names, "AppArmor") {
		note += "; AppArmor also requires proof that all profile components are visible (readable policy namespace depth zero)"
	}
	if slices.Contains(names, "SELinux") {
		note += "; SELinux file creation contexts must also match before creating a file"
	}
	return note
}

// lsmDisplay is each task-labelling LSM's name as people write it and what it confines a program with.
var lsmDisplay = map[string][2]string{
	"apparmor": {"AppArmor", "profile"},
	"selinux":  {"SELinux", "domain"},
	"smack":    {"Smack", "label"},
}

// closeDeputy ends the run's open deputy: its control socket closed, it exits, and this process, its parent
// (CLONE_PARENT), reaps it, waiting a moment for the exit. Nothing else reaps it (keepDeputy), even once the agent
// ended it early.
func (r *runner) closeDeputy() {
	if r.deputy == nil {
		return
	}
	pid := r.deputy.PID()
	if err := r.deputy.Close(); err != nil {
		r.log.Warn("run: close the open deputy", "err", err)
	}
	r.deputy = nil
	for i := 0; i < 100; i++ {
		var ws syscall.WaitStatus
		got, err := syscall.Wait4(pid, &ws, syscall.WNOHANG, nil)
		if got == pid || err != nil {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	r.log.Warn("run: the open deputy did not exit within 1 s of its control socket closing", "pid", pid)
}

// ErrStagePidsCap is a child stage that died before its handoff while the run cgroup's pids.events max
// rose above createCgroup's baseline. The stage is a Go process cloned into the run cgroup after pids.max
// is written, so its runtime's threads count against limits.pids, and a cap below what it needs to start
// (about 6 tasks) kills it with the Go runtime's "failed to create new OS thread" (runtime-launch.md
// §5 case 3). The run still fails before run_start, as any launch failure does.
var ErrStagePidsCap = errors.New("runtime: limits.pids is below what the launcher's child stage needs to start")

// stagePidsCap names a pids cap that killed the child stage before its handoff: err is ErrChildDied and
// pids.events max is above the baseline createCgroup read. Any other error, or a counter that cannot be
// read or did not rise, is returned as it is.
func (r *runner) stagePidsCap(err error) error {
	if !errors.Is(err, launch.ErrChildDied) || !r.limitBase.ok || r.cg.Path == "" {
		return err
	}
	_, pids, rerr := cgroup.ReadLimitEvents(r.cg)
	if rerr != nil || pids <= r.limitBase.pids {
		return err
	}
	return fmt.Errorf("%w (pids.events max %d, was %d; the stage's Go runtime threads count against the cap): %w",
		ErrStagePidsCap, pids, r.limitBase.pids, err)
}

// arm is ADR 0021 (2)'s one arming point: the tier's kernel decision state that keys on the run (tier 2's
// run-set row and fanotify marks) goes in here, after the child stage's first execve and before the ack. The
// stage writes its control message only once that execve has returned, so WaitNotifyFD's return is the
// signal, and the agent does not exist until the ack. tego's own stage binary is therefore never decided
// or recorded by the run's rules, and the agent's first exec is. From here until Detach removes the marks
// this process starts no process (internal/platform/proc.Start, ADR 0021 (3)): everything the run starts
// (the child stage, any helper) has started already. A failed arm fails the run before run_start: unwind
// kills the stage, which never execs the agent, and Detach removes whatever the arm placed.
func (r *runner) arm() error {
	a, ok := r.handle.(api.Armer)
	if !ok {
		return nil
	}
	if err := a.Arm(); err != nil {
		return fmt.Errorf("runtime: arm %s: %w", r.deps.Enforce.Tier(), err)
	}
	return nil
}

// childSpec builds what the child stage needs. The agent's environment is env.pass/deny/set applied
// to the launcher's own, with the identity set written last and unconditionally (SEMANTICS §9, R3).
// No rlimit is raised: the backend's O_PATH fds live in this process, not in the child's table.
func (r *runner) childSpec() (launch.ChildSpec, error) {
	cwd := r.deps.Cwd
	if cwd == "" {
		wd, err := os.Getwd()
		if err != nil {
			return launch.ChildSpec{}, fmt.Errorf("runtime: cwd: %w", err)
		}
		cwd = wd
	}
	env := r.harnessEnv(r.agentEnv())
	spec := launch.ChildSpec{
		RunID: string(r.id), AgentID: string(r.agentID),
		Command: resolveCommand(r.rt, r.cmd), Env: env, Dir: cwd,
		Stdin: r.deps.Stdio.In, Stdout: r.deps.Stdio.Out, Stderr: r.deps.Stdio.Err,
		Handle: r.handle, LandlockFlags: r.landlockFlags(),
	}
	// Any effective uid 0 drops, in whatever user namespace: this gate asks whether the agent would run as uid 0,
	// not whether this process is root of the host. Under `unshare -r` the drop has no target, since SUDO_UID is
	// read only by root of the initial user namespace (config.InvokingUID, ADR 0042 (5)(d)), and the run is
	// refused as case 36 refuses a root unit, never run as uid 0.
	if os.Geteuid() == 0 {
		tuid, tgid, err := dropTarget()
		if err != nil {
			return launch.ChildSpec{}, err
		}
		spec.Privileged = true
		spec.TargetUID, spec.TargetGID = tuid, tgid
		spec.Setuid = setuidOptOut(r.rt)
		spec.DropNetAdmin = dropsNetAdmin(r.rt)
	}
	return spec, nil
}

// agentEnv is the agent's environment before a harness provision's additions (harnessEnv): env.pass/deny/set applied
// to the launcher's own (agentBaseEnv), the identity set written last and unconditionally (SEMANTICS §9, R3), then the DNS broker's
// and the guarded resolver's variables. provisionHarness tells the provisioner this environment, and childSpec execs
// it. The explicit XDG_RUNTIME_DIR %R request is resolved after provisioning (claudesockets.go).
func (r *runner) agentEnv() []string {
	env := identity.Env{
		RunID: r.id, Agent: r.agentID, ParentRun: identity.RunID(r.deps.ParentRun),
		LedgerDir: r.dir, ReasonFile: r.reasonFile, Tier: string(r.tier()),
		ForwarderVars: r.forwarderVars(),
	}.Apply(buildEnv(r.rt, r.agentBaseEnv()))
	env = r.dnsBrokerEnv(env)
	return guardedResolverEnv(r.rt, r.tier(), env)
}

// dropTarget is the uid and gid a root launch's child drops to (privilegedTarget of the invoking user).
func dropTarget() (int, int, error) {
	uid, viaSudo := config.InvokingUID()
	return privilegedTarget(uid, viaSudo, os.Getenv("SUDO_GID"), passwdGID)
}

// setuidOptOut is whether a root launch leaves no_new_privs unset: a root tier's opt-out (ADR 0033,
// `setuid: true`). Compile refuses it where a pin holds the run at landlock, but an auto contract can still
// land there (a root run with --tier landlock, a machine without tier 2), and tier landlock keeps
// no_new_privs whatever the contract says (ADR 0019).
func setuidOptOut(rt *agent.RuleTable) bool {
	return rt != nil && rt.Contract != nil && rt.Contract.Setuid && rt.Tier != backend.TierLandlock
}

// dropsNetAdmin is whether a root launch takes CAP_NET_ADMIN out of the run's bounding set (ADR 0128): under a net:
// section the run reads the network and does not change it, and setuid: true is the one way a process of a run comes
// to hold a capability (no_new_privs and the empty sets hold every other run to none).
func dropsNetAdmin(rt *agent.RuleTable) bool {
	return setuidOptOut(rt) && rt.NetSocketPolicy().Restricted
}

// privilegedTarget is the uid/gid a root launcher drops the agent to (ARCHITECTURE.md §5 step 2 "drop
// to the invoking uid/gid if the parent was privileged"; R4).
//
// It deliberately does not reuse config.InvokingUID's fallback value. That helper answers a *config
// trust* question (identity-config.md R19/E8) and is documented to return the real uid — 0 — whenever
// SUDO_UID is absent or corrupt. For a credential drop, 0 is the one answer that must never be
// accepted: no_new_privs prevents privilege gains at exec, but does not turn an existing root
// identity into an unprivileged one. It is set by default, and only an explicit setuid opt-out
// on a privileged tier leaves it unset (ADR 0033). Either way the child must drop to a real
// unprivileged uid. viaSudo distinguishes an invoking account from a direct root launch.
//
// The gid comes from SUDO_GID, or failing that from the target uid's own passwd entry — never from
// the uid. uid and primary gid are independent on directory-backed hosts (FreeIPA/AD allocate them
// from separate ranges) and on distributions that give everyone a shared primary group, so aliasing
// them drops the agent into a group the caller may not belong to, whose DAC rights Landlock's
// per-path grants do not mediate.
func privilegedTarget(uid int, viaSudo bool, sudoGID string, primaryGID func(int) (int, error)) (int, int, error) {
	if !viaSudo || uid <= 0 {
		return 0, 0, fmt.Errorf("%w: run it as `sudo tego run`, or as the unprivileged user the "+
			"agent should run as", ErrPrivilegedTarget)
	}
	if gid, ok := parseID(sudoGID); ok {
		return uid, gid, nil
	}
	gid, err := primaryGID(uid)
	if err != nil {
		return 0, 0, fmt.Errorf("%w: SUDO_GID is unset or unusable and uid %d has no passwd entry: %w",
			ErrPrivilegedTarget, uid, err)
	}
	return uid, gid, nil
}

// parseID parses one SUDO_* id the way identity-config.md E8 reads SUDO_UID: an unsigned 32-bit
// value, with the (uid_t)-1 "no owner" sentinel and anything unparsable counted as unset.
func parseID(s string) (int, bool) {
	if s == "" {
		return 0, false
	}
	n, err := strconv.ParseUint(s, 10, 32)
	if err != nil || n == 0xffffffff {
		return 0, false
	}
	return int(n), true
}

// passwdGID is the primary group of uid from the passwd database. CGO_ENABLED=0 (Makefile) makes this
// a pure-Go /etc/passwd read, so a directory-backed uid with no local entry fails here rather than
// answering with a guess (config.LookupPasswd: not even os/user's guess from the process's own gid).
func passwdGID(uid int) (int, error) {
	u, err := config.LookupPasswd(uid)
	if err != nil {
		return 0, err
	}
	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		return 0, fmt.Errorf("passwd gid %q for uid %d: %w", u.Gid, uid, err)
	}
	return gid, nil
}
