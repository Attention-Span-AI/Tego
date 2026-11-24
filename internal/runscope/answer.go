// SPDX-License-Identifier: Apache-2.0

package runscope

import (
	"strconv"
	"time"
)

// Verdict is one of the three answers to "is this process outside every tego run made inside its cgroup
// namespace?". Inside is the zero value on purpose: an answer nobody filled in, a struct decoded from nothing and a
// forgotten return all read as inside, which refuses.
type Verdict uint8

const (
	// Inside: the process's own cgroup path shows a run, or cannot be read as a path that shows none.
	Inside Verdict = iota
	// Unknown: the path shows no run, and what would prove the process outside every run could not be shown. It
	// always carries a Cause. Every caller treats it as Inside.
	Unknown
	// Outside: this process is in no run's cgroup made inside its own cgroup namespace. It is the only answer that
	// permits a governance change, an approval or the entry into a user scope.
	Outside
)

// String names a verdict for a diagnostic.
func (v Verdict) String() string {
	switch v {
	case Outside:
		return "outside"
	case Unknown:
		return "unknown"
	}
	return "inside"
}

// Cause is why an answer is not Outside: one typed word per state of the rule (Decide, Prove). "" only on Outside.
type Cause string

// The causes, in the order the rule can reach them.
const (
	// Step 1 and its repeat through the anchored /proc: the process's own cgroup path. These answer Inside.
	CausePathUnreadable Cause = "path-unreadable"
	CausePathMalformed  Cause = "path-malformed"
	CausePathAboveRoot  Cause = "path-above-root"
	CauseGoverned       Cause = "governed"
	// Step 2: the process's own cgroup namespace file.
	CauseNSUnreadable Cause = "ns-unreadable"
	// Step 4: the caller itself. Its seccomp mode is read and recorded on the answer, never judged (Describe).
	CauseMixedIDs     Cause = "mixed-ids"
	CauseRootCaller   Cause = "root-caller"
	CauseCapabilities Cause = "capabilities"
	// Step 5: /proc.
	CauseProcUnanchored Cause = "proc-unanchored"
	// Step 8 (a): who owns the cgroup namespace.
	CauseUserNamespace Cause = "user-namespace"
	// Step 8 (b): pid 1.
	CauseInitUnreadable Cause = "init-unreadable"
	CauseInitNotAtRoot  Cause = "init-not-at-root"
	// Step 8 (c'): the user's service manager.
	CauseNoUserManager       Cause = "no-user-manager"
	CauseManagerNotListening Cause = "manager-not-listening"
	CauseManagerBusy         Cause = "manager-busy"
	CauseSocketRefused       Cause = "socket-refused"
	CauseProbeError          Cause = "probe-error"
	CausePeerUID             Cause = "peer-uid"
	CausePeerUnidentified    Cause = "peer-unidentified"
	CauseNoPeerPidfd         Cause = "no-peer-pidfd"
	CausePeerElsewhere       Cause = "peer-elsewhere"
	CauseProbeTimeout        Cause = "probe-timeout"
	// The gate (Facts.Withheld): every fact held, and the answer is withheld where the rule is not proven yet. On WSL,
	// in every branch:
	CauseWSLLauncherUnproven Cause = "wsl-launcher-unproven"
	// Outside WSL, in a cgroup namespace that is not the kernel's first one:
	CauseSystemUnproven Cause = "system-unproven"
)

// Answer is the rule's answer: a verdict, the cause when it is not Outside, the read that failed when one did, the
// seccomp mode the rule recorded and how long its probe took (Describe). Its zero value is Inside. Its fields are this package's alone, so no other package can make an Outside answer,
// read a field as "permit", or decode one (encoding/json and its kin see no field to fill): Decide and Prove are the
// only producers of Outside, and Unproven, the one constructor other packages have, never makes it. It has one
// method, and nothing encodes it: an answer is computed in the process it describes and never stored, sent or
// handed to another.
type Answer struct {
	verdict Verdict
	cause   Cause
	err     error
	seccomp seccompNote
	probe   time.Duration // how long the probe of step 8 took, when one ran for this answer; 0 when none did
}

// seccompNote is the caller's seccomp mode as the rule read it outside the kernel's first cgroup namespace: recorded
// for whoever reads Describe, never a condition of the answer. The signed rule's fact 4c (no filter) was removed
// on 2026-11-19 (ADR 0100): with WSL's mirrored networking every ordinary shell carries a filter.
type seccompNote struct {
	read bool
	mode int
	err  error
}

// Outside reports whether the answer permits what only a process outside every run may do. It is the one way a
// caller reads an answer: Inside and Unknown are both false.
func (a Answer) Outside() bool { return a.verdict == Outside }

func inside(c Cause, err error) Answer  { return Answer{verdict: Inside, cause: c, err: err} }
func unknown(c Cause, err error) Answer { return Answer{verdict: Unknown, cause: c, err: err} }

// Unproven is the unknown answer for cause c, with the read that failed when there is one: what a caller that runs
// part of the rule itself (internal/platform/peer's proof cache and its time limit) returns when it could not show
// the process outside every run. It never makes Outside, and an empty cause is CauseProbeError, so an unknown
// always carries a cause.
func Unproven(c Cause, err error) Answer {
	if c == "" {
		c = CauseProbeError
	}
	return unknown(c, err)
}

// WithProbeTime is a with the time its probe took (step 8, runscope.Prove), as the code that ran the probe measured
// it: a fact for a diagnostic line, never a condition. It changes nothing else of a, so it cannot make an Outside.
func WithProbeTime(a Answer, d time.Duration) Answer {
	a.probe = d
	return a
}

// Description is an answer laid out for a diagnostic line and for tests: its verdict, its cause ("" on Outside and
// on an answer nobody filled in), the failed read, the seccomp mode the rule recorded and the probe's time. It permits nothing and cannot be turned back into an Answer: a
// caller decides with Answer.Outside alone, and outside this package, the kernel's reads beside it and the test
// table, only a diagnostic file and tests may call Describe (TestCallersReadTheAnswerThroughOutside).
type Description struct {
	Verdict Verdict
	Cause   Cause
	Err     error
	// Seccomp is the seccomp mode the rule read outside the kernel's first cgroup namespace ("0", "2"), or why it
	// could not be read; "" where the rule did not read it (the first namespace, or an answer settled before it).
	Seccomp string
	// Probe is how long the probe of the user's service manager took when one ran for this answer (a proof held
	// from an earlier call keeps the time of the probe that made it); 0 when none ran.
	Probe time.Duration
}

// Describe lays a out for a diagnostic line or a test.
func Describe(a Answer) Description {
	d := Description{Verdict: a.verdict, Cause: a.cause, Err: a.err, Probe: a.probe}
	switch {
	case !a.seccomp.read:
	case a.seccomp.err != nil:
		d.Seccomp = "unreadable (" + a.seccomp.err.Error() + ")"
	default:
		d.Seccomp = strconv.Itoa(a.seccomp.mode)
	}
	return d
}

// String is the description as one line: "unknown, wsl-launcher-unproven; seccomp mode 2 (recorded, not judged);
// probe took 377.7 ms".
func (d Description) String() string {
	s := d.Verdict.String()
	if d.Cause != "" {
		s += ", " + string(d.Cause)
	}
	if d.Err != nil {
		s += " (" + d.Err.Error() + ")"
	}
	if d.Seccomp != "" {
		s += "; seccomp mode " + d.Seccomp + " (recorded, not judged)"
	}
	if d.Probe > 0 {
		s += "; probe took " + strconv.FormatFloat(float64(d.Probe)/float64(time.Millisecond), 'f', 1, 64) + " ms"
	}
	return s
}

// SaysGoverned reports whether a refusal for a may say "a governed agent": only when the process's own cgroup path
// shows a run. Every other refusal says that the process cannot be shown to be outside every run, and why (Why).
func SaysGoverned(a Answer) bool { return a.verdict == Inside && a.cause == CauseGoverned }

// CouldNotTell reports whether a is the rule's unknown: the process's own path shows no run, and it still could not
// be shown to be outside every run. A caller that words or routes a refusal asks this; none permits anything on it.
func CouldNotTell(a Answer) bool { return a.verdict == Unknown }

// PlainFirst reports whether a's cause has a line the person can act on that comes before any wording about runs:
// no systemd at the top of the tree, a user session that is not up, and root.
func PlainFirst(a Answer) bool {
	return a.verdict == Unknown && plainFirst[a.cause]
}

// plainFirst are the causes whose words stand alone as a line the person can act on.
var plainFirst = map[Cause]bool{CauseInitNotAtRoot: true, CauseNoUserManager: true, CauseManagerNotListening: true,
	CauseRootCaller: true}

// Why is the sentence part that says why a is not Outside, with the failed read when there is one. "" for Outside.
func Why(a Answer) string {
	if a.Outside() {
		return ""
	}
	w := causeWords[a.cause]
	if w == "" {
		w = "the check gave no reason (" + a.verdict.String() + ")"
	}
	if a.err != nil {
		w += " (" + a.err.Error() + ")"
	}
	return w
}

// Advice is what a refusal for a adds after its reason: where to run the command instead. "" when the reason itself
// says what to do (PlainFirst), when there is nothing the person can do (the gate on WSL), and for Outside.
func Advice(a Answer) string {
	switch {
	case a.Outside(), PlainFirst(a), a.cause == CauseWSLLauncherUnproven:
		return ""
	case a.verdict == Inside:
		return "run it from a terminal outside any tego run"
	}
	return "run it from a terminal of the machine's own, outside any tego run and any container"
}

// causeWords is each cause in words. The sentences for a private cgroup namespace say what the person can do where
// there is something to do.
var causeWords = map[Cause]string{
	CausePathUnreadable: "its cgroup file, /proc/self/cgroup, could not be read",
	CausePathMalformed:  "its cgroup file, /proc/self/cgroup, names no single cgroup v2 path",
	CausePathAboveRoot:  "its cgroup lies above the root of its cgroup namespace",
	CauseGoverned:       "this process is inside a tego run's cgroup",
	CauseNSUnreadable:   "its cgroup namespace file, /proc/self/ns/cgroup, could not be read as a kernel namespace file",
	CauseMixedIDs:       "its real, effective and saved user ids differ",
	CauseRootCaller: "this is root in a cgroup namespace that is not the machine's first one (a WSL distribution " +
		"or a container), where tego does not judge root; run tego as your own user, without sudo",
	CauseCapabilities: "it holds a capability in a cgroup namespace that is not the machine's first one, and a " +
		"capability holder could have made that namespace itself",
	CauseProcUnanchored: "/proc could not be shown to be the kernel's own process filesystem",
	CauseUserNamespace: "its cgroup namespace is not owned by the machine's first user namespace (it runs in a " +
		"user namespace of its own, or in a container made in one)",
	CauseInitUnreadable: "the cgroup of process 1 could not be read",
	CauseInitNotAtRoot: "the service manager (systemd) is not at the top of this cgroup tree: process 1 is not in " +
		"/init.scope; on WSL, turn systemd on ([boot] systemd=true in /etc/wsl.conf), update WSL (wsl --update) " +
		"and start the distribution again",
	CauseNoUserManager: "your user session is not up: your user's service manager has no socket under " +
		"/run/user yet; wait a few seconds after the machine starts, or log in again",
	CauseManagerNotListening: "your user session is not up: your user's service manager is not listening on its " +
		"socket (it may be starting or restarting); try again in a moment",
	CauseManagerBusy:      "your user's service manager did not take a connection within half a second",
	CauseSocketRefused:    "the connection to your user's service manager was refused",
	CauseProbeError:       "the connection to your user's service manager failed",
	CausePeerUID:          "the listener on your user's service-manager socket runs as another user",
	CausePeerUnidentified: "the listener on your user's service-manager socket could not be identified",
	CauseNoPeerPidfd: "this kernel cannot name the process that listens on a socket (SO_PEERPIDFD needs Linux " +
		"6.5), so your user's service manager cannot be identified",
	CausePeerElsewhere: "the listener on your user's service-manager socket is not in the service manager's " +
		"own cgroup",
	CauseProbeTimeout: "the check of your user's service manager did not finish within half a second",
	CauseWSLLauncherUnproven: "on WSL this build treats no process as outside every tego run yet: it is not " +
		"proven yet that a tego run refuses WSL's own program launcher (wsl.exe and the sockets under /run/WSL), " +
		"through which a process inside a run could start one outside it",
	CauseSystemUnproven: "this kind of system has not been proven: outside WSL, tego has not yet been measured where " +
		"the cgroup namespace is not the machine's first one (a container, or a system nested in another), so this " +
		"build treats no process here as outside every tego run",
}
