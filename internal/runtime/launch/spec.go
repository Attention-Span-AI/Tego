// SPDX-License-Identifier: Apache-2.0

package launch

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"golang.org/x/net/bpf"

	"github.com/attention-span-ai/tego/internal/runtime/enforce/api"
)

// ChildCommand is the argv[1] the launcher passes to /proc/self/exe to enter the child stage.
const ChildCommand = "__child"

// Child-side descriptor numbers: the launcher places its pipe ends and the ruleset fd there with ExtraFiles.
const (
	childControlFD = 3 // parent→child: length-prefixed ChildSpec JSON, then the one-byte ack (pipe B, R6)
	childReportFD  = 4 // child→parent: one int32 control message (pipe A, R6)
	childRulesetFD = 5 // the Landlock ruleset, present only when the handle has one
	// The open deputy's control socket follows the inherited descriptors above, when the spec has one: fd 6 after a
	// ruleset, fd 5 without (wireSpec.DeputyFD names it).
)

// maxSpecBytes bounds the serialized ChildSpec the child stage accepts: env and argv together are bounded by
// ARG_MAX (case 18, 27), so anything past a few MiB is a corrupt or hostile stream, not a run.
const maxSpecBytes = 8 << 20

// ChildSpec describes one agent process to start (docs/p0/runtime-launch.md §2).
type ChildSpec struct {
	RunID   string
	AgentID string
	// Command is the argv; Command[0] is the executable path, pre-resolved against PATH before Start
	// (agent.Compile). execve does no PATH search.
	Command []string
	// Env is the final environment; identity variables already applied last (SEMANTICS §9).
	Env []string
	// Dir is the working directory; it must exist (agent.Compile checked).
	Dir string
	// Stdin, Stdout, Stderr are the agent's standard streams; nil means /dev/null.
	Stdin, Stdout, Stderr *os.File
	// Handle is the prepared enforcement state: its Landlock ruleset fd and seccomp program are applied in the
	// child. Required.
	Handle api.Handle
	// Privileged selects the R4 ordering swap: Landlock and seccomp before the uid/capability drop, and
	// no_new_privs only after the drop (ADR 0033). Only a root launcher sets it.
	Privileged bool
	// Setuid is a root-tier contract's opt-out of no_new_privs (ADR 0033, `setuid: true`): an exec inside the
	// run may then gain the ids and capabilities of a setuid binary. Without it no process of a run becomes
	// root through an exec, at any tier.
	Setuid bool
	// DropNetAdmin takes CAP_NET_ADMIN out of the bounding set before anything else in the privileged order, so no
	// process of a `setuid: true` run under a net: section ever holds it (ADR 0128). The kernel's own capability
	// checks then refuse every change to the network, on the paths the filter does not see (write(2), an unaddressed
	// send(2), an ioctl) as on those it does. Without Setuid no_new_privs gives the same and this is not set.
	DropNetAdmin bool
	// TargetUID and TargetGID are the credentials the child drops to; used only when Privileged.
	TargetUID, TargetGID int
	// LandlockFlags are the LANDLOCK_RESTRICT_SELF_* bits passed to landlock_restrict_self (LandlockLog*,
	// ABI 7+; LandlockNoNewPrivs, ABI 11). The child stage drops the ones its kernel's ABI does not know
	// (LandlockFlags says which, for the launcher to record) and never drops one the kernel knows.
	// internal/runtime sets LandlockLogNewExecOn here when the machine config's landlock.audit is new-exec,
	// and records a drop as gap why=landlock-audit-unavailable.
	LandlockFlags uint32
	// Deputy, when set, is the stage's end of the open deputy's control socketpair (deputy.Socketpair): the stage
	// starts `tego __open-deputy` after landlock_restrict_self and before the listener filter and passes it this
	// end (ADR 0041 D2). The caller keeps the launcher's end, reads the hello from it once the stage has reported
	// (deputy.Hello), and closes this one after Start. Nil starts no deputy.
	Deputy *os.File
}

// ErrSpec is wrapped by Start when a ChildSpec is unusable before any process is created.
var ErrSpec = errors.New("launch: invalid child spec")

// Validate re-checks the fields agent.Compile already gated (defensively, §2 Validation).
func (s ChildSpec) Validate() error {
	switch {
	case len(s.Command) == 0 || s.Command[0] == "":
		return fmt.Errorf("%w: empty command", ErrSpec)
	case s.Handle == nil:
		return fmt.Errorf("%w: nil api.Handle", ErrSpec)
	case s.Privileged && (s.TargetUID < 0 || s.TargetGID < 0):
		return fmt.Errorf("%w: privileged run without target uid/gid", ErrSpec)
	case s.Dir == "":
		return fmt.Errorf("%w: empty working directory", ErrSpec)
	}
	for _, e := range s.Env {
		for i := 0; i < len(e); i++ {
			if e[i] == 0 {
				return fmt.Errorf("%w: env entry contains NUL", ErrSpec)
			}
		}
	}
	return nil
}

// wireSpec is what crosses the control pipe: ChildSpec minus the parent-only members (files, Handle), plus
// the child-side fd numbers and the parent pid the child verifies after arming PDEATHSIG.
type wireSpec struct {
	BuiltinRefusals bool                 `json:"builtin_refusals,omitempty"`
	RunID           string               `json:"run_id"`
	AgentID         string               `json:"agent_id"`
	Command         []string             `json:"command"`
	Env             []string             `json:"env"`
	Dir             string               `json:"dir"`
	UID             int                  `json:"uid"` // -1: keep the current uid
	GID             int                  `json:"gid"` // -1: keep the current gid
	Privileged      bool                 `json:"privileged"`
	Setuid          bool                 `json:"setuid,omitempty"`
	DropNetAdmin    bool                 `json:"drop_net_admin,omitempty"`
	ParentPID       int                  `json:"parent_pid"`
	RulesetFD       int                  `json:"ruleset_fd"` // -1: no Landlock domain
	LandlockFlags   uint32               `json:"landlock_flags"`
	Seccomp         []bpf.RawInstruction `json:"seccomp"` // empty: no filter, no listener
	// ResetSignals are the signals the stage sets to SIG_DFL before it execs the agent: the job-control
	// stops a tier-2 launcher ignores for itself (HoldJobControl), whose ignored disposition would otherwise
	// reach the agent across execve.
	ResetSignals []int `json:"reset_signals,omitempty"`
	// DeputyFD is the open deputy's control socket in the stage; 0, its absence, or anything below 3 is no deputy.
	DeputyFD int `json:"deputy_fd,omitempty"`
}

// wireJSON is wireSpec as it crosses the pipe. Command, Env and Dir are byte strings the stage hands to execve
// and chdir as given, and a JSON string is UTF-8: encoding/json replaces each invalid byte with U+FFFD, so an
// argv or env byte that is not UTF-8 would reach execve changed (runtime-launch.md E17). As []byte they travel
// base64-encoded, every byte kept. RunID and AgentID are validated ASCII identifiers and stay strings.
type wireJSON struct {
	wireAlias
	Command [][]byte `json:"command"`
	Env     [][]byte `json:"env"`
	Dir     []byte   `json:"dir"`
}

// wireAlias drops wireSpec's JSON methods so the embedded struct marshals field by field; wireJSON's byte
// fields shadow its string ones of the same key.
type wireAlias wireSpec

func byteStrings(ss []string) [][]byte {
	if ss == nil {
		return nil
	}
	out := make([][]byte, len(ss))
	for i, s := range ss {
		out[i] = []byte(s)
	}
	return out
}

func stringsOf(bs [][]byte) []string {
	if bs == nil {
		return nil
	}
	out := make([]string, len(bs))
	for i, b := range bs {
		out[i] = string(b)
	}
	return out
}

// MarshalJSON carries Command, Env and Dir losslessly (wireJSON).
func (w wireSpec) MarshalJSON() ([]byte, error) {
	return json.Marshal(wireJSON{
		wireAlias: wireAlias(w), Command: byteStrings(w.Command), Env: byteStrings(w.Env), Dir: []byte(w.Dir),
	})
}

// UnmarshalJSON is MarshalJSON's inverse.
func (w *wireSpec) UnmarshalJSON(b []byte) error {
	var j wireJSON
	if err := json.Unmarshal(b, &j); err != nil {
		return err
	}
	*w = wireSpec(j.wireAlias)
	w.Command, w.Env, w.Dir = stringsOf(j.Command), stringsOf(j.Env), string(j.Dir)
	return nil
}

// toWire projects the spec for the child, resolving the Handle's ruleset and filter now so the child never
// touches enforce.
func (s ChildSpec) toWire(parentPID int, hasRuleset, hasDeputy bool) wireSpec {
	w := wireSpec{
		RunID: s.RunID, AgentID: s.AgentID, Command: s.Command, Env: s.Env, Dir: s.Dir,
		UID: -1, GID: -1, Privileged: s.Privileged, Setuid: s.Setuid, DropNetAdmin: s.DropNetAdmin, ParentPID: parentPID, RulesetFD: -1,
		LandlockFlags: s.LandlockFlags,
	}
	if s.Privileged {
		w.UID, w.GID = s.TargetUID, s.TargetGID
	}
	if h, ok := s.Handle.(interface{ BuiltinRefusals() bool }); ok {
		w.BuiltinRefusals = h.BuiltinRefusals()
	}
	if hasRuleset {
		w.RulesetFD = childRulesetFD
	}
	if hasDeputy {
		w.DeputyFD = childRulesetFD
		if hasRuleset {
			w.DeputyFD = childRulesetFD + 1
		}
	}
	if prog, ok := s.Handle.SeccompFilter(); ok {
		w.Seccomp = prog
	}
	return w
}

// writeSpec sends w as a 4-byte little-endian length followed by JSON: one framed message the child reads
// exactly, so the ack byte that follows on the same pipe is never swallowed.
func writeSpec(wr io.Writer, w wireSpec) error {
	body, err := json.Marshal(w)
	if err != nil {
		return fmt.Errorf("encode child spec: %w", err)
	}
	if len(body) > maxSpecBytes {
		return fmt.Errorf("%w: serialized spec is %d bytes, above %d", ErrSpec, len(body), maxSpecBytes)
	}
	buf := make([]byte, 4+len(body))
	binary.LittleEndian.PutUint32(buf, uint32(len(body)))
	copy(buf[4:], body)
	if _, err := wr.Write(buf); err != nil {
		return fmt.Errorf("write child spec: %w", err)
	}
	return nil
}

// readSpec reads one framed wireSpec. A short read is io.ErrUnexpectedEOF; an oversized frame is refused
// before any allocation.
func readSpec(rd io.Reader) (wireSpec, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(rd, hdr[:]); err != nil {
		return wireSpec{}, fmt.Errorf("read child spec length: %w", err)
	}
	n := binary.LittleEndian.Uint32(hdr[:])
	if n == 0 || n > maxSpecBytes {
		return wireSpec{}, fmt.Errorf("%w: spec frame of %d bytes", ErrSpec, n)
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(rd, body); err != nil {
		return wireSpec{}, fmt.Errorf("read child spec body: %w", err)
	}
	var w wireSpec
	if err := json.Unmarshal(body, &w); err != nil {
		return wireSpec{}, fmt.Errorf("%w: decode: %w", ErrSpec, err)
	}
	if len(w.Command) == 0 || w.Command[0] == "" {
		return wireSpec{}, fmt.Errorf("%w: empty command on the wire", ErrSpec)
	}
	return w, nil
}
