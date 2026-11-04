// SPDX-License-Identifier: Apache-2.0

package observe

import (
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/internal/policy/decide"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// inheritedTTYIdentity is attribution metadata, never an enforcement decision.
// The run's Landlock domain holds the actual terminal node. Match the recorded
// file identity rather than treating every numeric terminal as foreign.
func inheritedTTYIdentity() [2]uint64 {
	rdev, err := sys.ControllingTTYDevice()
	if err != nil || rdev == 0 {
		return [2]uint64{}
	}
	for _, dir := range []string{"/dev/pts", "/dev"} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			p := filepath.Join(dir, e.Name())
			if !agent.OtherTTY(p) {
				continue
			}
			var st unix.Stat_t
			if unix.Stat(p, &st) == nil && st.Rdev == rdev {
				return [2]uint64{st.Dev, st.Ino}
			}
		}
	}
	return [2]uint64{}
}

// builtinTTYRefusal attributes only an actual kernel refusal of a foreign
// terminal. It never infers that an allowed open was refused. Full recording's
// notified refusal has already been answered by the supervisor instead.
func (r *Recorder) builtinTTYRefusal(rec *Record, path string) bool {
	if r.rules.rt == nil || r.rules.rt.Builtins == nil || !agent.OtherTTY(path) || rec.FS.PathTruncated {
		return false
	}
	if r.ownTTY != [2]uint64{} && r.ownTTY == [2]uint64{rec.FS.Dev, rec.FS.Ino} {
		return false
	}
	return rec.Verdict == KernelRefused || rec.FS.RetOK && (rec.FS.Ret == -int32(unix.EACCES) || rec.FS.Ret == -int32(unix.EPERM))
}

// The peer hook emits a named plane sample because sockaddr producers cannot
// name the inode selected after an admitted datagram's arguments are reread.
func (r *Recorder) handleBuiltinPeer(rec *Record) {
	if rec.Reason != uint8(bpf.ReasonNetNotAllowed) || rec.Verdict != KernelRefused {
		r.gap(GapMalformedRecord, 1)
		return
	}
	path, _, resolved := r.resolveFSOpPath(rec.FS.Dev, rec.FS.Ino, rec.FS.Path, rec.FS.PathTruncated, true, "", bpf.DirNone)
	r.dirUnresolvedGap(resolved, rec.FS.PathTruncated)
	rule := agent.BuiltinHostIPC
	if rec.Plane.RuleIdx == bpf.PlaneRuleBuiltinSurface {
		rule = agent.BuiltinTegoSurface
	}
	if rows := r.planeRows(); rows != nil && rec.Plane.RuleIdx != bpf.PlaneRuleBuiltinHost && rec.Plane.RuleIdx != bpf.PlaneRuleBuiltinSurface {
		candidate := rows.RowName(r.rules.rt, int(rec.Plane.RuleIdx), decide.PlaneModify, 1)
		if candidate == agent.BuiltinHostIPC || candidate == agent.BuiltinTegoSurface {
			rule = candidate
		}
	}
	ev := r.event(rec, record.KindNet, rule, record.VerdictRefused, record.ReasonNetNotAllowed)
	r.setPayload(ev, record.NetPayload{Op: "sendmsg", Proto: "unix", Dst: "unix:" + path, Mechanism: record.MechanismPlane, DecisionPlane: r.opts.DecisionPlane})
	r.emit(ev)
}
