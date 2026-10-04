// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import "github.com/attention-span-ai/tego/internal/platform/proc"

func (l *Loop) ContinuedListen(tid, pid int, startBootNS, eventMonoNS uint64) (ListenNaming, bool) {
	return l.listenHanded.find(tid, pid, startBootNS, eventMonoNS)
}

func (l *Loop) saveListenNaming(n *notif, d dest, rule string, supervisorOwned bool) {
	if n.listenAttemptNS == 0 {
		n.listenAttemptNS = l.mono()
	}
	pid := l.tgidOf(n.pid)
	_, ticks, err := l.k.ProcStat(pid)
	name := d.unixPath
	if len(d.abstract) > 0 {
		name = string(d.abstract)
	}
	l.listenHanded.put(continuedBind{tid: n.pid, pid: pid, startNS: ticks * proc.NanosPerTick,
		named: err == nil && (supervisorOwned || d.ok),
		naming: ListenNaming{Path: name, Abstract: len(d.abstract) > 0, Rule: rule,
			AttemptMonoNS: n.listenAttemptNS, SupervisorOwned: supervisorOwned}})
}

func (l *Loop) beginListenHandover(n *notif) {
	n.listenAttemptNS = l.mono()
	l.listenHanded.put(continuedBind{tid: n.pid, naming: ListenNaming{AttemptMonoNS: n.listenAttemptNS}})
}

func (l *Loop) listenHandoffReady() bool {
	return l.kernelListenHandoff != nil && l.kernelListenHandoff()
}
