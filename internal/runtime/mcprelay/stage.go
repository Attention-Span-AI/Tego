// SPDX-License-Identifier: Apache-2.0

package mcprelay

import (
	"os"
	"slices"
	"strconv"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/sys"
)

// prepareStage records a socket created after shim admission, before its child exists. A sibling forked before
// the shim's exec cannot inherit it. The trusted shim keeps this end open until proc.Start returns, so its inode
// cannot be reused while the supervisor verifies the child's held exec (ADR 0126, SEC06 compatibility amendment).
func (s *Service) prepareStage(shim admission, stage StageRequest) bool {
	if stage.Socket == 0 || len(stage.Argv) < 4 || stage.Argv[1] != ServerCommand || stage.Argv[2] == "" ||
		!s.opts.stillShim(shim) || !holdsSocket(shim.pid, stage.Socket) {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.pending[shim.pid]
	if !ok || p.shim != shim || p.stage != nil || p.child != nil || s.stopped ||
		!slices.Equal(stage.Argv[3:], s.servers[p.server].Command) {
		return false
	}
	stage.Argv = slices.Clone(stage.Argv)
	p.stage = &stage
	s.pending[shim.pid] = p
	return true
}

// StageRule names the runtime's conditional child-stage grant; it grants no other exec of this binary.
func (s *Service) StageRule() string {
	for _, server := range s.servers {
		if len(server.Command) > 0 {
			return "exec.mcp-stage[" + s.opts.Exe + "]"
		}
	}
	return ""
}

// Stage vouches for one internal exec while the supervisor holds it. The resolved image must be this launcher's,
// the whole vector must be the prepared one, and fd 3 must be the fresh socket the admitted shim still holds.
// Pinning that live child here binds the grant to its pidfd, not merely to the shim's parent PID. A subsequent
// Child frame must confirm this same identity before it may consume the server start. C50 attach authority is
// unchanged: an attacker allowed to copy these descriptors or alter the shim can still bypass the relay.
func (s *Service) Stage(pid int, dev, ino uint64, argv []string) string {
	var own unix.Stat_t
	if unix.Stat("/proc/self/exe", &own) != nil || dev != own.Dev || ino != own.Ino {
		return ""
	}
	parent := ppidOf(pid)
	s.mu.Lock()
	p, ok := s.pending[parent]
	s.mu.Unlock()
	if !ok || p.stage == nil || p.child != nil || !slices.Equal(argv, p.stage.Argv) || !s.stageChild(p, pid) {
		return ""
	}
	child, err := sys.PidfdOpenProcessFD(pid)
	if err != nil {
		return ""
	}
	keep := false
	defer func() {
		if !keep {
			_ = child.Close()
		}
	}()
	if !s.stageChild(p, pid) {
		return ""
	}
	if exited, err := sys.PollPidfdFD(child, 0); err != nil || exited {
		return ""
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now, ok := s.pending[parent]
	if !ok || now.shim != p.shim || now.stage != p.stage || now.child != nil || s.stopped {
		return ""
	}
	now.pid, now.child = pid, child
	s.pending[parent] = now
	keep = true
	return s.StageRule()
}

func (s *Service) stageChild(p pendingStart, pid int) bool {
	if ppidOf(pid) != p.shim.pid || !s.opts.stillShim(p.shim) || !holdsSocket(p.shim.pid, p.stage.Socket) {
		return false
	}
	fd, err := os.Readlink("/proc/" + strconv.Itoa(pid) + "/fd/3")
	return err == nil && fd == "socket:["+strconv.FormatUint(p.stage.Socket, 10)+"]"
}
