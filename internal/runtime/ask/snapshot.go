// SPDX-License-Identifier: Apache-2.0

package ask

import (
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/proc"
	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/internal/runscope"
)

// senderHandle keeps the packet's process alive as an identity, not as a task.
// procDir is opened once while pidfd is live. Relative reads cannot switch to a
// replacement process if the numerical PID is reused during admission.
// Its socket handler owns both descriptors until the answer reply is sent.
type senderHandle struct {
	mu      sync.Mutex
	closed  bool
	pidfd   *sys.FD
	procDir *sys.FD
	// afterRead is nil in production; tests stop inside the real snapshot reads.
	afterRead func(string)
}

func openSender(p Peer, packetFD *sys.FD) (*senderHandle, error) {
	fd := packetFD
	if fd == nil {
		var err error
		fd, err = sys.PidfdOpenProcessFD(p.PID)
		if err != nil {
			return nil, err
		}
	}
	h := &senderHandle{pidfd: fd}
	// Also prove the proc mount's PID namespace agrees with the packet's PID.
	if err := h.validate(p); err != nil {
		h.close()
		return nil, err
	}
	dir, err := sys.Own(unix.Open(fmt.Sprintf("/proc/%d", p.PID), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0))
	if err != nil {
		h.close()
		return nil, err
	}
	h.procDir = dir
	if err := h.validate(p); err != nil {
		h.close()
		return nil, err
	}
	return h, nil
}

func (h *senderHandle) close() {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return
	}
	h.closed = true
	if h.procDir != nil {
		_ = h.procDir.Close()
	}
	_ = h.pidfd.Close()
}

func (h *senderHandle) read(name string) ([]byte, error) {
	owned, err := h.procDir.Openat(name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	f, err := owned.Release(name)
	if err != nil {
		_ = owned.Close()
		return nil, err
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, (64<<10)+1))
	if err == nil && len(b) > 64<<10 {
		err = ErrUnauthorized
	}
	h.barrier(name)
	return b, err
}

func (h *senderHandle) barrier(name string) {
	if h.afterRead != nil {
		h.afterRead(name)
	}
}

func (h *senderHandle) namespace(name string) (uint64, error) {
	var st unix.Stat_t
	err := h.procDir.Fstatat("ns/"+name, &st, 0)
	h.barrier("ns/" + name)
	return st.Ino, err
}

func (h *senderHandle) facts(p Peer) (Peer, error) {
	b, err := h.read("status")
	if err != nil {
		return Peer{}, err
	}
	p.realUID, err = senderRealUID(b)
	if err != nil {
		return Peer{}, err
	}
	if p.UserNamespace, err = h.namespace("user"); err != nil {
		return Peer{}, err
	}
	if p.CgroupNS, err = h.namespace("cgroup"); err != nil {
		return Peer{}, err
	}
	b, err = h.read("cgroup")
	if err != nil {
		return Peer{}, err
	}
	p.Cgroup, err = runscope.Unified(b)
	return p, err
}

// senderRealUID reads the real UID as rendered in the broker's user namespace.
// Packet credentials still identify the sender; this is a decision-time fact.
func senderRealUID(status []byte) (uint32, error) {
	found := false
	var real uint32
	for line := range strings.SplitSeq(string(status), "\n") {
		values, ok := strings.CutPrefix(line, "Uid:")
		if !ok {
			continue
		}
		fields := strings.Fields(values)
		if found || len(fields) != 4 {
			return 0, ErrUnauthorized
		}
		found = true
		for i, field := range fields {
			uid, err := strconv.ParseUint(field, 10, 32)
			if err != nil {
				return 0, ErrUnauthorized
			}
			if i == 0 {
				real = uint32(uid)
			}
		}
	}
	if !found {
		return 0, ErrUnauthorized
	}
	return real, nil
}

func (h *senderHandle) validate(p Peer) error {
	if h == nil || h.closed || p.PID <= 0 || p.StartBootNS == 0 {
		return ErrUnauthorized
	}
	b, err := h.pidfd.ProcInfo()
	if err != nil {
		return err
	}
	h.barrier("pidfd")
	matched := false
	for line := range strings.SplitSeq(string(b), "\n") {
		if v, ok := strings.CutPrefix(line, "Pid:"); ok {
			matched = strings.TrimSpace(v) == strconv.Itoa(p.PID)
		}
	}
	if !matched {
		return ErrUnauthorized
	}
	if h.procDir != nil {
		b, err := h.read("stat")
		if err != nil {
			return err
		}
		st, err := proc.ParseStat(b)
		if err != nil || st.PID != p.PID || st.Gone() || st.Exiting() || st.StartBootNS() != p.StartBootNS {
			return ErrUnauthorized
		}
	}
	// Last, after every read and every governed-scope diagnostic. Exit makes
	// pidfd readable even when a replacement now owns the packet's PID.
	return h.alive()
}

func (h *senderHandle) alive() error {
	if h.closed {
		return ErrUnauthorized
	}
	if exited, err := sys.PollPidfdFD(h.pidfd, 0); err != nil || exited {
		return ErrUnauthorized
	}
	return nil
}

func readSenderSnapshot(p Peer, authorize func(Peer) error) (Peer, error) {
	// Identity is bound at the send; these later facts judge the same process
	// at the decision and cannot establish its namespace or scope at the send.
	h := p.sender
	if err := h.validate(p); err != nil {
		return Peer{}, err
	}
	first, err := h.facts(p)
	if err != nil {
		return Peer{}, err
	}
	if err := authorize(first); err != nil {
		return Peer{}, err
	}
	h.barrier("governed-scopes")
	last, err := h.facts(p)
	if err != nil || first != last {
		return Peer{}, ErrUnauthorized
	}
	if err := h.validate(last); err != nil {
		return Peer{}, err
	}
	return last, nil
}
