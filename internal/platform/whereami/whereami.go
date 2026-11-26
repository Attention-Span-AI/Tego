// SPDX-License-Identifier: Apache-2.0

package whereami

import (
	"bytes"
	"os"

	"github.com/attention-span-ai/tego/internal/platform/peer"
	"github.com/attention-span-ai/tego/internal/runscope"
)

// Kind is where this process is, for the words of a message.
type Kind uint8

// The three places. Host is the zero value: an answer nobody filled in keeps today's words.
const (
	Host Kind = iota
	WSL
	Container
)

// Facts are the reads Detect makes, each one fact. Machine is the running system; a test supplies its own.
type Facts struct {
	// Present reports whether path is there, true only when it was seen: a path that cannot be looked at is absent.
	Present func(path string) bool
	// IsDir reports whether path is a directory, true only when it was seen as one.
	IsDir func(path string) bool
	// InitEnviron is process 1's environment, as /proc/1/environ holds it (NUL-separated), or the error that stopped
	// the read: a process that may not read it learns nothing from it.
	InitEnviron func() ([]byte, error)
	// WSLMarks is how many of WSL's marks hold (peer.WSLMarks): any one makes this WSL.
	WSLMarks func() int
}

// Machine is where Here reads: the running system.
var Machine = Facts{
	Present:     func(path string) bool { _, err := os.Lstat(path); return err == nil },
	IsDir:       func(path string) bool { fi, err := os.Stat(path); return err == nil && fi.IsDir() },
	InitEnviron: func() ([]byte, error) { return os.ReadFile("/proc/1/environ") },
	WSLMarks:    peer.WSLMarks,
}

// The marks of a container. Docker makes /.dockerenv in every container it starts, Podman /run/.containerenv, and a
// container runtime that sets `container` in process 1's environment says so there (Podman, LXC, systemd-nspawn).
const (
	dockerMark      = "/.dockerenv"
	podmanMark      = "/run/.containerenv"
	systemdBooted   = "/run/systemd/system"
	initEnvVariable = "container"
)

// Detect says where the facts f put a process. A container is shown by a positive mark and no systemd at process 1;
// WSL by one of its marks; anything else is a host.
func Detect(f Facts) Kind {
	if containerMark(f) && !f.IsDir(systemdBooted) {
		return Container
	}
	if f.WSLMarks() >= 1 {
		return WSL
	}
	return Host
}

// containerMark reports whether one of the three positive marks holds.
func containerMark(f Facts) bool {
	if f.Present(dockerMark) || f.Present(podmanMark) {
		return true
	}
	env, err := f.InitEnviron()
	if err != nil {
		return false
	}
	for _, kv := range bytes.Split(env, []byte{0}) {
		if v, ok := bytes.CutPrefix(kv, []byte(initEnvVariable+"=")); ok && len(v) > 0 {
			return true
		}
	}
	return false
}

// Here is Detect over the running system. A variable so a test describes the machine it needs.
var Here = func() Kind { return Detect(Machine) }

// ContainerNeeds is what Tego needs inside a container, in the words of docs/user/container.md: what the example
// image's entrypoint and examples/container/compose.yaml give it, in place of systemd's delegation.
const ContainerNeeds = "what the example image's entrypoint and examples/container/compose.yaml give it: a delegated " +
	"cgroup subtree that the entrypoint makes for the tego user (cgroup: private, and the SYS_ADMIN capability to remount " +
	"/sys/fs/cgroup read-write), apparmor=unconfined where AppArmor runs, and the kernel's security-module list handed in " +
	"(/run/tego-lsm/lsm-list); see docs/user/container.md and examples/container"

// ContainerCgroupCure is the cure of a failed cgroup check in a container.
const ContainerCgroupCure = "in a container there is no systemd to delegate a cgroup subtree: Tego needs " + ContainerNeeds

// ContainerNotAtTop is the sentence for "no service manager at the top of this cgroup tree" in a container: the
// commands that look for a user session (start, setup) find none there.
const ContainerNotAtTop = "this is a container, and no service manager (systemd) runs at the top of its cgroup tree " +
	"(process 1 is not in /init.scope), so there is no user session for this command to look for; in a container " +
	"Tego runs agents with tego run and needs " + ContainerNeeds

// Words are the sentences of a run-membership refusal for where this process is: the container's in a container, none
// elsewhere (WSL and a host keep runscope's own).
func Words() runscope.Words {
	if Here() == Container {
		return runscope.Words{NotAtTop: ContainerNotAtTop}
	}
	return runscope.Words{}
}

// CgroupCure is the cure a failed cgroup check prints: host is what a host (and WSL) have always printed, replaced in
// a container.
func CgroupCure(host string) string {
	if Here() == Container {
		return ContainerCgroupCure
	}
	return host
}
