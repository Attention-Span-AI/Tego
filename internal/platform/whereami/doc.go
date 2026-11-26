// SPDX-License-Identifier: Apache-2.0

// Package whereami answers one question for the words of a refusal: where is this process, on a host, on WSL, or in a
// container. It changes no decision. A check that fails fails as it did; what changes is the cure the message prints,
// because "enable systemd user delegation" is true on a host with systemd, "turn systemd on in /etc/wsl.conf" on WSL,
// and neither inside a container that has no systemd, where the cure is what examples/container gives the container
// (docs/user/container.md).
//
// The answer rests on positive facts only. A container is shown by /.dockerenv, by /run/.containerenv, or by a
// `container` variable in process 1's environment (where that file is readable); a mark that cannot be looked at
// counts as absent, never as present, so an ordinary machine is never taken for a container. A machine on which
// systemd runs as process 1 (/run/systemd/system is a directory, as sd_booted(3) tests) is not given the container
// words even with a mark, because the systemd cure is the true one there (LXC, systemd-nspawn, a systemd image).
// WSL is told by the marks internal/platform/peer already counts for the run-membership gate (the kernel release,
// /run/WSL, the binfmt_misc entries); a container on a WSL kernel is a container. Anything else is a host, and a host
// keeps every word it had.
//
// Facts it did not use, and why: /proc/1/cgroup text (a private cgroup namespace shows "0::/", and the names Docker
// and Kubernetes put in a host namespace are not stable); the root filesystem being an overlay (a live system or an
// ordinary host can be one); KUBERNETES_SERVICE_HOST and other variables of the caller's own environment (the caller
// sets them); the hostname; and the cgroup namespace not being the machine's first one (WSL, a nested system and a
// Docker run with --cgroupns=host are not told apart by it). A Kubernetes pod under containerd has none of the three
// marks, so it is told as a host and keeps the host words.
//
// Imports: standard library, internal/platform/peer (the WSL marks), internal/runscope
// Must not import: internal/runtime, internal/doctor, internal/policy, internal/check
package whereami
