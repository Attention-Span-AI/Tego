// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

// ADR 0113's immutable rule names. They use the existing record rule field.
const (
	BuiltinHostIPC     = "builtin.host_ipc"
	BuiltinTegoSurface = "builtin.tego_surface"
	BuiltinOtherTTY    = "builtin.other_tty"
)

// BuiltinName names a configured protected entry, independently of host presence.
// Prepare pins its parent (or the first missing component beneath an existing
// ancestor). Target is the deny-write row that names a refusal.
type BuiltinName struct{ Path, Parent, Name, Target string }

// BuiltinRefusals captures the invoking host's immutable ADR 0113 boundary.
// Environment values add directories, never exceptions.
type BuiltinRefusals struct {
	UID int // invoking identity, not the privileged supervisor

	Names            []BuiltinName
	Runtime          []string
	IPCDirs          []string
	TegoDirs         []string
	Ledger           string
	LedgerResolved   string
	ServePort        uint16
	Nodes            []string // fixed socket nodes, including canonical spellings
	PeerNames        []BuiltinName
	PeerSockets      []string // exact SSH/container exceptions for the native peer check
	ContainerAliases []string `json:",omitempty"`
	// OwnRuntime is filled by the runtime, never by contract input.
	OwnRuntime         string
	OwnRuntimeResolved string
}

// UnixRule names the immutable refusal at a cleaned absolute socket path.
// Container sockets have the ADR's sole explicit-contract exception. SSH
// exceptions remove this refusal only; the ordinary contract still decides.
func (b *BuiltinRefusals) UnixRule(p string, containerAllowed bool) string {
	if b == nil || !filepath.IsAbs(p) {
		return ""
	}
	p = filepath.Clean(p)
	if b.OwnPath(p) {
		return ""
	}
	for _, d := range b.TegoDirs {
		if Covers(d, p) {
			return BuiltinTegoSurface
		}
	}
	if b.LedgerSocket(p) {
		return BuiltinTegoSurface
	}
	if IsContainerSocket(p, b.Runtime) {
		if containerAllowed {
			return ""
		}
		return BuiltinHostIPC
	}
	for _, node := range b.Nodes {
		if p == node {
			return BuiltinHostIPC
		}
	}
	for _, d := range b.Runtime {
		if Covers(d, p) {
			if sshSocket(strings.TrimPrefix(p, d+"/")) {
				return ""
			}
			return BuiltinHostIPC
		}
	}
	if p == "/run/dbus/system_bus_socket" || p == "/var/run/dbus/system_bus_socket" {
		return BuiltinHostIPC
	}
	if filepath.Dir(p) == "/tmp/.X11-unix" && strings.HasPrefix(filepath.Base(p), "X") {
		return BuiltinHostIPC
	}
	for _, d := range b.IPCDirs {
		if Covers(d, p) {
			return BuiltinHostIPC
		}
	}
	return ""
}

func sshSocket(p string) bool {
	switch p {
	case "openssh_agent", "ssh-agent.socket", "keyring/ssh", "gcr/ssh", "gnupg/S.gpg-agent.ssh":
		return true
	}
	parts := strings.Split(p, "/")
	return len(parts) == 3 && parts[0] == "gnupg" && strings.HasPrefix(parts[1], "d.") && len(parts[1]) > 2 && parts[2] == "S.gpg-agent.ssh"
}

// IsContainerSocket is ADR 0113 (2)'s fixed container-daemon list.
func IsContainerSocket(p string, runtime []string) bool {
	switch p {
	case "/run/docker.sock", "/var/run/docker.sock", "/run/podman/podman.sock", "/var/run/podman/podman.sock", "/run/containerd/containerd.sock", "/var/run/containerd/containerd.sock":
		return true
	}
	for _, d := range runtime {
		if p == d+"/docker.sock" || p == d+"/podman/podman.sock" {
			return true
		}
	}
	return false
}

// BuiltinUnixRule applies the non-overridable boundary before net.allow.
func (rt *RuleTable) BuiltinUnixRule(p string) string {
	if rt == nil || rt.Builtins == nil {
		return ""
	}
	explicit := slices.Contains(rt.Builtins.ContainerAliases, p)
	for _, r := range rt.Net {
		if r.Proto == ProtoUnix && !r.Abstract && r.Runtime == "" && r.Verdict == VerdictAllow && r.UnixPath == p {
			explicit = true
			break
		}
	}
	return rt.Builtins.UnixRule(p, explicit)
}

// OtherTTY identifies only numeric pty slaves and virtual consoles, never the
// multiplexor, /dev/tty, or serial devices. Own terminals are runtime grants.
func OtherTTY(p string) bool {
	var n string
	switch {
	case strings.HasPrefix(p, "/dev/pts/"):
		n = strings.TrimPrefix(p, "/dev/pts/")
	case strings.HasPrefix(p, "/dev/tty"):
		n = strings.TrimPrefix(p, "/dev/tty")
	default:
		return false
	}
	if n == "" {
		return false
	}
	_, err := strconv.ParseUint(n, 10, 32)
	return err == nil && !strings.ContainsAny(n, "+-")
}

// WriteRule is the unconditional name floor; no write entry (including one
// exactly at the target) lifts it. Ancestors applies to a directory rename.
func (b *BuiltinRefusals) WriteRule(p string, ancestors bool) string {
	if b == nil || p == "" {
		return ""
	}
	p = filepath.Clean(p)
	if b.OwnPath(p) && !(ancestors && Covers(p, b.OwnRuntime)) {
		return ""
	}
	for _, d := range b.TegoDirs {
		if Covers(d, p) || ancestors && Covers(p, d) {
			return BuiltinTegoSurface
		}
	}
	for _, ds := range [][]string{b.Runtime, b.IPCDirs} {
		for _, d := range ds {
			if Covers(d, p) || ancestors && Covers(p, d) {
				return BuiltinHostIPC
			}
		}
	}
	return ""
}

// OwnPath is the run's runtime directory under its validated spellings.
func (b *BuiltinRefusals) OwnPath(p string) bool {
	return b != nil && (b.OwnRuntime != "" && Covers(b.OwnRuntime, p) || b.OwnRuntimeResolved != "" && Covers(b.OwnRuntimeResolved, p))
}

// LedgerSocket is precise even when ledger_root is a shared directory.
func (b *BuiltinRefusals) LedgerSocket(p string) bool {
	return b != nil && (filepath.Base(p) == "ask.sock" || filepath.Base(p) == "operator.sock") &&
		(b.Ledger != "" && Covers(b.Ledger, p) || b.LedgerResolved != "" && Covers(b.LedgerResolved, p))
}
