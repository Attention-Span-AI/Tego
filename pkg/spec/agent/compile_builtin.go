// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"os"
	"path/filepath"
	"slices"
	"strconv"

	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

func (k *compiler) builtinRefusals() {
	if k.o.observe {
		return // record-only runs install no immutable enforcement state
	}
	uid, _ := config.InvokingUID()
	if k.o.socketUID >= 0 {
		uid = k.o.socketUID
	}
	user := strconv.Itoa(uid)
	if u, err := config.LookupPasswd(uid); err == nil {
		user = u.Username
	}
	b := &BuiltinRefusals{UID: uid, ServePort: 7433, Ledger: k.m.LedgerRoot.Value}
	if b.Ledger != "" {
		b.Ledger = k.abs(b.Ledger)
		b.LedgerResolved = k.resolve(b.Ledger)
	}
	if k.m.ServePort.Value > 0 && k.m.ServePort.Value <= 65535 {
		b.ServePort = uint16(k.m.ServePort.Value)
	}
	b.Runtime = append(b.Runtime, "/run/user/"+strconv.Itoa(uid))
	for _, p := range k.o.runtimeParents {
		d := filepath.Dir(p)
		if !slices.Contains(b.Runtime, d) {
			b.Runtime = append(b.Runtime, d)
		}
	}
	b.TegoDirs = append(b.TegoDirs, filepath.Join(k.o.home, ".tego"))
	for _, d := range b.Runtime {
		b.TegoDirs = append(b.TegoDirs, filepath.Join(d, "tego"))
	}
	b.TegoDirs = k.spellings(nil, b.TegoDirs)
	b.IPCDirs = []string{"/tmp/tmux-" + strconv.Itoa(uid), "/run/screen/S-" + user, "/var/run/screen/S-" + user, filepath.Join(k.o.home, ".screen"), "/tmp/emacs" + strconv.Itoa(uid), "/tmp/nvim." + user, "/tmp/.X11-unix"}
	envPath := func(key string) string {
		raw := os.Getenv(key)
		if raw == "" {
			return ""
		}
		p, ok := WalkedPath(k.asWalked(raw))
		if !ok {
			k.ds.errorf(k.cpos, CodePathMissing, "%s=%q cannot be placed for builtin.host_ipc", key, raw).
				fix("use a path with resolvable parents, or remove this environment variable")
			return ""
		}
		return p
	}
	if p := envPath("TMUX_TMPDIR"); p != "" {
		b.IPCDirs = append(b.IPCDirs, filepath.Join(p, "tmux-"+strconv.Itoa(uid)))
	}
	if p := envPath("SCREENDIR"); p != "" {
		b.IPCDirs = append(b.IPCDirs, p)
	}
	// Follow links now as well as checking the names at each operation. A moved
	// target retains its identity in the supervisor and in the plane's rows.
	b.Nodes = []string{"/run/dbus/system_bus_socket", "/var/run/dbus/system_bus_socket", "/run/docker.sock", "/var/run/docker.sock", "/run/podman/podman.sock", "/var/run/podman/podman.sock", "/run/containerd/containerd.sock", "/var/run/containerd/containerd.sock"}
	for _, root := range b.Runtime {
		b.Nodes = append(b.Nodes, filepath.Join(root, "docker.sock"), filepath.Join(root, "podman/podman.sock"))
		for _, leaf := range []string{"gnupg/S.gpg-agent.ssh", "openssh_agent", "ssh-agent.socket", "keyring/ssh", "gcr/ssh"} {
			b.PeerSockets = append(b.PeerSockets, filepath.Join(root, leaf))
		}
	}
	guardNames := map[string]bool{}
	all := append(append(append(slices.Clone(b.Runtime), b.IPCDirs...), b.TegoDirs...), b.Nodes...)
	for _, d := range all {
		resolved, err := filepath.EvalSymlinks(d)
		if err != nil {
			resolved = d
		}

		named := resolved
		for {
			parent := filepath.Dir(named)
			if _, err := os.Stat(parent); err == nil {
				break
			}
			if parent == "/" || parent == named {
				break
			}
			named = parent
		}
		parent := filepath.Dir(named)
		if canonical, err := filepath.EvalSymlinks(parent); err == nil {
			if suffix, err := filepath.Rel(parent, resolved); err == nil {
				resolved = filepath.Join(canonical, suffix)
			}
			parent = canonical
		}
		if resolved != d {
			switch {
			case slices.Contains(b.Runtime, d):
				if !slices.Contains(b.Runtime, resolved) {
					b.Runtime = append(b.Runtime, resolved)
				}
				tego := filepath.Join(resolved, RuntimeDirName)
				if !slices.Contains(b.TegoDirs, tego) {
					b.TegoDirs = append(b.TegoDirs, tego)
				}
			case slices.Contains(b.TegoDirs, d):
				if !slices.Contains(b.TegoDirs, resolved) {
					b.TegoDirs = append(b.TegoDirs, resolved)
				}
			case slices.Contains(b.Nodes, d):
				if !slices.Contains(b.Nodes, resolved) {
					b.Nodes = append(b.Nodes, resolved)
				}
			default:
				if !slices.Contains(b.IPCDirs, resolved) {
					b.IPCDirs = append(b.IPCDirs, resolved)
				}
			}
		}
		writable := false
		for _, w := range k.rt.FS {
			if w.Kind == FSWrite && (Covers(w.Canonical(), resolved) || Covers(resolved, w.Canonical())) {
				writable = true
				break
			}
		}
		guardKey := filepath.Join(parent, filepath.Base(named))
		if !guardNames[guardKey] {
			b.Names = append(b.Names, BuiltinName{Path: "builtin:" + resolved, Parent: parent, Name: filepath.Base(named), Target: resolved})
			guardNames[guardKey] = true
		}
		rule := b.WriteRule(d, false)
		if rule == "" {
			rule = BuiltinHostIPC
		}
		k.rt.DenyWrite = append(k.rt.DenyWrite, FSRule{Path: d, Resolved: resolved, Kind: FSDenyWrite, BuiltIn: true, BuiltinRule: rule, Unenforced: writable})
	}
	if k.c.IOUring && !k.o.observe && (k.mayLand(backend.TierCgroup) || k.mayLand(backend.TierBPFLSM)) {
		k.ds.errorf(k.pos("io_uring"), CodeIOUring, "io_uring: true cannot carry builtin.host_ipc and builtin.tego_surface: ring operations bypass the socket identity relay").fix("drop io_uring: so every connect uses the built-in boundary")
	}
	k.rt.Builtins = b
}

// builtinContainerAliases keeps a declared /var/run spelling usable after the
// inode relay resolves /run. A link to a different protected service never
// becomes a container exception.
func (k *compiler) builtinContainerAliases() {
	b := k.rt.Builtins
	if b == nil {
		return
	}
	for _, r := range k.rt.Net {
		if r.Proto != ProtoUnix || r.Abstract || r.Runtime != "" || r.Verdict != VerdictAllow || !IsContainerSocket(r.UnixPath, b.Runtime) {
			continue
		}
		p, err := filepath.EvalSymlinks(r.UnixPath)
		if err != nil {
			parent, e := filepath.EvalSymlinks(filepath.Dir(r.UnixPath))
			if e != nil {
				continue
			}
			p = filepath.Join(parent, filepath.Base(r.UnixPath))
		}
		if !IsContainerSocket(p, b.Runtime) {
			continue
		}
		if !slices.Contains(b.ContainerAliases, p) {
			b.ContainerAliases = append(b.ContainerAliases, p)
		}
		b.PeerSockets = append(b.PeerSockets, r.UnixPath, p)
	}
}

// Pin only exact, resolvable exception parents. Missing parents never broaden
// a native datagram exception to their nearest ancestor.
func (k *compiler) builtinPeerNames() {
	b := k.rt.Builtins
	if b == nil {
		return
	}
	seen := map[string]bool{}
	for _, p := range b.PeerSockets {
		parent, err := filepath.EvalSymlinks(filepath.Dir(p))
		if err != nil {
			continue
		}
		canonical := filepath.Join(parent, filepath.Base(p))
		if seen[canonical] {
			continue
		}
		seen[canonical] = true
		b.PeerNames = append(b.PeerNames, BuiltinName{Path: "builtin-peer:" + canonical, Parent: parent, Name: filepath.Base(p)})
	}
}
