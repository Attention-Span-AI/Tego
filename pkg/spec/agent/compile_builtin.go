// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"os"
	"path/filepath"
	"slices"
	"strconv"

	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

func (k *compiler) builtinRefusals() {
	if k.o.observe {
		return // record-only runs install no immutable enforcement state
	}
	uid := 0
	if k.o.caller != nil {
		uid = k.o.caller.UID
	} else {
		uid, _ = config.InvokingUID()
	}
	if k.o.ownerSet {
		uid = k.o.ownerUID
	}
	if k.o.socketUID >= 0 {
		uid = k.o.socketUID
	}
	user := strconv.Itoa(uid)
	if k.o.caller != nil {
		user = k.o.caller.Username
	} else if u, err := config.LookupPasswd(uid); err == nil {
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
	if k.o.home != "" {
		b.TegoDirs = append(b.TegoDirs, filepath.Join(k.o.home, ".tego"))
	}
	for _, d := range b.Runtime {
		b.TegoDirs = append(b.TegoDirs, filepath.Join(d, "tego"))
	}
	b.TegoDirs = k.spellings(nil, b.TegoDirs)
	b.IPCDirs = []string{"/tmp/tmux-" + strconv.Itoa(uid), "/run/screen/S-" + user, "/var/run/screen/S-" + user}
	if k.o.home != "" {
		b.IPCDirs = append(b.IPCDirs, filepath.Join(k.o.home, ".screen"))
	}
	b.IPCDirs = append(b.IPCDirs, "/tmp/emacs"+strconv.Itoa(uid), "/tmp/nvim."+user, "/tmp/.X11-unix",
		"/run/WSL", "/mnt/wslg/.X11-unix", "/mnt/wslg/runtime-dir")
	// Protect WSLg's server directories, not /mnt/wslg itself: its distro
	// mount is a second view of the whole Linux filesystem. FIFO inventory
	// must not walk that tree as though it were a session-server directory.
	envPath := func(key string) string {
		raw := ""
		if k.o.caller != nil {
			if key == "TMUX_TMPDIR" {
				raw = k.o.caller.TMUXDir
			} else {
				raw = k.o.caller.ScreenDir
			}
		} else {
			raw = os.Getenv(key)
		}
		if raw == "" {
			return ""
		}
		// A relative value is resolved against the working directory, and the folder it resolves to is a place Tego
		// resolved: the FIFO check prints it where its message is about that folder (identity envtext.go, rule (c)).
		p, ok := WalkedPath(k.asWalked(raw))
		if !ok {
			// Only a value that is not an absolute clean path can fail here: an absolute clean path holds no ".." for
			// WalkedPath to resolve (TestPlacedEnvValueAlwaysWalks). Such a value failed validation and is never
			// echoed (identity envtext.go, rule (b)).
			k.ds.errorf(k.cpos, CodePathMissing, "the %s value is not an absolute clean path, so it cannot be placed for builtin.host_ipc", key).
				fix("set %s to an absolute path with resolvable parents, or remove it; %s", key, identity.EnvInspect(key))
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
	b.Nodes = []string{"/mnt/wslg/PulseServer", "/run/dbus/system_bus_socket", "/var/run/dbus/system_bus_socket", "/run/docker.sock", "/var/run/docker.sock", "/run/podman/podman.sock", "/var/run/podman/podman.sock", "/run/containerd/containerd.sock", "/var/run/containerd/containerd.sock"}
	for _, root := range b.Runtime {
		b.Nodes = append(b.Nodes, filepath.Join(root, "docker.sock"), filepath.Join(root, "podman/podman.sock"))
		for _, leaf := range []string{"gnupg/S.gpg-agent.ssh", "openssh_agent", "ssh-agent.socket", "keyring/ssh", "gcr/ssh"} {
			b.PeerSockets = append(b.PeerSockets, filepath.Join(root, leaf))
		}
	}
	guardNames := map[string]bool{}
	all := append(append(append(slices.Clone(b.Runtime), b.IPCDirs...), b.TegoDirs...), b.Nodes...)
	for _, d := range all {
		resolved := builtinResolvedPath(d, k.builtinCut)

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
		parent := builtinResolvedPath(filepath.Dir(d), k.builtinCut)
		guardKey := filepath.Join(parent, filepath.Base(d))
		if !guardNames[guardKey] {
			b.Names = append(b.Names, BuiltinName{Path: "builtin:" + d, Parent: parent, Name: filepath.Base(d), Target: resolved})
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

// Canonicalize existing prefixes without using presence to select an entry's
// name. /var/run must remain /run even when a server directory is absent.
// cut hears a prefix a permission failure kept from being resolved
// (compiler.builtinCut or namePredictionUnavailable): root resolves it, perhaps elsewhere.
func builtinResolvedPath(p string, cut func(string, error)) string {
	for head := p; ; head = filepath.Dir(head) {
		canonical, err := filepath.EvalSymlinks(head)
		if err == nil {
			if suffix, err := filepath.Rel(head, p); err == nil {
				return filepath.Join(canonical, suffix)
			}
		} else if cut != nil {
			cut(head, err)
		}
		if head == "/" {
			return p
		}
	}
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
			k.namePredictionUnavailable(r.UnixPath, err) // root resolves it: a root-tier prediction is unknown
			parent, e := filepath.EvalSymlinks(filepath.Dir(r.UnixPath))
			if e != nil {
				k.namePredictionUnavailable(filepath.Dir(r.UnixPath), e)
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
			k.builtinCut(filepath.Dir(p), err) // root pins it: a root-tier prediction is unknown
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
