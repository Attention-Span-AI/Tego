// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// hostSocket is one well-known host daemon socket: where it lives and why reaching it matters. %U in a
// path is the invoking user's runtime directory, /run/user/<uid>.
type hostSocket struct{ path, what string }

// hostSockets are the host daemons whose socket gives an agent a way out of the run or at the user's
// credentials. Each is a lateral-movement or persistence route documented against sandboxes: the session
// bus reaches systemd's user manager, whose StartTransientUnit runs any command outside the run (as
// `systemd-run --user` does); the Docker, Podman and containerd sockets start a container that mounts the
// host (root-equivalent for the rootful daemons); gpg-agent and the SSH agents sign with keys the agent
// cannot read; the X server takes synthetic keystrokes into every other window.
var hostSockets = []hostSocket{
	{"%U/bus", "the D-Bus session bus, through which systemd-run --user starts a command outside the run"},
	{"%U/systemd/private", "the systemd user manager"},
	{"/run/dbus/system_bus_socket", "the D-Bus system bus"},
	{"/var/run/docker.sock", "the Docker daemon, root-equivalent"},
	{"/run/docker.sock", "the Docker daemon, root-equivalent"},
	{"%U/docker.sock", "rootless Docker"},
	{"/run/podman/podman.sock", "the Podman API, root-equivalent"},
	{"%U/podman/podman.sock", "the rootless Podman API"},
	{"/run/containerd/containerd.sock", "containerd, root-equivalent"},
	{"%U/gnupg/S.gpg-agent", "gpg-agent, which signs and decrypts with your keys"},
	{"%U/gnupg/S.gpg-agent.ssh", "gpg-agent's SSH agent"},
	{"%U/openssh_agent", "the SSH agent"},
	{"%U/keyring/ssh", "the GNOME keyring's SSH agent"},
}

// x11Dir holds the X server's pathname sockets; each server also binds an abstract name of the same path.
const x11Dir = "/tmp/.X11-unix"

// maxX11Display bounds the displays looked up in x11Dir: X0 to X1023 covers the local console (:0), the
// displays VNC and Xephyr take (:1 upwards) and the virtual framebuffers of headless browser automation
// (xvfb-run's :99 upwards).
//
// /tmp is writable by every user and x11Dir is mode 1777, so the directory, a link standing at its name and
// any number of names inside it can be anyone's. x11Sockets therefore looks each display's name up rather
// than listing the directory: a bounded listing returns the first entries in the file system's order, which
// on tmpfs puts later names first, so anyone could push X0 out of it by creating enough names after it.
const maxX11Display = 1024

// x11Sockets returns the X server sockets in root+x11Dir, each as its path beneath x11Dir. The directory is
// opened O_PATH|O_DIRECTORY|O_NOFOLLOW: a FIFO or a device there is never opened, and a link there is not
// followed (it would report another directory's sockets as this host's X servers). Each name is looked up
// without following a link, since an X server binds its socket there itself. The directory's descriptor is owned by
// its *os.File and lent to the lookups through the File's SyscallConn (ADR 0023 A2: pkg/spec takes the standard
// library's owner, never a bare number it would close itself).
func x11Sockets(root string) []string {
	dir, err := os.OpenFile(filepath.Join(root, x11Dir), unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil
	}
	defer func() { _ = dir.Close() }()
	rc, err := dir.SyscallConn()
	if err != nil {
		return nil
	}
	var out []string
	if err := rc.Control(func(fd uintptr) {
		for n := 0; n < maxX11Display; n++ {
			name := "X" + strconv.Itoa(n)
			var st unix.Stat_t
			if unix.Fstatat(int(fd), name, &st, unix.AT_SYMLINK_NOFOLLOW) == nil && st.Mode&unix.S_IFMT == unix.S_IFSOCK {
				out = append(out, filepath.Join(x11Dir, name))
			}
		}
	}); err != nil {
		return nil
	}
	return out
}

// hostSocketsReachable is R19 as ADR 0070 amends it. A contract with no net: section is in the unix-only state
// (RuleTable.HostSocketsRefused): every IP destination is admitted, and a unix connect or an addressed unix datagram
// reaches only a socket a process of the run bound and tego's own endpoints; every other one, the daemon sockets
// below among them, is refused rule host-sockets. At tier landlock that is race-free (the supervisor relays every
// connect and addressed send, the abstract scope from Landlock ABI 6 and RESOLVE_UNIX from ABI 9 back it); at the root
// tiers immutable raw-name checks now back the relay; alias and unsupported-datagram residuals remain disclosed (ADR 0113).
//
// host_sockets: true is the opt-out, all or nothing like keyring: true, and the one default whose reach depends on
// what else runs on the machine, so compile names the well-known daemon sockets that exist here and what each one
// gives, docker.sock as root-equivalent. Abstract names are the other half: with the opt-out the Landlock scope
// still refuses an abstract name bound outside the run at ABI 6 (Linux 6.12) and later (enforce-landlock R7), and
// below that nothing does. Compile cannot tell the ABI (it makes no call beyond read-only file and DNS I/O, I6), so
// the warning states the condition. The fix steers to a net: section naming the one socket the agent needs.
//
// An --observe run (WithObserve, tego watch with no --boundary) refuses nothing and lists no best_effort cell
// (BestEffortCellsFor), so the root-tier note, which says a socket "is refused", is not given to it: as root it was the
// line under tego watch's notice that said the opposite of "No rule refuses anything".
func (k *compiler) hostSocketsReachable() {
	if k.c.Net != nil {
		return
	}
	if !k.c.HostSockets {
		if !k.o.observe && (k.mayLand(backend.TierCgroup) || k.mayLand(backend.TierBPFLSM)) {
			k.ds.warnf(k.cpos, CodeUnenforced, "best effort (%s): %s; the cell is recorded in run_start best_effort "+
				"and never counted as enforced (ADR 0070)", BestEffortHostSocketsRoot, bestEffortWhy[BestEffortHostSocketsRoot]).
				fix("add a net: section naming every endpoint the agent needs, whose unix: entries the root tiers admit in the " +
					"kernel where their unix programs load, or pin tier: landlock, which makes no root-tier claim")
		}
		return
	}
	found := k.hostSocketsFound()
	list := "none of the well-known daemon sockets exists on this machine now"
	if len(found) > 0 {
		list = "these among them: " + strings.Join(found, "; ")
	}
	k.ds.warnf(k.pos("host_sockets"), CodeHostSockets, "host_sockets: true lets the agent connect to every host socket "+
		"its uid can open except ADR 0113's immutable built-in refusals; these sockets exist here (protected sockets in this list remain refused): %s; and to every abstract socket (the X server's @/tmp/.X11-unix/X0, systemd's buses) on a "+
		"kernel below Landlock ABI 6 (Linux 6.12), where no scope refuses them", list).
		fix("remove host_sockets: true and add a net: section naming each endpoint the agent needs, with a unix: entry " +
			"for the one socket it uses (unix:/run/user/<uid>/openssh_agent for git over ssh); the session buses, " +
			"gpg-agent's main socket and Tego's surfaces remain refused")
}

// hostSocketsFound is each well-known daemon socket that exists here, as "path: what it gives".
func (k *compiler) hostSocketsFound() []string {
	uid := k.o.socketUID
	if uid < 0 {
		uid, _ = config.InvokingUID()
	}
	runtimeDir := filepath.Join("/run/user", strconv.Itoa(uid))
	var found []string
	seen := map[string]bool{}
	for _, s := range hostSockets {
		p := strings.Replace(s.path, "%U", runtimeDir, 1)
		if seen[p] || !isSocket(filepath.Join(k.o.socketRoot, p)) {
			continue
		}
		seen[p] = true
		found = append(found, p+": "+s.what)
	}
	for _, p := range x11Sockets(k.o.socketRoot) {
		found = append(found, p+": the X server, which takes keystrokes into every other window")
	}
	return found
}

// HostSocketWhat is what the well-known daemon socket at path gives an agent that reaches it ("the Docker daemon,
// root-equivalent"), for the refused line of a unix destination (ADR 0070), or "" for a socket the list does not
// name. runtimeDir is the invoking user's /run/user/<uid>, which the list's %U stands for.
func HostSocketWhat(path, runtimeDir string) string {
	for _, s := range hostSockets {
		if strings.Replace(s.path, "%U", runtimeDir, 1) == path {
			return s.what
		}
	}
	if dir, name := filepath.Split(path); filepath.Clean(dir) == x11Dir && strings.HasPrefix(name, "X") {
		return "the X server, which takes keystrokes into every other window"
	}
	return ""
}

// isSocket reports whether p is a unix socket, following a symlink as a connect would.
func isSocket(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.Mode()&os.ModeSocket != 0
}

func (k *compiler) containerSocketWarning() {
	if k.rt.Builtins == nil {
		return
	}
	for _, r := range k.rt.Net {
		if r.Runtime == "" && r.Proto == ProtoUnix && !r.Abstract && r.Verdict == VerdictAllow && IsContainerSocket(r.UnixPath, k.rt.Builtins.Runtime) {
			k.ds.warnf(r.Pos, CodeContainerSocketEscape, "%s admits a container daemon that can start containers outside the run", r.RuleName()).fix("keep this exact socket allowance only when the agent needs that authority")
		}
	}
}
