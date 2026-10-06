// SPDX-License-Identifier: Apache-2.0

package learn

import (
	"path"
	"regexp"
	"strings"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// runtimeDirRE is a path under a user's runtime directory, /run/user/<uid> (/var/run is a link to /run).
var runtimeDirRE = regexp.MustCompile(`^/(var/)?run/user/[0-9]+(/|$)`)

// sshAgentDirRE is the directory OpenSSH's ssh-agent makes its socket in, /tmp/ssh-XXXXXXXXXX/agent.<pid>.
var sshAgentDirRE = regexp.MustCompile(`^/tmp/ssh-[^/]+/agent\.[0-9]+$`)

// dangerous is why a unix socket is never proposed as an endpoint, or "". Each is a daemon whose socket gives the
// agent a way out of the run or at the user's credentials (the list agent.hostSockets keeps for compile's
// warning, which this one is kept in step with by hand: pkg/spec/agent does not export it).
//
// The socket's name is the abstract name when it starts with "@", else its path. The names here are matched on the
// string the agent connected to, which the record keeps as written: a link the agent made to one of them is not
// seen, and that is a limit of reading a record, not a decision.
func dangerous(sock string) string {
	abstract := strings.HasPrefix(sock, "@")
	name := strings.TrimPrefix(sock, "@")
	if !abstract {
		name = path.Clean(sock)
	}
	base := path.Base(name)
	switch {
	case name == "/tmp/.X11-unix" || strings.HasPrefix(name, "/tmp/.X11-unix/"):
		return "the X server, which takes keystrokes into every other window"
	case strings.HasPrefix(name, "/org/freedesktop/systemd1"), strings.HasPrefix(name, "/org/freedesktop/DBus"),
		strings.HasPrefix(name, "/tmp/dbus-"):
		return "a D-Bus or systemd bus, through which a command can be started outside the run"
	case !abstract && base == "bus" && runtimeDirRE.MatchString(name):
		return "the D-Bus session bus, through which systemd-run --user starts a command outside the run"
	case !abstract && base == "system_bus_socket":
		return "the D-Bus system bus"
	case !abstract && base == "private" && (path.Base(path.Dir(name)) == "systemd"):
		return "systemd's private socket (the service manager's own API)"
	case strings.HasPrefix(base, "S.gpg-agent") || strings.HasPrefix(base, "S.dirmngr"):
		return "gpg-agent, which signs and decrypts with your keys (its SSH socket included)"
	case !abstract && (sshAgentDirRE.MatchString(name) || base == "openssh_agent" || base == "ssh-agent.socket" ||
		strings.HasSuffix(name, "/keyring/ssh") || strings.HasSuffix(name, "/gcr/ssh")):
		return "an SSH agent, which signs with keys the agent cannot read"
	case base == "docker.sock":
		return "the Docker daemon, root-equivalent"
	case base == "podman.sock" || base == "containerd.sock":
		return "a container daemon, root-equivalent"
	}
	return ""
}

// classifyUnix decides one unix destination, "unix:<path>" or "unix:@<abstract name>".
func (l *Learner) classifyUnix(dst string) (entry, note string, left *Excluded) {
	sock, ok := strings.CutPrefix(dst, "unix:")
	if !ok || sock == "" || sock == "@" {
		return "", "", &Excluded{What: record.Printable(dst), Why: "not a socket path or abstract name"}
	}
	shown := record.Printable(dst)
	if why := dangerous(sock); why != "" {
		return "", "", &Excluded{What: shown, Why: why}
	}
	abstract := strings.HasPrefix(sock, "@")
	created := !abstract && l.touched[path.Clean(sock)]
	if !abstract && runtimeDirRE.MatchString(path.Clean(sock)) && !created {
		return "", "", &Excluded{What: shown, Why: "a socket under the user's runtime directory that this run did not create: the session's own services live there"}
	}
	if !plain(sock) {
		return "", "", &Excluded{What: shown, Why: "the name is not a plain path (a control or pattern character in it)"}
	}
	if !abstract && !path.IsAbs(sock) {
		return "", "", &Excluded{What: shown, Why: "not an absolute path"}
	}
	if created {
		note = "a socket the run created"
	}
	return "unix:" + sock, note, nil
}
