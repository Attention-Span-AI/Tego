// SPDX-License-Identifier: Apache-2.0

package demo

// The demo kit's three stated limits (GAPS N92), each held in a test: the name-lookup sockets follow the host's
// nsswitch.conf and the kit says which modules it cannot name, a host with no procfs is refused in words, and a reset on
// a host with no python3 still ends the helpers it started.

import (
	"bytes"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// demoSplit runs demo.sh and returns its standard output and its standard error apart.
func (k *plainKit) demoSplit(env []string, args ...string) (stdout, stderr string, err error) {
	k.t.Helper()
	cmd := exec.Command("sh", append([]string{"demo.sh"}, args...)...)
	cmd.Env = env
	var o, e bytes.Buffer
	cmd.Stdout, cmd.Stderr = &o, &e
	err = cmd.Run()
	return o.String(), e.String(), err
}

// TestNameLookupFollowsTheHostsNameServices (N92 (a)): a host whose nsswitch.conf names sssd or avahi's mdns module has
// the lookup go to that module's socket first, which showed as an extra net refusal. The kit names the socket of each
// module the host's hosts, passwd and group lines name, when it exists, and no other; and it says, in words, which module
// it does not know (ldap, nis, winbind), instead of leaving the presenter a refusal with no explanation.
func TestNameLookupFollowsTheHostsNameServices(t *testing.T) {
	root, err := os.MkdirTemp("", "rr")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	k := newPlainKit(t, "DEMO_RESOLVER_ROOT="+root)
	const nscd = `"unix:/var/run/nscd/socket"`

	write := func(content string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Join(root, "etc"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, "etc/nsswitch.conf"), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// Sockets the host has: avahi's and sssd's, which only a module that names them makes the lookup ask.
	listen(t, filepath.Join(root, "var/run/avahi-daemon/socket"))
	listen(t, filepath.Join(root, "var/lib/sss/pipes/nss"))

	// No nsswitch.conf: the sockets are not asked for, whatever exists.
	if got, note, err := k.demoSplit(k.env, "lookup"); err != nil || strings.TrimSpace(got) != nscd || note != "" {
		t.Fatalf("no nsswitch.conf: lookup = %q, note %q (%v), want %s and no note", got, note, err, nscd)
	}

	// Ubuntu's stock hosts line, with bracketed actions and a comment: avahi's socket, no note.
	write("# /etc/nsswitch.conf\npasswd: files systemd\nhosts: files mdns4_minimal [NOTFOUND=return] dns # comment\nnetworks: files\n")
	got, note, err := k.demoSplit(k.env, "lookup")
	if err != nil || strings.TrimSpace(got) != nscd+`, "unix:/var/run/avahi-daemon/socket"` || note != "" {
		t.Fatalf("mdns4_minimal: lookup = %q, note %q (%v)", got, note, err)
	}

	// sssd on passwd and group, an LDAP module on hosts and a second line naming a module twice: sssd's socket once; the
	// kit names ldap and nis as the ones it cannot name, and not the modules it knows.
	write("passwd: files sss\ngroup: files [SUCCESS=merge] sss\nhosts: files sss ldap dns\nhosts: nis myhostname\nshadow: files vault\n")
	got, note, err = k.demoSplit(k.env, "lookup")
	if err != nil || strings.TrimSpace(got) != nscd+`, "unix:/var/lib/sss/pipes/nss"` {
		t.Fatalf("sss: lookup = %q (%v)", got, err)
	}
	for _, want := range []string{"note: /etc/nsswitch.conf names the name service(s) ldap nis,", "does not know", "net.allow"} {
		if !strings.Contains(note, want) {
			t.Errorf("the note %q lacks %q", note, want)
		}
	}
	if strings.Contains(note, "sss") || strings.Contains(note, "vault") {
		t.Errorf("the note names a module the kit knows or a line it does not read: %q", note)
	}

	// The note is in setup's own output too, where the presenter looks.
	out := k.mustDemo("setup")
	if !strings.Contains(out, "names the name service(s) ldap nis,") {
		t.Errorf("setup does not say which name services it does not know:\n%s", out)
	}
	b, err := os.ReadFile(filepath.Join(k.stage, "project", "agent.yaml"))
	if err != nil || !strings.Contains(string(b), `"unix:/var/lib/sss/pipes/nss"`) {
		t.Errorf("agent.yaml does not allow sssd's socket (%v):\n%s", err, b)
	}
}

// TestKitRefusesAHostWithNoProcInWords (N92 (b)): the kit knows a helper by its process (the start time, the arguments and
// the open sockets under /proc), so a system with no Linux procfs cannot run it. It says so, and what to do, before it
// starts anything, and not by an error about a pid.
func TestKitRefusesAHostWithNoProcInWords(t *testing.T) {
	empty := t.TempDir()
	k := newPlainKit(t, "DEMO_PROC_ROOT="+empty)
	out, err := k.demo("setup")
	if err == nil {
		t.Fatalf("setup ran on a host with no procfs:\n%s", out)
	}
	want := "demo.sh: this demo runs on Linux only: it knows the helpers it starts by their process (the start time and arguments in " +
		empty + "/<pid>), and this system has no readable " + empty + ". Run it on a Linux machine or in a Linux VM."
	if strings.TrimSpace(out) != want {
		t.Errorf("setup said\n%s\nwant\n%s", out, want)
	}
	if _, err := os.Stat(k.stage); err == nil {
		t.Error("a stage was made before the refusal")
	}
	c, err := net.DialTimeout("tcp", "127.0.0.1:"+k.port, 300*time.Millisecond)
	if err == nil {
		_ = c.Close()
		t.Error("a sink was started before the refusal")
	}
	// lookup touches no process and no stage.
	if _, err := k.demo("lookup"); err != nil {
		t.Errorf("lookup on a host with no procfs: %v", err)
	}
}

// toolsOnly is a PATH folder holding the programs the reset path runs, and no python3.
func toolsOnly(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for _, tool := range []string{"sh", "dirname", "readlink", "cat", "id", "rm", "cksum", "cut", "sed", "awk", "tr", "grep", "sort", "head", "kill", "env", "sleep"} {
		p, err := exec.LookPath(tool)
		if err != nil {
			continue
		}
		if err := os.Symlink(p, filepath.Join(dir, tool)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := exec.LookPath("python3"); err == nil {
		// The folder must not give python3 by another route.
		if _, err := os.Stat(filepath.Join(dir, "python3")); err == nil {
			t.Fatal("python3 is in the tools folder")
		}
	}
	return dir
}

// TestResetEndsTheHelpersWithoutPython (N92 (c)): setup starts the sink with python3; a reset from a shell where python3
// is not on PATH (a venv left, an interpreter removed, another user's PATH) found no helper to stop, said the sink was
// stopped, and removed the pid file that was the only record of it. It now makes procid.py's checks in sh and ends the
// helper that passes them, says it did it that way, and still leaves a process that is not the helper alone.
func TestResetEndsTheHelpersWithoutPython(t *testing.T) {
	k := newPlainKit(t)
	t.Cleanup(func() { stopSinkOn(t, k.port) })
	listens := func() bool {
		c, err := net.DialTimeout("tcp", "127.0.0.1:"+k.port, 500*time.Millisecond)
		if err == nil {
			_ = c.Close()
		}
		return err == nil
	}
	noPython := append([]string(nil), k.env...)
	for i, e := range noPython {
		if strings.HasPrefix(e, "PATH=") {
			noPython[i] = "PATH=" + toolsOnly(t)
		}
	}

	k.mustDemo("setup")
	if !listens() {
		t.Fatal("setup did not start the sink")
	}
	// A stranger the pid file of another helper names, and one with the sink's script among its words but the wrong start time.
	other, start := sleeper(t)
	if err := os.WriteFile(filepath.Join(k.stage, "sockd.pid"), []byte(strconv.Itoa(other)+" "+start+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, _, err := k.demoSplit(noPython, "reset")
	if err != nil {
		t.Fatalf("reset without python3: %v\n%s", err, out)
	}
	// What it says is what it did (review F2): the sink was ended, and sockd.pid names a process that is not sockd.py,
	// which is left running with its pid file kept.
	if !strings.Contains(out, "helpers stopped (TERM sent): sink") || strings.Contains(out, "sink stopped") {
		t.Errorf("reset does not name the helper it ended:\n%s", out)
	}
	if !strings.Contains(out, "left running, not recognised as this demo's: sockd") {
		t.Errorf("reset does not say it left sockd alone:\n%s", out)
	}
	if _, err := os.Stat(filepath.Join(k.stage, "sockd.pid")); err != nil {
		t.Errorf("reset removed the pid file of a process it left running: %v", err)
	}
	if _, err := os.Stat(filepath.Join(k.stage, "sink.pid")); err == nil {
		t.Error("reset kept the pid file of the sink it ended")
	}
	if !strings.Contains(out, "demo.sh: python3 is not on PATH, so procid.py cannot run; stopping the helpers by the pid files' start time and script with sh alone.") {
		t.Errorf("reset does not say how it stopped the helpers:\n%s", out)
	}
	time.Sleep(500 * time.Millisecond)
	if listens() {
		t.Error("the sink still listens after a reset without python3")
	}
	if !alive(other) {
		t.Errorf("reset ended pid %d, a process that is not sockd.py", other)
	}

	// A pid file with another start time is a reused pid: not ours, not ended, even without python3.
	k.mustDemo("setup")
	b, err := os.ReadFile(filepath.Join(k.stage, "sink.pid"))
	if err != nil {
		t.Fatal(err)
	}
	f := strings.Fields(string(b))
	if len(f) != 2 {
		t.Fatalf("sink.pid = %q", b)
	}
	if err := os.WriteFile(filepath.Join(k.stage, "sink.pid"), []byte(f[0]+" 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, _, err = k.demoSplit(noPython, "reset")
	if err != nil {
		t.Fatal(err)
	}
	if !listens() {
		t.Error("a reset without python3 ended a process whose start time did not match the pid file")
	}
	if strings.Contains(out, "sink stopped") || strings.Contains(out, "helpers stopped") || !strings.Contains(out, "left running, not recognised as this demo's: sink") {
		t.Errorf("reset claims a sink it left running was stopped:\n%s", out)
	}
	if _, err := os.Stat(filepath.Join(k.stage, "sink.pid")); err != nil {
		t.Errorf("reset removed the pid file of the sink it left running: %v", err)
	}
}

// TestResetSaysWhatItDidWithPython (review F2): with procid.py the reset also names the helpers it sent TERM to and the
// ones it left running, and keeps the pid file of a live process it did not recognise; a pid file whose process has
// ended is no process to leave, so it is removed and not reported.
func TestResetSaysWhatItDidWithPython(t *testing.T) {
	k := newPlainKit(t)
	t.Cleanup(func() { stopSinkOn(t, k.port) })
	k.mustDemo("setup")
	other, start := sleeper(t)
	if err := os.WriteFile(filepath.Join(k.stage, "sockd.pid"), []byte(strconv.Itoa(other)+" "+start+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(k.stage, "stub.pid"), []byte("999999 1\n"), 0o600); err != nil { // no such process
		t.Fatal(err)
	}
	out := k.mustDemo("reset")
	if !strings.Contains(out, "helpers stopped (TERM sent): sink;") || !strings.Contains(out, "left running, not recognised as this demo's: sockd (") || strings.Contains(out, "stub") {
		t.Errorf("reset does not say what it did:\n%s", out)
	}
	if !alive(other) {
		t.Errorf("reset ended pid %d, a process that is not sockd.py", other)
	}
	if _, err := os.Stat(filepath.Join(k.stage, "sockd.pid")); err != nil {
		t.Errorf("the pid file of a process left running was removed: %v", err)
	}
	for _, gone := range []string{"sink.pid", "stub.pid"} {
		if _, err := os.Stat(filepath.Join(k.stage, gone)); err == nil {
			t.Errorf("%s was kept", gone)
		}
	}
}
