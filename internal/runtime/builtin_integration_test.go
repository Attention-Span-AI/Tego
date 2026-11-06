// SPDX-License-Identifier: Apache-2.0

//go:build integration

package runtime

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/testutil"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/record"
	"golang.org/x/sys/unix"
)

const builtinProbe = `import errno, os, socket, subprocess, sys, time, ctypes
if len(sys.argv)>1 and sys.argv[1]=='child':
    s=socket.socket(socket.AF_UNIX)
    try:
        s.connect(sys.argv[2]); sys.exit(7)
    except OSError as e:
        sys.exit(0 if e.errno in (errno.EACCES,errno.EPERM) else 8)
root, abstract, foreignpty, ledger = sys.argv[1:]
out=os.path.abspath('out')
def connect(label,path):
    s=socket.socket(socket.AF_UNIX)
    try:
        s.connect(path); result='ok'
    except OSError as e:
        result=errno.errorcode.get(e.errno,str(e.errno))
    s.close()
    with open(out+'/rc-'+label,'w') as f: f.write(result)
for name in ('bus','systemd/private','gnupg/S.gpg-agent','gnupg/S.gpg-agent.extra','gnupg/S.gpg-agent.ssh','tego/other/operator.sock'):
    connect(name.replace('/','_'),root+'/'+name)
connect('ledger',ledger)
connect('ledger-alias',out+'/ledger-link')
for name in ('link','hard'):
    connect(name,out+'/'+name)
connect('proc','/proc/'+str(os.getppid())+'/root'+root+'/bus')
os.chdir(root)
connect('relative','bus')
os.chdir(os.path.dirname(out))
connect('abstract','\0'+abstract)
rc=subprocess.call([sys.executable,__file__,'child',root+'/bus'])
with open(out+'/child','w') as f: f.write(str(rc))
try:
    fd=os.open(foreignpty,os.O_RDONLY)
    os.close(fd); result='ok'
except OSError as e:
    result=errno.errorcode.get(e.errno,str(e.errno))
with open(out+'/rc-foreignpty','w') as f: f.write(result)
try:
    fd=os.open(root+'/screen-pipe',os.O_RDONLY|os.O_NONBLOCK)
    os.close(fd); result='ok'
except OSError as e:
    result=errno.errorcode.get(e.errno,str(e.errno))
with open(out+'/rc-fifo','w') as f: f.write(result)
for label,op in (('tcp-connect','connect'),('tcp-bind','bind')):
    sock=socket.socket()
    try:
        getattr(sock,op)(('127.0.0.1',7433)); result='ok'
    except OSError as e:
        result=errno.errorcode.get(e.errno,str(e.errno))
    sock.close()
    with open(out+'/rc-'+label,'w') as f: f.write(result)
libc=ctypes.CDLL(None,use_errno=True)
pidfd=libc.syscall(434,os.getpid(),0)
assert pidfd>=0
fd=libc.syscall(438,pidfd,0,0)
result=errno.errorcode.get(ctypes.get_errno(),'unknown') if fd<0 else 'ok'
if fd>=0: os.close(fd)
os.close(pidfd)
with open(out+'/rc-pidfd','w') as f: f.write(result)
# Both pty APIs must work. The pathname reopen is deliberately O_NOCTTY.
import fcntl, struct, termios
m=os.open('/dev/ptmx',os.O_RDWR|os.O_NOCTTY)
fcntl.ioctl(m,0x40045431,struct.pack('i',0))
n=struct.unpack('i',fcntl.ioctl(m,0x80045430,struct.pack('i',0)))[0]
s=os.open('/dev/pts/'+str(n),os.O_RDWR|os.O_NOCTTY)
os.write(m,b'x\n')
assert os.read(s,2)==b'x\n'
os.close(s)
s=fcntl.ioctl(m,0x5441,os.O_RDWR|os.O_NOCTTY)
os.close(s); os.close(m)
with open(out+'/pty','w') as f: f.write('ok')
try:
    os.mkdir(out+'/blocked'); result='ok'
except OSError as e:
    result=errno.errorcode.get(e.errno,str(e.errno))
with open(out+'/rc-mkdir','w') as f: f.write(result)
# The protected target's parent did not exist at compile time. An outside
# creation must not make its protected child writable through the broad grant.
with open(out+'/parent-now','w') as f: f.write('ready')
for _ in range(1000):
    if os.path.exists(out+'/parent-done'): break
    time.sleep(.01)
assert open(out+'/parent-done').read()=='ok'
try:
    os.mkdir(out+'/new-parent/tmux-'+str(os.getuid())); result='ok'
except OSError as e:
    result=errno.errorcode.get(e.errno,str(e.errno))
with open(out+'/rc-nested-mkdir','w') as f: f.write(result)
# An outside move must not turn the prepared directory into an allowed server.
with open(out+'/move-now','w') as f: f.write('ready')
for _ in range(1000):
    if os.path.exists(out+'/move-done'): break
    time.sleep(.01)
assert open(out+'/move-done').read()=='ok'
connect('moved',os.path.dirname(root)+'/moved/moving')
`

func TestIntegrationBuiltinRefusals(t *testing.T) {
	for _, explicit := range []bool{false, true} {
		t.Run(fmt.Sprintf("explicit=%v", explicit), func(t *testing.T) { builtinRun(t, tegoBinary(t), "landlock", explicit) })
	}
}

func TestRootBuiltinRefusals(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root only: cgroup and bpflsm built-in refusals")
	}
	bin := tegoBPFBinary(t)
	for _, tier := range []string{"cgroup", "bpflsm"} {
		t.Run(tier, func(t *testing.T) {
			probe := &askReadScene{bin: bin}
			probe.f = newFixture(t, contractFor("ibuiltinprobe", []string{"/bin/true"}, []string{"/bin/true"}))
			probe.env = isolatedEnv(t, probe.f)
			testutil.RequireTier(t, probe.tego(t, "doctor", "--require", tier), tier)
			t.Run("controlling-tty", func(t *testing.T) { builtinControllingTTY(t, bin, tier) })
			t.Run("pty-policy", func(t *testing.T) { builtinPTYPolicy(t, bin, tier) })
			for _, explicit := range []bool{false, true} {
				t.Run(fmt.Sprintf("explicit=%v", explicit), func(t *testing.T) { builtinRun(t, bin, tier, explicit) })
			}
		})
	}
}

func builtinRun(t *testing.T, bin, tier string, explicit bool) {
	t.Helper()
	dir, err := os.MkdirTemp(filepath.Dir(os.TempDir()), "c40-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	// This short socket root is beside TestMain's TMPDIR, so agentReaches
	// intentionally will not chmod it. Let the dropped KVM agent traverse it.
	if err := os.Chmod(dir, 0o711); err != nil {
		t.Fatal(err)
	}
	host := filepath.Join(dir, "h")
	for _, p := range []string{host, host + "/systemd", host + "/gnupg", host + "/tego/other"} {
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	agentReaches(t, host)
	var listeners []net.Listener
	for _, n := range []string{"bus", "moving", "systemd/private", "gnupg/S.gpg-agent", "gnupg/S.gpg-agent.extra", "gnupg/S.gpg-agent.ssh", "tego/other/operator.sock"} {
		p := filepath.Join(host, n)
		ln, err := net.Listen("unix", p)
		if err != nil {
			t.Fatal(err)
		}
		listeners = append(listeners, ln)
		if err := os.Chmod(p, 0o666); err != nil {
			t.Fatal(err)
		}
	}
	abstract := "tego-c40-" + strconv.Itoa(os.Getpid()) + "-" + filepath.Base(dir)
	ln, err := net.Listen("unix", "\x00"+abstract)
	if err != nil {
		t.Fatal(err)
	}
	listeners = append(listeners, ln)
	t.Cleanup(func() {
		for _, ln := range listeners {
			_ = ln.Close()
		}
	})
	// The accepted calls need no server payload; draining every queue prevents a
	// broken guard from turning the test into a blocked connect.
	for _, ln := range listeners {
		go func(ln net.Listener) {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				_ = c.Close()
			}
		}(ln)
	}
	master, err := unix.Open("/dev/ptmx", unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(master) //nolint:errcheck // test terminal
	if err := unix.IoctlSetPointerInt(master, unix.TIOCSPTLCK, 0); err != nil {
		t.Fatal(err)
	}
	idx, err := unix.IoctlGetInt(master, unix.TIOCGPTN)
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkfifo(filepath.Join(host, "screen-pipe"), 0o666); err != nil {
		t.Fatal(err)
	}
	foreignPTY := "/dev/pts/" + strconv.Itoa(idx)
	agentOwns(t, foreignPTY)
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Fatal(err)
	}
	contract := fmt.Sprintf("version: 0\nname: ibuiltin\ncommand: [%q]\ntier: landlock\nfs:\n  write: [\"./out/\", \"/dev/pts/\"]\n  deny_read: []\nrecord: full\nlimits:\n  pids: 128\n", python)
	if explicit {
		// A net: section that names only the SSH exception: every other probe is refused by the built-ins before the
		// section is read, as the probes' rule ids show. An entry naming a protected socket (the bus, the user
		// manager, gpg-agent, another run's or the ledger's control socket, or a link that resolves to one) is a
		// compile-time contradiction now (TestBuiltinRefusedAllowIsAContradiction). The root tiers load no kernel
		// allow row for such an entry either (cgroup's builtinUnixRows), so dropping them changes no cell here.
		contract += "net:\n  allow: [" + strconv.Quote("unix:"+filepath.Join(host, "gnupg/S.gpg-agent.ssh")) + "]\n"
	} else {
		contract += "host_sockets: true\n"
	}
	if tier != "landlock" && explicit {
		contract = strings.Replace(contract, "record: full", "record: summary", 1)
	}
	project := filepath.Join(dir, "project")
	if err := os.Mkdir(project, 0o755); err != nil {
		t.Fatal(err)
	}
	ledgerRoot := filepath.Join(dir, "l")
	if err := os.Mkdir(ledgerRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	f := newFixtureIn(t, project, contract, func(m *config.Machine) { m.LedgerRoot.Value = ledgerRoot })
	f.root = ledgerRoot
	ledgerSocket := filepath.Join(ledgerRoot, "ask.sock")
	control, err := net.Listen("unix", ledgerSocket)
	if err != nil {
		t.Fatal(err)
	}
	listeners = append(listeners, control)
	if err := os.Chmod(ledgerSocket, 0o666); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(ledgerSocket, filepath.Join(f.out, "ledger-link")); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"link", "hard"} {
		p := filepath.Join(f.out, n)
		if n == "link" {
			err = os.Symlink(host+"/bus", p)
		} else {
			err = os.Link(host+"/bus", p)
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	script := filepath.Join(f.dir, "probe.py")
	if err := os.WriteFile(script, []byte(builtinProbe), 0o644); err != nil {
		t.Fatal(err)
	}
	s := &askReadScene{bin: bin, f: f}
	s.env = isolatedEnv(t, f)
	s.env = append(s.env, "XDG_RUNTIME_DIR="+host, "SCREENDIR="+filepath.Join(f.out, "blocked"), "TMUX_TMPDIR="+filepath.Join(f.out, "new-parent"))
	// Compile under the real CLI: XDG_RUNTIME_DIR is the invoking environment's
	// additional refusal base, never a contract-supplied exception.
	if tier != "landlock" {
		contract = strings.Replace(contract, "tier: landlock", "tier: "+tier, 1)
		if err := os.WriteFile(filepath.Join(f.dir, "agent.yaml"), []byte(contract), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	cmd := s.tego(t, "run", filepath.Join(f.dir, "agent.yaml"), "--", python, script, host, abstract, foreignPTY, ledgerSocket)
	cmd.Dir = f.dir
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	moved := make(chan error, 1)
	// Publish the complete payload: exists-before-write let the probe read an
	// empty marker while the outside helper was still writing it.
	signal := func(name string) error {
		p := filepath.Join(f.out, name)
		if err := os.WriteFile(p+".new", []byte("ok"), 0o644); err != nil {
			return err
		}
		return os.Rename(p+".new", p)
	}
	go func() {
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		parentMade := false
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if !parentMade {
					if _, err := os.Stat(filepath.Join(f.out, "parent-now")); err == nil {
						parent := filepath.Join(f.out, "new-parent")
						err = os.Mkdir(parent, 0o755)
						if err == nil && os.Geteuid() == 0 {
							var st unix.Stat_t
							err = unix.Stat(f.out, &st)
							if err == nil {
								err = unix.Chown(parent, int(st.Uid), int(st.Gid))
							}
						}
						if err == nil {
							err = signal("parent-done")
						}
						if err != nil {
							moved <- err
							return
						}
						parentMade = true
					}
				}
				if _, err := os.Stat(filepath.Join(f.out, "move-now")); err != nil {
					continue
				}
				err := os.Rename(host, filepath.Join(dir, "moved"))
				if err == nil {
					err = signal("move-done")
				}
				moved <- err
				return
			}
		}
	}()
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("run %s: %v\n%s", tier, err, out)
	}
	for _, name := range []string{"bus", "systemd_private", "gnupg_S.gpg-agent", "gnupg_S.gpg-agent.extra", "tego_other_operator.sock", "link", "hard", "proc", "relative", "abstract", "foreignpty", "mkdir", "fifo", "moved", "tcp-connect", "tcp-bind", "pidfd", "nested-mkdir", "ledger", "ledger-alias"} {
		got := s.out("rc-" + name)
		if got != "EACCES" && got != "EPERM" {
			t.Errorf("%s: %q, expected a refusal\n%s", name, got, out)
		}
	}
	if got := s.out("rc-gnupg_S.gpg-agent.ssh"); got != "ok" {
		t.Errorf("SSH exception: %q\n%s", got, out)
	}
	if got := s.out("child"); got != "0" {
		t.Errorf("exec child escaped: %q\n%s", got, out)
	}
	if got := s.out("pty"); got != "ok" {
		t.Errorf("run's pty: %q\n%s", got, out)
	}
	select {
	case err := <-moved:
		if err != nil {
			t.Fatal(err)
		}
	default:
		t.Fatal("outside move did not complete")
	}
	dirs := runDirs(t, f.root)
	if len(dirs) != 1 {
		t.Fatal(dirs)
	}
	evs := events(t, dirs[0])
	counts := map[string]int{}
	foreignRecorded := false
	for _, e := range evs {
		if e.Verdict == record.VerdictRefused {
			counts[e.Rule]++
			var p record.FSPayload
			if e.Kind == record.KindFS && json.Unmarshal(e.Payload, &p) == nil && p.Path == foreignPTY {
				foreignRecorded = true
				if e.Rule != agent.BuiltinOtherTTY {
					t.Errorf("foreign terminal refusal named %s", e.Rule)
				}
			}
		}
	}
	if tier != "landlock" && !foreignRecorded {
		t.Error("kernel-only foreign terminal refusal has no built-in event")
	}
	if counts[agent.BuiltinHostIPC] < 5 || counts[agent.BuiltinTegoSurface] < 1 || counts[agent.BuiltinOtherTTY] < 1 {
		t.Fatalf("missing built-in rules in ledger: %v\n%s", counts, out)
	}
	eventsCmd := s.tego(t, "events", filepath.Base(dirs[0]), "--json")
	body, err := eventsCmd.CombinedOutput()
	if err != nil || !strings.Contains(string(body), agent.BuiltinHostIPC) || !strings.Contains(string(body), agent.BuiltinTegoSurface) {
		t.Fatalf("events lost rule ids: %v\n%s", err, body)
	}
}

// TestIntegrationBuiltinControllingTTY holds G6: reopening the inherited
// controlling slave by name retains READ/WRITE and IOCTL_DEV in both domains.
func TestIntegrationBuiltinControllingTTY(t *testing.T) {
	builtinControllingTTY(t, tegoBinary(t), "landlock")
}

func builtinControllingTTY(t *testing.T, bin, tier string) {
	t.Helper()
	master, err := unix.Open("/dev/ptmx", unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(master) //nolint:errcheck // test terminal
	if err := unix.IoctlSetPointerInt(master, unix.TIOCSPTLCK, 0); err != nil {
		t.Fatal(err)
	}
	slave, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(master), unix.TIOCGPTPEER, unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC)
	if errno != 0 {
		t.Fatal(errno)
	}
	fslave := os.NewFile(slave, "controlling-tty")
	if index, err := unix.IoctlGetInt(master, unix.TIOCGPTN); err == nil {
		agentOwns(t, fmt.Sprintf("/dev/pts/%d", index))
	}
	defer fslave.Close() //nolint:errcheck // test terminal
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Fatal(err)
	}
	contract := fmt.Sprintf("version: 0\nname: ibuiltintty\ncommand: [%q]\ntier: landlock\nfs:\n  write: [\"./out/\", \"/dev/pts/\"]\nrecord: full\n", python)
	f := newFixture(t, contract)
	if tier != "landlock" {
		// The plain test binary also drives the prebuilt tagged CLI in KVM.
		// Pin the executable contract after the fixture's local compilation.
		contract = strings.Replace(contract, "tier: landlock", "tier: "+tier, 1)
		if err := os.WriteFile(filepath.Join(f.dir, "agent.yaml"), []byte(contract), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	s := &askReadScene{bin: bin, f: f}
	s.env = isolatedEnv(t, f)
	script := `import os, termios
p=os.ttyname(0)
fd=os.open(p,os.O_RDWR)
a=termios.tcgetattr(fd)
termios.tcsetattr(fd,termios.TCSANOW,a)
os.close(fd)
open('out/tty-reopen','w').write('ok')
`
	run := s.tego(t, "run", filepath.Join(f.dir, "agent.yaml"), "--", python, "-c", script)
	run.Dir = f.dir
	run.Stdin = fslave
	run.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	if out, err := run.CombinedOutput(); err != nil {
		t.Fatalf("controlling terminal reopen: %v\n%s", err, out)
	}
	if s.out("tty-reopen") != "ok" {
		t.Fatal("agent did not reopen and set modes on its controlling terminal")
	}
}
