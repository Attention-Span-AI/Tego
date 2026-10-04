// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/internal/runtime/dnsbroker"
	cgroupenforce "github.com/attention-span-ai/tego/internal/runtime/enforce/cgroup"
	"github.com/attention-span-ai/tego/internal/runtime/launch"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/record"
	"golang.org/x/sys/unix"
)

func dnsReapFixture(t *testing.T) (*dnsDirectory, reapSpec, *net.UnixListener) {
	t.Helper()
	d, err := newDNSDirectory()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	l, err := net.ListenUnix("unixpacket", &net.UnixAddr{Name: filepath.Join(d.path, dnsbroker.SocketName), Net: "unixpacket"})
	if err != nil {
		t.Fatal(err)
	}
	l.SetUnlinkOnClose(false)
	t.Cleanup(func() { l.Close(); os.Remove(filepath.Join(d.path, dnsbroker.SocketName)); _ = d.Close() })
	if err = d.captureSocket(); err != nil {
		t.Fatal(err)
	}
	spec := reapTestSpec(t, t.TempDir(), t.TempDir())
	spec.DNSName, spec.DNSDev, spec.DNSIno = d.name, d.socketDev, d.socketIno
	return d, spec, l
}

func TestDNSReaperMetadataDescriptorsAndStartupRollback(t *testing.T) {
	d, spec, _ := dnsReapFixture(t)
	parsed, err := parseReapSpec(spec.args())
	if err != nil || parsed != spec {
		t.Fatalf("roundtrip %+v %v", parsed, err)
	}
	for _, name := range []string{"", "../tego-dns-123", "tego-dns-123/child", "foreign", "tego-dns-x", "tego-dns-12345678901"} {
		args := spec.args()
		args[13] = name
		if _, err = parseReapSpec(args); err == nil {
			t.Fatalf("bad cleanup name %q accepted", name)
		}
	}
	w := openRun(t, filepath.Dir(spec.Dir), spec.ID)
	defer w.Abandon()
	ledgerDir, err := w.OpenDirPath()
	if err != nil {
		t.Fatal(err)
	}
	defer ledgerDir.Close()
	pidfd := deadLauncherPidfd(t)
	stray, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer stray.Close()
	handoff, handoffW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer handoff.Close()
	defer handoffW.Close()
	dns := &reapDNS{dir: d, handoff: handoff}
	cmd := reaperCommand(os.Args[0], spec, pidfd, ledgerDir, nil, dns)
	if len(cmd.ExtraFiles) != 5 || cmd.ExtraFiles[2] != d.file || cmd.ExtraFiles[3] != d.parent || cmd.ExtraFiles[4] != handoff {
		t.Fatal("DNS descriptor ownership drift")
	}
	// The test binary runs ReapMain itself (reapMainHelper), with a stray descriptor right above the handoff: its
	// start-up sweep closes the stray and keeps 5-7, which it then owns as their kinds; at its hold, the launcher
	// gone and the handoff read, it holds the run directory and the two DNS directories.
	cmd.ExtraFiles = append(cmd.ExtraFiles, stray)
	rm := runReapMain(t, cmd, "run")
	if rm.code != 0 || !rm.hold {
		t.Fatalf("DNS reaper exit %d, hold %t, stderr %q: want its hold", rm.code, rm.hold, rm.stderr)
	}
	if got := rm.numbers(); !slices.Equal(got, []int{0, 1, 2, reapDirFD, reapDNSDirFD, reapDNSParentFD}) {
		t.Fatalf("DNS reaper holds %v (%v), want 0-2, the run directory and the DNS directory and its parent", got, rm.fds)
	}
	if rm.fds[reapDNSDirFD] != d.path || rm.fds[reapDNSParentFD] != filepath.Dir(d.path) {
		t.Fatalf("DNS reaper holds %q and %q, want %s and its parent", rm.fds[reapDNSDirFD], rm.fds[reapDNSParentFD], d.path)
	}
	if err = startReaperProcess("/not-executed", spec, w, &reapDNS{dir: d}); err == nil {
		t.Fatal("DNS reaper started without its target handoff")
	}
	beforeFail := reapStartFails
	reapStartFails = func() bool { return true }
	t.Cleanup(func() { reapStartFails = beforeFail })
	if err = startReaperProcess("/not-executed", spec, w, dns); err == nil {
		t.Fatal("startup failure hidden")
	}
	r := &runner{deps: Deps{Launcher: &launch.Launcher{Exe: "/not-executed"}}}
	if err = r.startDNSReaper(); err != nil {
		t.Fatalf("a run without a DNS broker started a DNS reaper: %v", err)
	}
	if err = r.startReaper(); err != nil {
		t.Fatalf("ordinary tier without kernel state started a reaper: %v", err)
	}
	r.dnsDirectory = d
	if err = r.startDNSReaper(); err == nil || !strings.Contains(err.Error(), "DNS endpoint cleanup") || r.reapHandoff != nil {
		t.Fatalf("DNS-only run failed to require its reaper: %v", err)
	}
	for _, f := range []*os.File{d.file, d.parent} {
		if _, err = f.Stat(); err != nil {
			t.Fatalf("borrowed descriptor closed on rollback: %v", err)
		}
	}
	if err = cleanupReapDNS(spec, int(d.file.Fd()), int(d.parent.Fd())); err != nil {
		t.Fatal(err)
	}
	if err = cleanupReapDNS(spec, int(d.file.Fd()), int(d.parent.Fd())); err != nil {
		t.Fatalf("duplicate cleanup: %v", err)
	}
}

// The owned DNS endpoint is never without a reaper: it is bound before Prepare, which at tiers 2 and 3 loads and
// attaches for up to a second, and a launcher SIGKILLed or OOM-killed there left /tmp/tego-dns-N and its socket
// with nothing to remove them, since the reaper only started after Prepare. A reaper that cannot
// start now fails the run before Prepare runs at all.
func TestDNSReaperExistsBeforePrepare(t *testing.T) {
	m, rt, root := startupFixture(t)
	m.Resolver.Value = config.ResolverMode{Servers: []netip.AddrPort{netip.MustParseAddrPort("127.0.0.1:53")}}
	cache := 2
	rt.Contract.Net = &agent.NetSection{DNS: &agent.DNSPolicy{Mode: "broker", Allow: []string{"allowed.example"}, Types: []string{"A"}, Cache: &cache}}
	var err error
	if rt.DNS, rt.DNSQueries, err = agent.CompileDNSPolicy(rt.Contract); err != nil {
		t.Fatal(err)
	}
	before := reapStartFails
	reapStartFails = func() bool { return true }
	t.Cleanup(func() { reapStartFails = before })
	b := &fakeBackend{}
	_, err = Run(context.Background(), rt, []string{"/bin/true"}, Deps{
		Config: m, Cgroups: &fakeCgroups{root: t.TempDir()}, Enforce: b, Cwd: root,
		Launcher: &launch.Launcher{Exe: filepath.Join(root, "must-never-start")},
	})
	if err == nil || !strings.Contains(err.Error(), "DNS endpoint cleanup") {
		t.Fatalf("a DNS run without its cleanup reaper did not fail: %v", err)
	}
	if b.handle != nil {
		t.Fatal("Prepare ran while the owned DNS endpoint had no reaper")
	}
}

// The early reaper learns the tier's target only from what the launcher wrote before dying: a whole handoff is
// the target, none (an empty pipe whose writer is gone or still open) is no target, and a malformed one is an
// error, never a guessed target.
func TestDNSReaperTargetHandoff(t *testing.T) {
	pipe := func(t *testing.T) (*os.File, *os.File) {
		rd, wr, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { rd.Close(); wr.Close() })
		return rd, wr
	}
	want := cgroupenforce.ReapTarget{Hash: strings.Repeat("a", 64), BPFFS: "/sys/fs/bpf", StateDir: "/run/tego",
		Linger: 30 * time.Second, Slot: 7, PlaneMode: record.DecisionPlaneLSM}
	rd, wr := pipe(t)
	if err := handOffReapTarget(wr, want); err != nil {
		t.Fatal(err)
	}
	wr.Close()
	if got, ok, err := readReapTarget(int(rd.Fd())); err != nil || !ok || got != want {
		t.Fatalf("handed-over target %+v %t %v, want %+v", got, ok, err, want)
	}
	rd, wr = pipe(t)
	if _, ok, err := readReapTarget(int(rd.Fd())); err != nil || ok {
		t.Fatalf("an open, empty handoff read as a target: %t %v", ok, err)
	}
	wr.Close()
	if _, ok, err := readReapTarget(int(rd.Fd())); err != nil || ok {
		t.Fatalf("a closed, empty handoff read as a target: %t %v", ok, err)
	}
	rd, wr = pipe(t)
	if _, err := wr.Write([]byte("not\x00a target")); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := readReapTarget(int(rd.Fd())); err == nil || ok {
		t.Fatalf("a malformed handoff was accepted: %t %v", ok, err)
	}
}

func TestDNSReaperPreservesForeignSocketAndDirectory(t *testing.T) {
	for _, replace := range []string{"socket", "directory"} {
		t.Run(replace, func(t *testing.T) {
			d, spec, l := dnsReapFixture(t)
			_ = l.Close()
			if replace == "socket" {
				if err := os.Remove(filepath.Join(d.path, dnsbroker.SocketName)); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(d.path, dnsbroker.SocketName), []byte("foreign"), 0600); err != nil {
					t.Fatal(err)
				}
			} else {
				moved := d.path + "-held"
				if err := os.Rename(d.path, moved); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { os.Remove(filepath.Join(moved, dnsbroker.SocketName)); os.Remove(moved) })
				if err := os.Mkdir(d.path, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(d.path, "keep"), []byte("foreign"), 0600); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { os.Remove(filepath.Join(d.path, "keep")); os.Remove(d.path) })
			}
			if err := cleanupReapDNS(spec, int(d.file.Fd()), int(d.parent.Fd())); err == nil {
				t.Fatal("foreign identity removed")
			}
			name := filepath.Join(d.path, dnsbroker.SocketName)
			if replace == "directory" {
				name = filepath.Join(d.path, "keep")
			}
			if b, err := os.ReadFile(name); err != nil || string(b) != "foreign" {
				t.Fatalf("foreign evidence changed %q %v", b, err)
			}
		})
	}
}

func TestDNSReaperWaitsForActualLauncherDeathBeforeCleanup(t *testing.T) {
	d, spec, _ := dnsReapFixture(t)
	child := exec.Command(os.Args[0], "-test.run=^TestDNSReaperWaitHelper$")
	child.Env = append(os.Environ(), "TEGO_DNS_REAP_WAIT=1")
	var err error
	gate, err := child.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err = child.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { gate.Close(); child.Process.Kill(); child.Wait() }()
	pfd, err := unix.PidfdOpen(child.Process.Pid, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(pfd)
	done := make(chan error, 1)
	go func() {
		if err := waitPidfd(pfd); err != nil {
			done <- err
			return
		}
		done <- cleanupReapDNS(spec, int(d.file.Fd()), int(d.parent.Fd()))
	}()
	if _, err = os.Stat(filepath.Join(d.path, dnsbroker.SocketName)); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		t.Fatalf("live launcher cleaned: %v", err)
	default:
	}
	if err = child.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("dead launcher cleanup stuck")
	}
	if err = child.Wait(); err == nil {
		t.Fatal("launcher was not SIGKILLed")
	}
	if _, err = os.Stat(d.path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("owned directory remains %v", err)
	}
}

func TestDNSReaperWaitHelper(t *testing.T) {
	if os.Getenv("TEGO_DNS_REAP_WAIT") != "1" {
		return
	}
	var b [1]byte
	_, _ = os.Stdin.Read(b[:])
}

// TestReapFDsCleanupDNSLendsTheHeldDirectories is ReapMain's DNS cleanup through the owners it inherited (ADR 0023
// C9): reapFDs.cleanupDNS lends the held socket directory and its /tmp parent to cleanupReapDNS, which removes the
// endpoint; with either owner closed it is sys.ErrClosed and removes nothing.
func TestReapFDsCleanupDNSLendsTheHeldDirectories(t *testing.T) {
	d, spec, l := dnsReapFixture(t)
	_ = l.Close()
	own := func(f *os.File) *sys.FD {
		t.Helper()
		fd, err := sys.DupFile(f, 3)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = fd.Close() })
		return fd
	}
	for _, which := range []string{"dns-dir", "dns-parent"} {
		f := reapFDs{dnsDir: own(d.file), dnsParent: own(d.parent)}
		closed := f.dnsDir
		if which == "dns-parent" {
			closed = f.dnsParent
		}
		_ = closed.Close()
		if err := f.cleanupDNS(spec); !errors.Is(err, sys.ErrClosed) {
			t.Fatalf("cleanupDNS with %s closed = %v, want sys.ErrClosed", which, err)
		}
		if _, err := os.Lstat(d.path); err != nil {
			t.Fatalf("cleanupDNS with %s closed removed the endpoint: %v", which, err)
		}
	}
	f := reapFDs{dnsDir: own(d.file), dnsParent: own(d.parent)}
	if err := f.cleanupDNS(spec); err != nil {
		t.Fatalf("cleanupDNS: %v", err)
	}
	if _, err := os.Lstat(d.path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("cleanupDNS left %s: %v", d.path, err)
	}
}
