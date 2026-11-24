// SPDX-License-Identifier: Apache-2.0

//go:build integration

package runtime

import (
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/tomoyo"
	"github.com/attention-span-ai/tego/internal/testutil"
)

// SEC08b's guest halves that need no domain of their own (ADR 0041): an unprivileged process moves TOMOYO's update
// counter (C75), and a registered manager flips a profile's mode while the proof reads it. Each runs in its own fresh boot
// of the dedicated TOMOYO guest (test/vm/held-label-tests.sh), TEGO_VM_TOMOYO_HALF naming it.

// The test binary is also the process the initializer half starts, and the program it execs as /sbin/modprobe.
func init() {
	if len(os.Args) < 2 {
		return
	}
	switch os.Args[1] {
	case "--held-label-modprobe":
		os.Exit(0)
	case "--held-label-initializer":
		os.Exit(tomoyoInitializerChild())
	}
}

// tomoyoInitializerChild runs as root of a user and mount namespace its parent (an unprivileged user) made with
// unshare. It does what switch_root does: puts a tmpfs with a real /sbin/modprobe in a directory, moves that mount onto the
// namespace's root and chroots into it, so the namespace's root is a filesystem of its own and /sbin there is a real
// directory. TOMOYO names a file by its absolute path from the root of the mount namespace, chroot ignored, so the exec is
// of "/sbin/modprobe"; a host whose /sbin is a link into /usr never runs that name. (A tmpfs mounted on "/" would not do:
// the process's root stays the mount it covers, and pivot_root refuses an initramfs root.)
func tomoyoInitializerChild() int {
	fail := func(step string, err error) int {
		fmt.Printf("INITIALIZER-STEP %s: %v\n", step, err)
		return 2
	}
	body, err := os.ReadFile(os.Args[0])
	if err != nil {
		return fail("read self", err)
	}
	root, err := os.MkdirTemp("/tmp", "nr-")
	if err != nil {
		return fail("mkdir the new root", err)
	}
	if err := unix.Mount("tmpfs", root, "tmpfs", 0, "mode=0755"); err != nil {
		return fail("mount tmpfs", err)
	}
	if err := os.Mkdir(filepath.Join(root, "sbin"), 0o755); err != nil {
		return fail("mkdir sbin", err)
	}
	if err := os.WriteFile(filepath.Join(root, "sbin", "modprobe"), body, 0o755); err != nil {
		return fail("write sbin/modprobe", err)
	}
	if err := unix.Chdir(root); err != nil {
		return fail("chdir the new root", err)
	}
	if err := unix.Mount(".", "/", "", unix.MS_MOVE, ""); err != nil {
		return fail("move the new root onto /", err)
	}
	if err := unix.Chroot("."); err != nil {
		return fail("chroot", err)
	}
	if err := unix.Chdir("/"); err != nil {
		return fail("chdir /", err)
	}
	fmt.Println("INITIALIZER-EXEC")
	err = syscall.Exec("/sbin/modprobe", []string{"/sbin/modprobe", "--held-label-modprobe"}, nil)
	return fail("exec /sbin/modprobe", err)
}

func tomoyoUpdateLine(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("/sys/kernel/security/tomoyo/stat")
	if err != nil {
		t.Fatal(err)
	}
	line, _, _ := strings.Cut(string(b), "\n")
	return line
}

// tomoyoInitializerCounter is C75's mechanism, run for real: an unprivileged user, in a user and mount namespace of its
// own with a real /sbin, starts a program named /sbin/modprobe, TOMOYO's built-in initializer rules make a domain, and the
// update counter moves with no policy written and none activated (no loader runs in this boot). The root tiers' launcher
// reads the profile and is admitted; tier landlock's launcher, the invoking user, cannot read it and keeps the refusal,
// now with the sentence that says why.
func tomoyoInitializerCounter(t *testing.T, c *crossOwner, actor string) {
	before := tomoyoUpdateLine(t)
	if !strings.HasPrefix(before+"\n", "Policy update:                                 0\n") {
		t.Fatalf("not a fresh counter: %q", before)
	}
	if _, err := os.Stat("/vm/tomoyo-loader"); !os.IsNotExist(err) {
		t.Fatalf("loader present: %v", err)
	}
	unshare, err := exec.LookPath("unshare")
	if err != nil {
		t.Fatalf("the guest has no unshare: %v", err)
	}
	cmd := exec.Command(unshare, "-Urm", "--", actor, "--held-label-initializer")
	cmd.Dir = "/"
	cmd.Env = []string{"PATH=" + os.Getenv("PATH")}
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(c.uid), Gid: uint32(c.gid), Groups: []uint32{}}}
	out, err := cmd.CombinedOutput()
	t.Logf("unprivileged uid %d, unshare -Urm, exec /sbin/modprobe: %v\n%s", c.uid, err, out)
	after := tomoyoUpdateLine(t)
	t.Logf("update line: before %q; after %q", before, after)
	if err != nil || !strings.Contains(string(out), "INITIALIZER-EXEC") {
		t.Fatalf("the unprivileged process did not reach its exec of /sbin/modprobe (no user namespace here?): %v\n%s", err, out)
	}
	if after == before {
		t.Fatalf("an unprivileged exec of /sbin/modprobe in a mount namespace of its own did not move the counter; C75's mechanism is not reproduced")
	}
	domain, err := os.ReadFile("/sys/kernel/security/tomoyo/self_domain")
	if err != nil || string(domain) != "<kernel>" {
		t.Fatalf("the checking thread's domain is %q: %v", domain, err)
	}
	for _, tier := range []string{"landlock", "cgroup", "bpflsm"} {
		t.Run("initializer_counter/"+tier, func(t *testing.T) {
			testutil.RequireTier(t, c.doctorRequire(t, tier), tier)
			asUser := tier == "landlock"
			cmd, path := tomoyoRunAs(t, c, actor, tier, "counter", "--held-label-agent", asUser)
			if err := cmd.Run(); err != nil {
				t.Fatalf("counter: %v\n%s", err, output(cmd))
			}
			tomoyoResult(t, c, cmd, path, asUser)
		})
	}
}

// flipWrite is one write of the profile: its mode, and the monotonic time it started and returned.
type flipWrite struct {
	enforcing  bool
	start, end time.Duration
}

// flipCheck is one run of the proof: when it started and returned, and whether it admitted.
type flipCheck struct {
	start, end time.Duration
	admitted   bool
	err        error
}

// tomoyoProfileFlipRace is the proof under a changing profile. The loader registers this test binary as a TOMOYO manager,
// the only kind of writer after activation, and the test writes an unused profile's file category permissive and
// enforcing in turn, a few hundred microseconds apart, while four goroutines run the product's own check (tomoyo.CheckVia)
// as fast as they can. Each write and each check is timed on one monotonic clock. A write's mode holds from when it
// returned to when the next one started; a check that began and ended inside one such window saw the profile unchanged,
// so it must admit in a permissive window and must refuse in an enforcing one. Checks that overlap a write may go either
// way (the kernel publishes a mode before it counts it); they are counted, not judged. The profile is one no domain uses,
// so nothing is denied and the guest keeps running; the proof refuses any enforcing mode in any profile. What this tests
// is the proof function and its bracket, not a held open through a run: a held open's check is this same call.
func tomoyoProfileFlipRace(t *testing.T) {
	if err := os.WriteFile("/vm/tomoyo-manager", []byte("1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename("/vm/tomoyo-loader.fixture", "/vm/tomoyo-loader"); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("/vm/tomoyo-trigger").CombinedOutput(); err != nil {
		t.Fatalf("activate TOMOYO: %v\n%s", err, out)
	}
	managers, err := os.ReadFile("/sys/kernel/security/tomoyo/manager")
	if err != nil || !strings.Contains(string(managers), "/vm/runtime.test") {
		t.Fatalf("the loader did not register the test binary as a manager (%v):\n%s", err, managers)
	}
	const profile = "/sys/kernel/security/tomoyo/profile"
	write := func(enforcing bool) error {
		mode := "permissive"
		if enforcing {
			mode = "enforcing"
		}
		f, err := os.OpenFile(profile, os.O_WRONLY, 0)
		if err != nil {
			return err
		}
		_, werr := f.WriteString("7-CONFIG::file={ mode=" + mode + " }\n")
		if cerr := f.Close(); werr == nil {
			werr = cerr
		}
		return werr
	}
	// Controls: the profile reads, the proof admits it permissive and refuses it enforcing, before any race.
	if err := write(false); err != nil {
		t.Fatalf("writing the profile as a registered manager: %v", err)
	}
	if via, err := tomoyo.CheckVia(tomoyo.ReadFile); err != nil || !via {
		t.Fatalf("a permissive profile: admitted via profile %v, %v", via, err)
	}
	if err := write(true); err != nil {
		t.Fatal(err)
	}
	if _, err := tomoyo.CheckVia(tomoyo.ReadFile); err == nil || !strings.Contains(err.Error(), "enforces") {
		t.Fatalf("an enforcing profile: %v, want the refusal naming it", err)
	}
	if err := write(false); err != nil {
		t.Fatal(err)
	}
	t0 := time.Now()
	now := func() time.Duration { return time.Since(t0) }
	const writes = 1500
	var recorded []flipWrite
	stop := make(chan struct{})
	var wg sync.WaitGroup
	const checkers = 4
	checks := make([][]flipCheck, checkers)
	for i := 0; i < checkers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				s := now()
				_, err := tomoyo.CheckVia(tomoyo.ReadFile)
				checks[i] = append(checks[i], flipCheck{start: s, end: now(), admitted: err == nil, err: err})
			}
		}(i)
	}
	var writeErr error
	for i := 0; i < writes && writeErr == nil; i++ {
		enforcing := i%2 == 0
		s := now()
		writeErr = write(enforcing)
		e := now()
		recorded = append(recorded, flipWrite{enforcing: enforcing, start: s, end: e})
		time.Sleep(time.Duration(50+(i*37)%1400) * time.Microsecond)
	}
	end := now()
	close(stop)
	wg.Wait()
	if writeErr != nil {
		t.Fatalf("a profile write failed: %v", writeErr)
	}
	// The window each write's mode holds: from its return to the next write's start (the last, to the end of the loop).
	type window struct {
		from, to  time.Duration
		enforcing bool
	}
	var windows []window
	for i, w := range recorded {
		to := end
		if i+1 < len(recorded) {
			to = recorded[i+1].start
		}
		windows = append(windows, window{from: w.end, to: to, enforcing: w.enforcing})
	}
	var inEnfAdmit, inEnfRefuse, inPermAdmit, inPermRefuse, overlap, overlapAdmit int
	var violations []string
	for _, cs := range checks {
		for _, c := range cs {
			// The window with the last return before this check began.
			i := sort.Search(len(windows), func(k int) bool { return windows[k].from > c.start }) - 1
			if i < 0 || c.end >= windows[i].to {
				overlap++
				if c.admitted {
					overlapAdmit++
				}
				continue
			}
			w := windows[i]
			switch {
			case w.enforcing && c.admitted:
				inEnfAdmit++
				if len(violations) < 5 {
					violations = append(violations, fmt.Sprintf("admitted at %v..%v inside the enforcing window %v..%v", c.start, c.end, w.from, w.to))
				}
			case w.enforcing:
				inEnfRefuse++
			case c.admitted:
				inPermAdmit++
			default:
				inPermRefuse++
				if len(violations) < 5 {
					violations = append(violations, fmt.Sprintf("refused (%v) at %v..%v inside the permissive window %v..%v", c.err, c.start, c.end, w.from, w.to))
				}
			}
		}
	}
	total := 0
	for _, cs := range checks {
		total += len(cs)
	}
	t.Logf("%d profile writes in %v, %d checks: inside an enforcing window %d refused and %d admitted; inside a permissive window %d admitted and %d refused; overlapping a write %d (%d admitted)",
		len(recorded), end, total, inEnfRefuse, inEnfAdmit, inPermAdmit, inPermRefuse, overlap, overlapAdmit)
	for _, v := range violations {
		t.Error(v)
	}
	if inEnfRefuse < 50 || inPermAdmit < 50 {
		t.Fatalf("too few checks inside a window to judge (%d in enforcing windows, %d in permissive ones); the race was not exercised", inEnfRefuse, inPermAdmit)
	}
	// The profile ends as the loop left it: permissive, so the last proof admits.
	if via, err := tomoyo.CheckVia(tomoyo.ReadFile); err != nil || !via {
		t.Errorf("after the loop: admitted via profile %v, %v", via, err)
	}
}

// TestIntegrationTOMOYOProfileProofDifferential holds SEC08b's proof to what the kernel enforces, which is the way it could
// be wrong: some kernel decides a denial from something `profile` does not print (ADR 0041). In the dedicated TOMOYO guest
// (TEGO_VM_TOMOYO_HALF=differential, a fresh boot with the test binary registered as a manager) a program, busybox's cat,
// runs in a domain of its own that uses profile 42, and the test writes random states of that profile, in the kernel's
// namespace and a second one, the default mode, the file category and its open, getattr and execute operations each disabled,
// learning, permissive, enforcing or left to the level above, with a second profile and a second namespace's profile
// drawn the same way. For each state it runs the product's own check (tomoyo.CheckVia) and then has the program open a
// file the domain has no ACL for. The one failure is a state the proof admitted in which the kernel denied the open.
// Where the proof refused and the open worked (an enforcing mode that does not apply to this open, or one in a profile no
// domain uses) is counted and logged, not failed: the proof refuses any enforcing mode anywhere. The run also fails when it
// is vacuous: it must see denials, and admissions with the open allowed, in numbers.
func TestIntegrationTOMOYOProfileProofDifferential(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root only: dedicated TOMOYO policy guest")
	}
	cmdline, err := os.ReadFile("/proc/cmdline")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat("/.vm/nonce"); err != nil || !strings.Contains(string(cmdline), "TOMOYO_trigger=/vm/tomoyo-trigger") || os.Getenv("TEGO_VM_TOMOYO_HALF") != "differential" {
		t.Skip("needs the dedicated TOMOYO policy guest, booted for the differential")
	}
	if err := os.WriteFile("/vm/tomoyo-manager", []byte("1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename("/vm/tomoyo-loader.fixture", "/vm/tomoyo-loader"); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("/vm/tomoyo-trigger").CombinedOutput(); err != nil {
		t.Fatalf("activate TOMOYO: %v\n%s", err, out)
	}
	const tdir = "/sys/kernel/security/tomoyo/"
	put := func(file, text string) error {
		f, err := os.OpenFile(tdir+file, os.O_WRONLY, 0)
		if err != nil {
			return err
		}
		_, werr := f.WriteString(text)
		if cerr := f.Close(); werr == nil {
			werr = cerr
		}
		return werr
	}
	// The program: a static busybox of its own path, so its domain is its own and no other process shares it.
	probe := "/vm/diff-probe"
	body, err := os.ReadFile("/usr/lib/tego-vm/busybox")
	if err != nil {
		t.Fatalf("the guest's busybox: %v", err)
	}
	if err := os.WriteFile(probe, body, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll("/vm/diff", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("/vm/diff/allowed", []byte("allowed\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Profile 42 exists before a domain may use it.
	if err := put("profile", "42-COMMENT=differential\n42-CONFIG={ mode=disabled }\n"); err != nil {
		t.Fatalf("define profile 42: %v", err)
	}
	if err := put("domain_policy", "<kernel> "+probe+"\nuse_profile 42\nfile read /vm/diff/allowed\n"); err != nil {
		t.Fatalf("define the probe's domain: %v", err)
	}
	if dp, err := os.ReadFile(tdir + "domain_policy"); err != nil || !strings.Contains(string(dp), "<kernel> "+probe+"\nuse_profile 42\n") {
		t.Fatalf("the probe's domain does not use profile 42 (%v):\n%s", err, dp)
	}
	open := func(name string) (denied bool, out string) {
		// busybox picks its applet from argv[0] when that is not "busybox"; the domain is named by the program's path.
		cmd := exec.Command(probe, "cat", name)
		cmd.Args[0] = "busybox"
		cmd.Env = []string{"PATH=/usr/bin:/bin"}
		b, err := cmd.CombinedOutput()
		out = strings.TrimSpace(string(b))
		if err == nil {
			return false, out
		}
		// TOMOYO answers a denial -EPERM (security/tomoyo: tomoyo_path_permission returns -EPERM), not -EACCES.
		if strings.Contains(out, "Operation not permitted") || strings.Contains(out, "Permission denied") {
			return true, out
		}
		t.Fatalf("the probe failed for a reason that is no denial: %v: %q", err, out)
		return false, out
	}
	// Controls: the probe's allowed file reads whatever the profile says, and a plain profile lets a file with no ACL open.
	if denied, out := open("/vm/diff/allowed"); denied || out != "allowed" {
		t.Fatalf("the probe cannot read its allowed file: denied %v %q", denied, out)
	}
	rng := rand.New(rand.NewSource(20261120))
	pick := func(withDefault bool) string {
		r := rng.Intn(100)
		switch {
		case r < 18:
			return "enforcing"
		case r < 36:
			return "permissive"
		case r < 54:
			return "learning"
		case r < 72 || !withDefault:
			return "disabled"
		}
		return "use_default"
	}
	line := func(prefix, key, mode string) string {
		if mode == "use_default" {
			return prefix + key + "=use_default\n"
		}
		return prefix + key + "={ mode=" + mode + " }\n"
	}
	const states = 400
	var admitted, admittedAllowed, refused, refusedAllowed, denials int
	var violations []string
	seen := map[string]int{}
	for i := 0; i < states; i++ {
		// TOMOYO's operation for opening a file is "file::open" (read and write opens are its path ACLs); the others are
		// operations this probe never makes, drawn all the same, since the proof refuses an enforcing mode anywhere.
		def, file, openMode, getattr, execute := pick(false), pick(true), pick(true), pick(true), pick(true)
		state := line("", "CONFIG", def) + line("", "CONFIG::file", file) + line("", "CONFIG::file::open", openMode) +
			line("", "CONFIG::file::getattr", getattr) + line("", "CONFIG::file::execute", execute)
		var text strings.Builder
		for _, l := range strings.Split(strings.TrimSuffix(state, "\n"), "\n") {
			text.WriteString("42-" + l + "\n")
		}
		// A profile no domain uses, and a second namespace's, in whatever modes: only the proof's refusal may follow.
		decoy := pick(false)
		text.WriteString("43-CONFIG={ mode=" + decoy + " }\n")
		other := pick(false)
		text.WriteString("<ns1> 42-CONFIG={ mode=" + other + " }\n")
		for _, l := range strings.Split(strings.TrimSuffix(text.String(), "\n"), "\n") {
			if err := put("profile", l+"\n"); err != nil {
				t.Fatalf("state %d: writing %q: %v", i, l, err)
			}
		}
		_, perr := tomoyo.CheckVia(tomoyo.ReadFile)
		fresh := fmt.Sprintf("/vm/diff/f%d", i)
		if err := os.WriteFile(fresh, []byte("x\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		denied, out := open(fresh)
		// What TOMOYO's own precedence says (operation, then category, then the profile's default), as a cross-check of
		// this test's reading of the kernel: logged on a disagreement, never failed on.
		effective := def
		if file != "use_default" {
			effective = file
		}
		if openMode != "use_default" {
			effective = openMode
		}
		if want := effective == "enforcing"; want != denied {
			seen["model disagrees with the kernel"]++
			if seen["model disagrees with the kernel"] <= 5 {
				t.Logf("state %d: the precedence model says denied=%v, the kernel %v (default %s, file %s, open %s): %q", i, want, denied, def, file, openMode, out)
			}
		}
		if denied {
			denials++
		}
		if perr == nil {
			admitted++
			if denied {
				violations = append(violations, fmt.Sprintf("state %d: the proof ADMITTED and the kernel DENIED: default %s, file %s, open %s, getattr %s, execute %s, decoy 43 %s, ns1 %s: %q", i, def, file, openMode, getattr, execute, decoy, other, out))
			} else {
				admittedAllowed++
			}
		} else {
			refused++
			if !denied {
				refusedAllowed++
			}
		}
	}
	t.Logf("%d states: the proof admitted %d (the open worked in %d) and refused %d (the open still worked in %d); the kernel denied %d; seen %v", states, admitted, admittedAllowed, refused, refusedAllowed, denials, seen)
	for _, v := range violations {
		t.Error(v)
	}
	if denials < 40 || admittedAllowed < 40 {
		t.Fatalf("too few denials (%d) or admissions with the open allowed (%d) to say anything", denials, admittedAllowed)
	}
}
