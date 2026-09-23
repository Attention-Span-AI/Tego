// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestDelegatedSubtree(t *testing.T) {
	tests := []struct {
		name string
		in   string
		uid  int
		want string
	}{
		{"inside user service", "0::/user.slice/user-1000.slice/user@1000.service/app.slice/x.scope\n", 1000,
			"/sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service"},
		{"exactly the service", "0::/user.slice/user-1000.slice/user@1000.service\n", 1000,
			"/sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service"},
		{"other uid", "0::/user.slice/user-1001.slice/user@1001.service/init.scope\n", 1000, ""},
		{"system service", "0::/system.slice/sshd.service\n", 1000, ""},
		{"v1 lines only", "12:pids:/user.slice\n1:name=systemd:/user@1000.service\n", 1000, ""},
		{"empty", "", 1000, ""},
		{"relative path", "0::user@1000.service\n", 1000, ""},
		{"prefix not a segment", "0::/user.slice/xuser@1000.service/a\n", 1000, ""},
		{"root cgroup", "0::/\n", 0, ""},
		{"earlier segment starts with the unit", "0::/a/user@1000.service.d/user@1000.service/x.scope\n", 1000,
			"/sys/fs/cgroup/a/user@1000.service.d/user@1000.service"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := delegatedSubtree([]byte(tc.in), tc.uid); got != tc.want {
				t.Fatalf("delegatedSubtree(%q, %d) = %q, want %q", tc.in, tc.uid, got, tc.want)
			}
		})
	}
}

func TestCanonicalSubtree(t *testing.T) {
	if got, want := canonicalSubtree(1000), "/sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service"; got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestCheckCgroup2RejectsTmp(t *testing.T) {
	if err := checkCgroup2(t.TempDir()); err == nil {
		t.Fatal("a temporary directory must not pass the cgroup2 magic check")
	}
}

// TestOwnCgroup covers the /proc/<pid>/cgroup parse delegatedSubtree rests on, including the
// namespace-relative ".." form cgroup_namespaces(7) documents, which must never be spliced onto
// the mount point (path.Join would silently clean it into a path outside the cgroup2 mount).
func TestOwnCgroup(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"absolute", "0::/user.slice/user-1000.slice/user@1000.service\n", "/user.slice/user-1000.slice/user@1000.service"},
		{"root", "0::/\n", "/"},
		{"v1 only", "12:pids:/user.slice\n", ""},
		{"relative", "0::user@1000.service\n", ""},
		{"escapes the namespace root", "0::/../sub2/user@1000.service\n", ""},
		{"escapes deeper", "0::/../../user.slice/user@1000.service\n", ""},
		{"nul", "0::/a\x00b\n", ""},
		{"empty", "", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := ownCgroup([]byte(tc.in)); got != tc.want {
				t.Fatalf("ownCgroup(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
	// The ".." form must not reach the splice either: without the refusal, path.Join cleans
	// "/../sub2" into a sibling of the mount point and names a directory outside it entirely.
	if got := delegatedSubtree([]byte("0::/../sub2/user@1000.service\n"), 1000); got != "" {
		t.Fatalf("delegatedSubtree escaped the mount: %q", got)
	}
}

func TestHasPID(t *testing.T) {
	data := []byte("14032\n876124\n")
	if !hasPID(data, 876124) || !hasPID(data, 14032) {
		t.Fatal("a listed pid must be found")
	}
	// Substring and prefix matches are not membership: 1403 is not 14032.
	if hasPID(data, 1403) || hasPID(data, 4032) || hasPID(data, 876) || hasPID(nil, 1) {
		t.Fatal("an unlisted pid must not be found")
	}
}

// TestDelegatedCandidateChecksMountAgreement is the cgroup-namespace case: /proc/<pid>/cgroup is
// relative to the reading process's cgroup namespace root (cgroup_namespaces(7)), so the path it
// names is only meaningful against a mount that agrees with it. A mount that does not agree holds a
// real, writable, *different* subtree at the same name, and Tego must not build run cgroups there.
func TestDelegatedCandidateChecksMountAgreement(t *testing.T) {
	const own = "/user.slice/user-1000.slice/user@1000.service/app.slice/x.scope"
	mount := t.TempDir()
	proc := []byte("0::" + own + "\n")
	want := filepath.Join(mount, "user.slice/user-1000.slice/user@1000.service")

	// The spliced path does not exist under this mount at all: the mount is someone else's tree.
	if got := delegatedCandidate(mount, proc, 1000, os.Getpid()); got != "" {
		t.Fatalf("candidate from a mount that does not hold the path: %q", got)
	}

	if err := os.MkdirAll(filepath.Join(mount, own), 0o755); err != nil {
		t.Fatal(err)
	}
	// The path exists and is writable, but its cgroup.procs does not list us: same name, different
	// tree. This is exactly the host-/sys/fs/cgroup-inside-a-private-cgroupns shape.
	procsPath := filepath.Join(mount, own, fileProcs)
	if err := os.WriteFile(procsPath, []byte("1\n2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := delegatedCandidate(mount, proc, 1000, os.Getpid()); got != "" {
		t.Fatalf("candidate from a mount whose cgroup.procs does not list us: %q", got)
	}

	// Agreement: our own pid is a member of the cgroup the path names, so the mount is the one
	// /proc/self/cgroup was written against and the delegated subtree is the right first candidate.
	if err := os.WriteFile(procsPath, []byte(strconv.Itoa(os.Getpid())+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := delegatedCandidate(mount, proc, 1000, os.Getpid()); got != want {
		t.Fatalf("delegatedCandidate = %q, want %q", got, want)
	}
	// A process outside a user@<uid>.service has no delegated candidate however consistent the
	// mount is: agreement is a veto, never a source of candidates.
	if got := delegatedCandidate(mount, proc, 1001, os.Getpid()); got != "" {
		t.Fatalf("candidate for the wrong uid: %q", got)
	}
}

// TestPrivilegedRootRequiresCgroup2 asserts the uid-0 branch of Detect validates its root. Without
// it a root launcher on a cgroup v1 or hybrid host gets an FS over a tmpfs and only finds out when
// clone3(CLONE_INTO_CGROUP) or cgroup.kill fails, i.e. after the run started unenforced.
func TestPrivilegedRootRequiresCgroup2(t *testing.T) {
	fs, err := privilegedRoot(t.TempDir(), nil, os.Getpid())
	if !errors.Is(err, ErrNotCgroup2) {
		t.Fatalf("privilegedRoot on a non-cgroup2 root = (%v, %v), want ErrNotCgroup2", fs, err)
	}
	if fs != nil {
		t.Fatal("no manager may be returned for a root that is not cgroup2")
	}
}

// agreeingMount builds a temporary directory laid out like a cgroup2 mount that agrees with a
// /proc/self/cgroup naming own: own's cgroup.procs lists this process. The mount root's own
// cgroup.procs lists pid 1 only, so the root is a cgroup this process is not in — how the host's
// root cgroup looks to a process in a cgroupns-private container handed the host's tree.
func agreeingMount(t *testing.T, own string) string {
	t.Helper()
	mount := t.TempDir()
	if err := os.MkdirAll(filepath.Join(mount, own), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(mount, own, fileProcs), []byte(strconv.Itoa(os.Getpid())+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(mount, fileProcs), []byte("1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return mount
}

// TestRequireMountAgreement is case 39's refusal over a temporary directory: nil only when the
// unified path resolves under the mount to a cgroup whose cgroup.procs lists this process, and
// ErrNotDelegated naming case 39 for every way of falling short of that — including the two where
// there is nothing to compare, since an unverified mount is the one case 39 is about.
//
// Also pins runtime-launch.md E39: a mount that does not hold this process's cgroup is refused.
func TestRequireMountAgreement(t *testing.T) {
	const own = "/user.slice/user-1000.slice/session-3.scope"
	mount := agreeingMount(t, own)
	other := filepath.Join(mount, "other.scope")
	if err := os.MkdirAll(other, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(other, fileProcs), []byte("1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		in     string
		refuse string // "" for agreement, else a substring the refusal must carry
	}{
		{"agrees", "0::" + own + "\n", ""},
		{"agrees after v1 lines", "12:pids:/x\n1:name=systemd:/y\n0::" + own + "\n", ""},
		{"cgroup lists someone else", "0::/other.scope\n", "holds no such cgroup"},
		{"namespace root of a foreign tree", "0::/\n", "holds no such cgroup"},
		{"path absent under the mount", "0::/nowhere.scope\n", "holds no such cgroup"},
		{"outside the namespace root", "0::/../../system.slice/docker-abc.scope\n", "outside the namespace"},
		{"the parent of the namespace root", "0::/..\n", "outside the namespace"},
		{"relative", "0::user.slice\n", "outside the namespace"},
		{"nul", "0::/a\x00b\n", "outside the namespace"},
		{"v1 lines only", "12:pids:/user.slice\n", "names no cgroup v2"},
		{"unreadable", "", "names no cgroup v2"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := requireMountAgreement(mount, []byte(tc.in), os.Getpid())
			if tc.refuse == "" {
				if err != nil {
					t.Fatalf("an agreeing mount was refused: %v", err)
				}
				return
			}
			if !errors.Is(err, ErrNotDelegated) {
				t.Fatalf("requireMountAgreement(%q) = %v, want ErrNotDelegated", tc.in, err)
			}
			if !strings.Contains(err.Error(), "case 39") || !strings.Contains(err.Error(), tc.refuse) {
				t.Fatalf("requireMountAgreement(%q) = %v, want case 39 and %q", tc.in, err, tc.refuse)
			}
		})
	}
}

// TestRequireMountAgreementNeverCleansDotDot pins why a "../" path is refused rather than resolved:
// path.Join would clean it into a directory outside the mount, and that directory can list this
// process — here it does — so resolving it would count an agreement the mount never showed.
func TestRequireMountAgreementNeverCleansDotDot(t *testing.T) {
	base := t.TempDir()
	outside := filepath.Join(base, "system.slice", "x.scope")
	if err := os.MkdirAll(outside, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outside, fileProcs), []byte(strconv.Itoa(os.Getpid())+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	mount := filepath.Join(base, "a", "b")
	if err := os.MkdirAll(mount, 0o755); err != nil {
		t.Fatal(err)
	}
	err := requireMountAgreement(mount, []byte("0::/../../system.slice/x.scope\n"), os.Getpid())
	if !errors.Is(err, ErrNotDelegated) || !strings.Contains(err.Error(), "case 39") {
		t.Fatalf("a ../ path that cleans into a directory listing this process = %v, want a case-39 refusal", err)
	}
}

// TestCandidatesInAsksTheMount drives the candidate list in the default test tier. The first case
// is case 39's motivating shape: "0::/" names no user@<uid>.service, so no derived candidate is
// built and the per-candidate agreement check is never consulted, yet the canonical candidate
// would be spliced onto the same foreign mount. The mount-level question must refuse it.
func TestCandidatesInAsksTheMount(t *testing.T) {
	const session = "/user.slice/user-1000.slice/session-3.scope"
	const service = "/user.slice/user-1000.slice/user@1000.service/app.slice/x.scope"
	foreign := agreeingMount(t, session)
	for _, in := range []string{
		"0::/\n",
		"0::/../../system.slice/docker-abc.scope\n",
		"0::/..\n",
		"0::" + service + "\n", // absent under this mount: the derived candidate is dropped, then refused
		"",
	} {
		got, err := candidatesIn(foreign, []byte(in), 1000, os.Getpid())
		if !errors.Is(err, ErrNotDelegated) || !strings.Contains(err.Error(), "case 39") {
			t.Fatalf("candidatesIn(%q) = (%q, %v), want a case-39 refusal", in, got, err)
		}
		if got != nil {
			t.Fatalf("candidatesIn(%q) refused but still returned candidates %q", in, got)
		}
	}

	canonical := filepath.Join(foreign, "user.slice/user-1000.slice/user@1000.service")
	got, err := candidatesIn(foreign, []byte("0::"+session+"\n"), 1000, os.Getpid())
	if err != nil || len(got) != 1 || got[0] != canonical {
		t.Fatalf("agreeing mount, no user service = (%q, %v), want [%q]", got, err, canonical)
	}

	// Inside the canonical user service the derived candidate is the canonical one, listed once.
	home := agreeingMount(t, service)
	derived := filepath.Join(home, "user.slice/user-1000.slice/user@1000.service")
	got, err = candidatesIn(home, []byte("0::"+service+"\n"), 1000, os.Getpid())
	if err != nil || len(got) != 1 || got[0] != derived {
		t.Fatalf("agreeing mount inside the user service = (%q, %v), want [%q]", got, err, derived)
	}

	// A user service somewhere else in the tree is tried first, then the canonical one.
	const elsewhere = "/machine.slice/user@1000.service/app.slice/x.scope"
	away := agreeingMount(t, elsewhere)
	want := []string{
		filepath.Join(away, "machine.slice/user@1000.service"),
		filepath.Join(away, "user.slice/user-1000.slice/user@1000.service"),
	}
	got, err = candidatesIn(away, []byte("0::"+elsewhere+"\n"), 1000, os.Getpid())
	if err != nil || len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("agreeing mount, user service off the canonical path = (%q, %v), want %q", got, err, want)
	}
}

// TestDetectDelegatedRefusesANonCgroup2Mount pins the order of the questions: a mount that is not
// cgroup2 at all is refused as that, before any case-39 question is asked of it. A hybrid host's
// /sys/fs/cgroup is a tmpfs, and neither "the namespaces disagree" nor "configure Delegate=" is the
// fix there. Both sentinels are reachable, so doctor can pick the hierarchy fix and callers that
// skip on ErrNotDelegated keep skipping.
func TestDetectDelegatedRefusesANonCgroup2Mount(t *testing.T) {
	const own = "/user.slice/user-1000.slice/user@1000.service/app.slice/x.scope"
	mount := agreeingMount(t, own) // agrees in every respect but the magic
	for _, in := range []string{"0::" + own + "\n", "12:pids:/user.slice\n", ""} {
		fs, err := detectDelegated(mount, []byte(in), 1000, os.Getpid())
		if fs != nil {
			t.Fatalf("detectDelegated(%q) built a manager over a temporary directory: %s", in, fs.Root())
		}
		if !errors.Is(err, ErrNotCgroup2) || !errors.Is(err, ErrNotDelegated) {
			t.Fatalf("detectDelegated(%q) = %v, want ErrNotCgroup2 and ErrNotDelegated", in, err)
		}
		if strings.Contains(err.Error(), "case 39") || strings.Contains(err.Error(), "Delegate=") {
			t.Fatalf("detectDelegated(%q) blamed the wrong fix on a non-cgroup2 mount: %v", in, err)
		}
		if !strings.Contains(err.Error(), "unified_cgroup_hierarchy") {
			t.Fatalf("detectDelegated(%q) lost the hierarchy fix: %v", in, err)
		}
	}
}

// TestFirstWritableNamesTheDelegationFix: when the mount agrees but no candidate qualifies, the
// refusal is the delegation one, naming every candidate it tried and the drop-in that fixes it.
func TestFirstWritableNamesTheDelegationFix(t *testing.T) {
	a, b := t.TempDir(), t.TempDir()
	fs, err := firstWritable(1000, []string{a, b})
	if fs != nil || !errors.Is(err, ErrNotDelegated) {
		t.Fatalf("firstWritable over temporary directories = (%v, %v), want ErrNotDelegated", fs, err)
	}
	for _, want := range []string{a, b, "user@.service.d", "uid 1000"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("the delegation refusal lost %q: %v", want, err)
		}
	}
	if strings.Contains(err.Error(), "case 39") {
		t.Fatalf("a candidate that is merely not writable was blamed on case 39: %v", err)
	}
}

// TestCommonAncestor pins the ancestor CanPlace asks the kernel's question of.
func TestCommonAncestor(t *testing.T) {
	for _, tc := range []struct{ a, b, want string }{
		{"/sys/fs/cgroup/system.slice/x.service", "/sys/fs/cgroup/user.slice/user-1001.slice/user@1001.service", "/sys/fs/cgroup"},
		{"/sys/fs/cgroup/user.slice/user-1000.slice/session-3.scope", "/sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service", "/sys/fs/cgroup/user.slice/user-1000.slice"},
		{"/sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service/app.slice/t.scope", "/sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service", "/sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service"},
		// a sibling whose name starts with the other's is not inside it
		{"/c/user@1000.service-x/a", "/c/user@1000.service", "/c"},
		{"/a", "/b", "/"},
	} {
		if got := commonAncestor(tc.a, tc.b); got != tc.want {
			t.Errorf("commonAncestor(%q, %q) = %q, want %q", tc.a, tc.b, got, tc.want)
		}
	}
}

// TestCanPlace is case 41 over a temporary directory: a process inside the root can always place a run
// there, and one outside it only when it may write the cgroup.procs of the two cgroups' common ancestor,
// which systemd leaves to root for a login's session-<n>.scope and a service alike.
//
// Also pins runtime-launch.md E41: an unprivileged launcher outside its delegated subtree is refused with ErrOutsideSubtree, and root is not.
func TestCanPlace(t *testing.T) {
	mount := t.TempDir()
	const user = "/user.slice/user-1000.slice"
	root := filepath.Join(mount, user, "user@1000.service")
	if err := os.MkdirAll(filepath.Join(root, "app.slice", "t.scope"), 0o755); err != nil {
		t.Fatal(err)
	}
	ancestorProcs := filepath.Join(mount, user, fileProcs)
	if err := os.WriteFile(ancestorProcs, []byte("1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	inside := []byte("0::" + user + "/user@1000.service/app.slice/t.scope\n")
	session := []byte("0::" + user + "/session-3.scope\n")

	if err := canPlace(mount, inside, root); err != nil {
		t.Fatalf("a process inside the root was refused: %v", err)
	}
	// Outside the root, an ancestor this process may write is the kernel's condition, and it holds here.
	if err := canPlace(mount, session, root); err != nil {
		t.Fatalf("a writable common ancestor was refused: %v", err)
	}
	// The same shape where no cgroup.procs of the ancestor can be written: here it does not exist, which
	// stops root as well as anyone else, as systemd's root-owned one stops every other uid.
	if err := os.Remove(ancestorProcs); err != nil {
		t.Fatal(err)
	}
	err := canPlace(mount, session, root)
	var de *DetectError
	if !errors.As(err, &de) || !errors.Is(err, ErrOutsideSubtree) || errors.Is(err, ErrNotDelegated) {
		t.Fatalf("canPlace from a session scope = %v, want a *DetectError matching ErrOutsideSubtree only", err)
	}
	for _, want := range []string{"session-3.scope", root, filepath.Join(mount, user) + "/" + fileProcs} {
		if !strings.Contains(de.Diagnosis, want) {
			t.Errorf("the diagnosis does not name %q: %s", want, de.Diagnosis)
		}
	}
	if !strings.Contains(de.Remedy, root) || !strings.Contains(de.Remedy, "systemd-run --user --scope") {
		t.Errorf("the remedy %q does not say to start tego inside %s", de.Remedy, root)
	}
	if err := canPlace(mount, nil, root); !errors.Is(err, ErrOutsideSubtree) {
		t.Fatalf("an unreadable /proc/self/cgroup = %v, want ErrOutsideSubtree", err)
	}
	// A privileged FS is the mount root, which uid 0 may always place in; CanPlace does not ask.
	if err := (&FS{root: mount, privileged: true}).CanPlace(); err != nil {
		t.Fatalf("a privileged FS was refused: %v", err)
	}
}

// TestEveryDetectRefusalNamesItsRemedy pins the contract doctor's D3 reads: every refusal Detect can
// return is a *DetectError whose Remedy is the one fix for that cause, and whose Error() is
// "<diagnosis>; fix: <remedy>" with the remedy said once. D3 prints Remedy as its fix line
// (docs/p0/limits-check-doctor-cli.md R27 D3). It used to split the message on the last "; fix: "
// instead, which nothing here pinned: a reworded separator would have sent case 39's refusal back to
// the Delegate= fix, which cannot help there, with every test still passing.
func TestEveryDetectRefusalNamesItsRemedy(t *testing.T) {
	tmp := t.TempDir()
	const own = "/user.slice/user-1000.slice/session-3.scope"
	mount := agreeingMount(t, own)
	type row struct {
		name     string
		err      error
		remedy   string
		matches  []error
		excludes []error
	}
	_, notCgroup2 := detectDelegated(tmp, nil, 1000, os.Getpid())
	_, absent := detectDelegated(filepath.Join(tmp, "absent"), nil, 1000, os.Getpid())
	_, rootNotCgroup2 := privilegedRoot(tmp, nil, os.Getpid())
	_, rootAbsent := privilegedRoot(filepath.Join(tmp, "absent"), nil, os.Getpid())
	_, notWritable := firstWritable(1000, []string{tmp})
	outside := canPlace(tmp, []byte("0::/system.slice/x.service\n"),
		filepath.Join(tmp, "user.slice/user-1000.slice/user@1000.service"))
	rows := []row{
		{"an unprivileged launcher's mount is not cgroup2", notCgroup2, "systemd.unified_cgroup_hierarchy=1",
			[]error{ErrNotDelegated, ErrNotCgroup2}, nil},
		// statfs fails before any magic is read: the errno is wrapped, not ErrNotCgroup2.
		{"the mount point cannot be statted", absent, "systemd.unified_cgroup_hierarchy=1",
			[]error{ErrNotDelegated, fs.ErrNotExist}, []error{ErrNotCgroup2}},
		{"a root launcher's mount is not cgroup2", rootNotCgroup2, "systemd.unified_cgroup_hierarchy=1",
			[]error{ErrNotCgroup2}, []error{ErrNotDelegated}},
		// The uid-0 branch has no ErrNotDelegated to lead with, so a mount point statfs cannot reach is
		// ErrNotCgroup2 as well: no cgroup2 filesystem is there, and the cure is the same hierarchy.
		{"a root launcher's mount point cannot be statted", rootAbsent, "systemd.unified_cgroup_hierarchy=1",
			[]error{ErrNotCgroup2, fs.ErrNotExist}, []error{ErrNotDelegated}},
		{"no 0:: line", requireMountAgreement(mount, nil, os.Getpid()), "is readable",
			[]error{ErrNotDelegated}, nil},
		{"a cgroup outside the namespace root", requireMountAgreement(mount, []byte("0::/../x.scope\n"), os.Getpid()),
			"from a cgroup inside its own cgroup namespace", []error{ErrNotDelegated}, nil},
		{"a mount that is someone else's tree", requireMountAgreement(mount, []byte("0::/\n"), os.Getpid()),
			"its own cgroup2 mount", []error{ErrNotDelegated}, nil},
		{"an agreeing mount with nothing delegated", notWritable, "Delegate=cpu memory pids",
			[]error{ErrNotDelegated}, nil},
		{"a launcher outside its delegated subtree (CanPlace)", outside, "systemd-run --user --scope",
			[]error{ErrOutsideSubtree, fs.ErrNotExist}, []error{ErrNotDelegated}},
	}
	for _, tc := range rows {
		t.Run(tc.name, func(t *testing.T) {
			var de *DetectError
			if !errors.As(tc.err, &de) {
				t.Fatalf("refusal %v (%T) is not a *DetectError", tc.err, tc.err)
			}
			if !strings.Contains(de.Remedy, tc.remedy) {
				t.Errorf("remedy %q, want it to name %q", de.Remedy, tc.remedy)
			}
			if got, want := tc.err.Error(), de.Diagnosis+"; fix: "+de.Remedy; got != want {
				t.Errorf("Error() = %q, want %q", got, want)
			}
			if strings.Count(tc.err.Error(), "; fix: ") != 1 || strings.Contains(de.Diagnosis, "fix:") {
				t.Errorf("the remedy is not said exactly once: %q", tc.err.Error())
			}
			for _, m := range tc.matches {
				if !errors.Is(tc.err, m) {
					t.Errorf("refusal does not match %v: %v", m, tc.err)
				}
			}
			for _, m := range tc.excludes {
				if errors.Is(tc.err, m) {
					t.Errorf("refusal matches %v and should not: %v", m, tc.err)
				}
			}
			// DetectError.Diagnosis begins with its sentinel's own text: ErrNotDelegated's wherever it
			// matches, else ErrOutsideSubtree's for CanPlace's refusal, else ErrNotCgroup2's.
			lead := ErrNotDelegated
			switch {
			case errors.Is(tc.err, ErrNotDelegated):
			case errors.Is(tc.err, ErrOutsideSubtree):
				lead = ErrOutsideSubtree
			default:
				lead = ErrNotCgroup2
			}
			if !strings.HasPrefix(de.Diagnosis, lead.Error()) {
				t.Errorf("diagnosis %q does not begin with %q", de.Diagnosis, lead.Error())
			}
		})
	}
}

// TestPrivilegedRootAsksCase39 is case 39 for a uid-0 launcher, against the real mount: root's
// /sys/fs/cgroup can be someone else's tree exactly as an ordinary user's can, and a root launcher in
// a cgroupns-private container handed the host's tree reads "0::/" for its namespace root. Without
// the question, privilegedRoot rooted at that mount, and Create would mkdir tego.slice and write
// limit files in the host's root cgroup before clone3 failed. It needs no privilege: privilegedRoot
// only reads, and NewAt only stats.
//
// Also pins runtime-launch.md E38: a privileged launcher roots at the cgroup2 mount itself, after the case-39 agreement question.
func TestPrivilegedRootAsksCase39(t *testing.T) {
	if err := checkCgroup2(Mount); err != nil {
		t.Skipf("no cgroup2 mount here: %v", err)
	}
	data, err := os.ReadFile(procSelfCgroup)
	if err != nil {
		t.Skipf("no %s: %v", procSelfCgroup, err)
	}
	if own := ownCgroup(data); own == "" || own == "/" {
		t.Skipf("this process's cgroup is %q, where the host-tree shape cannot be told apart", own)
	}
	fs, err := privilegedRoot(Mount, []byte("0::/\n"), os.Getpid())
	if fs != nil || !errors.Is(err, ErrNotDelegated) || !strings.Contains(err.Error(), "case 39") {
		t.Fatalf("privilegedRoot on a mount whose root cgroup does not hold this process = (%v, %v), "+
			"want a case-39 refusal", fs, err)
	}
	for _, in := range []string{"", "0::/../../system.slice/docker-abc.scope\n"} {
		if fs, err := privilegedRoot(Mount, []byte(in), os.Getpid()); fs != nil || !errors.Is(err, ErrNotDelegated) {
			t.Fatalf("privilegedRoot(%q) = (%v, %v), want a case-39 refusal", in, fs, err)
		}
	}
	// The other direction: this host's own /proc/self/cgroup agrees with its mount, and the root
	// branch still roots at the mount itself.
	fs, err = privilegedRoot(Mount, data, os.Getpid())
	if err != nil || fs == nil || fs.Root() != Mount || !fs.Privileged() {
		t.Fatalf("privilegedRoot on a self-consistent host = (%v, %v), want the privileged root %s", fs, err, Mount)
	}
}
