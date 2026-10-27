// SPDX-License-Identifier: Apache-2.0

//go:build integration

package runtime

import (
	"bufio"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestRootRunStartNamesTheSudoAccount is ADR 0073's root arm: `sudo tego run --tier cgroup` records launcher_uid 0,
// and the invoking account sudo names as sudo_uid and, from passwd, sudo_user; the same contract run by that account
// at tier landlock records its own uid and no sudo_uid; both record host as uname -n.
func TestRootRunStartNamesTheSudoAccount(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root: the case is sudo tego run")
	}
	if disposableHost() == "" {
		t.Skip("a root run at tier cgroup loads programs and makes host state: runs only where TEGO_DISPOSABLE_HOST is set (test/vm/root-suites.sh's KVM guests) or GITHUB_ACTIONS=true")
	}
	uid, gid, ok := agentUID(t)
	if !ok {
		t.Skip("needs SUDO_UID naming the invoking user, as `sudo go test` and test/vm/root-suites.sh give")
	}
	requireLandlock(t)
	var uts unix.Utsname
	if err := unix.Uname(&uts); err != nil {
		t.Fatal(err)
	}
	host := unix.ByteSliceToString(uts.Nodename[:])
	name, err := passwdName(uint32(uid))
	if err != nil {
		t.Fatalf("the invoking uid %d has no passwd name: %v", uid, err)
	}
	bin := tegoBPFBinary(t)
	agentReaches(t, bin)

	root := newPrivpathCase(t, -1, -1)
	agentReaches(t, root.out)
	agentOwns(t, root.out)
	code, out := root.exec(t, exec.Command(bin, "run", "--tier", "cgroup", filepath.Join(root.dir, "agent.yaml")))
	if code != 0 || !root.ran() {
		t.Fatalf("sudo tego run --tier cgroup: exit %d, ran %v:\n%s", code, root.ran(), out)
	}
	p := onlyRunStart(t, root.root)
	if p.Tier != "cgroup" || p.LauncherUID == nil || *p.LauncherUID != 0 || p.LauncherUser != "root" ||
		p.SudoUID == nil || *p.SudoUID != uint32(uid) || p.SudoUser != name || p.Host != host {
		t.Fatalf("run_start tier %s launcher_uid %v launcher_user %q sudo_uid %v sudo_user %q host %q; want cgroup, 0, root, %d, %q, %q",
			p.Tier, p.LauncherUID, p.LauncherUser, p.SudoUID, p.SudoUser, p.Host, uid, name, host)
	}

	user := newPrivpathCase(t, uid, gid)
	code, out = user.exec(t, asUser(exec.Command(bin, "run", "--tier", "landlock", filepath.Join(user.dir, "agent.yaml")),
		uid, gid, userLeaf(t, uid, gid)))
	if code != 0 || !user.ran() {
		t.Fatalf("tego run --tier landlock as uid %d: exit %d, ran %v:\n%s", uid, code, user.ran(), out)
	}
	p = onlyRunStart(t, user.root)
	if p.Tier != "landlock" || p.LauncherUID == nil || *p.LauncherUID != uint32(uid) || p.LauncherUser != name ||
		p.SudoUID != nil || p.SudoUser != "" || p.Host != host {
		t.Fatalf("run_start tier %s launcher_uid %v launcher_user %q sudo_uid %v sudo_user %q host %q; want landlock, %d, %q, none, %q",
			p.Tier, p.LauncherUID, p.LauncherUser, p.SudoUID, p.SudoUser, p.Host, uid, name, host)
	}
}

// TestRootAgentHasItsOwnAccountsHome is identity-config.md R3a: sudo gives the launcher HOME=/root, USER=root and
// LOGNAME=root, and the agent, which runs as the invoking user, gets that user's instead of a home it cannot enter.
func TestRootAgentHasItsOwnAccountsHome(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root: the case is sudo tego run")
	}
	if disposableHost() == "" {
		t.Skip("a root run at tier cgroup loads programs and makes host state: runs only where TEGO_DISPOSABLE_HOST is set (test/vm/root-suites.sh's KVM guests) or GitHub Actions")
	}
	uid, _, ok := agentUID(t)
	if !ok {
		t.Skip("needs SUDO_UID naming the invoking user, as `sudo go test` and test/vm/root-suites.sh give")
	}
	requireLandlock(t)
	root, err := config.LookupPasswd(0)
	if err != nil {
		t.Fatal(err)
	}
	target, err := config.LookupPasswd(uid)
	if err != nil {
		t.Fatalf("the invoking uid %d has no passwd entry: %v", uid, err)
	}
	if root.HomeDir == target.HomeDir {
		t.Fatalf("root and uid %d share the home %s: this case tells nothing", uid, root.HomeDir)
	}
	bin := tegoBPFBinary(t)
	agentReaches(t, bin)

	c := newPrivpathCase(t, -1, -1)
	agentReaches(t, c.out)
	agentOwns(t, c.out)
	contract := `version: 0
name: privpath
command: ["/bin/sh", "-c", "echo \"$HOME $USER $LOGNAME\" > out/ran"]
fs:
  write: ["./out/"]
record: summary
`
	if err := os.WriteFile(filepath.Join(c.dir, "agent.yaml"), []byte(contract), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out := c.exec(t, exec.Command(bin, "run", "--tier", "cgroup", filepath.Join(c.dir, "agent.yaml")),
		"HOME="+root.HomeDir, "USER="+root.Username, "LOGNAME="+root.Username)
	if code != 0 || !c.ran() {
		t.Fatalf("sudo tego run --tier cgroup: exit %d, ran %v:\n%s", code, c.ran(), out)
	}
	got, err := os.ReadFile(filepath.Join(c.out, "ran"))
	if err != nil {
		t.Fatal(err)
	}
	if want := target.HomeDir + " " + target.Username + " " + target.Username + "\n"; string(got) != want {
		t.Fatalf("the agent saw %q, want %q", got, want)
	}
}

// onlyRunStart is the run_start of the one run under ledger root, at record_minor 17 or later.
func onlyRunStart(t *testing.T, root string) record.RunStartPayload {
	t.Helper()
	dirs := runDirs(t, root)
	if len(dirs) != 1 {
		t.Fatalf("%d runs under %s, want 1", len(dirs), root)
	}
	f, err := os.Open(filepath.Join(dirs[0], ledger.EventsFile))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(nil, 1<<20)
	if !sc.Scan() {
		t.Fatalf("%s is empty", dirs[0])
	}
	var p record.RunStartPayload
	if err := json.Unmarshal(sc.Bytes(), &p); err != nil {
		t.Fatal(err)
	}
	if p.RecordMinor < record.MinorRunIdentity {
		t.Fatalf("run_start at record_minor %d, want %s or later", p.RecordMinor, strconv.Itoa(record.MinorRunIdentity))
	}
	return p
}
