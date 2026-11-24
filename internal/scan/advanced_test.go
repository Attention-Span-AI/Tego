// SPDX-License-Identifier: Apache-2.0

package scan

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/scan/catalog"
	"github.com/attention-span-ai/tego/internal/scan/result"
	"github.com/attention-span-ai/tego/internal/testutil/jsonschema"
)

func TestAdvancedProcessesAllUIDsAndRecipientInterpreters(t *testing.T) {
	root := t.TempDir()
	uid := uint32(os.Getuid())
	other := uid + 5000
	for _, p := range []struct {
		pid int
		uid uint32
		exe string
		tty int
	}{{10, uid, "/bin/claude", 0}, {20, other, "/bin/codex", 0}, {30, other, "/bin/python3", 1}, {40, uid, "/bin/python3", 1}} {
		processFixture(t, root, p.pid, 1, uint64(p.pid*100), p.exe, []byte(filepath.Base(p.exe)+"\x00--token="+markerSecret+"\x00"), int64(p.tty))
		writeProcFile(t, root, fmt.Sprint(p.pid)+"/status", statusFixture(p.uid))
	}
	id := strings.Repeat("a", 64)
	writeProcFile(t, root, "20/cgroup", []byte("0::/system.slice/docker-"+id+".scope\n"))
	fs, e := openProc(root)
	if e != nil {
		t.Fatal(e)
	}
	defer fs.close()
	spy := &spyProc{procAccess: fs, t: t, opened: map[int]bool{}, ownerHook: func(pid int, _ uint32, e error) (uint32, error) {
		if pid == 20 || pid == 30 {
			return other, e
		}
		return uid, e
	}}
	spy.hook = func(pid int, name string, _ int, b []byte, e error) ([]byte, error) {
		if pid == 30 && name == "cgroup" {
			t.Fatal("read G detail for another uid's unmatched interpreter")
		}
		return b, e
	}
	spy.linkHook = func(pid int, name, value string, e error) (string, error) {
		if pid == 30 && name == "cwd" {
			t.Fatal("read another uid's unmatched interpreter cwd")
		}
		return value, e
	}
	got := readProcessesMode(t.Context(), spy, root, uid, catalog.Rows(), true)
	if got.Unknown || len(got.Processes) != 3 {
		t.Fatalf("all-user snapshot: %+v", got)
	}
	for _, p := range got.Processes {
		if p.PID == 30 {
			t.Fatal("other uid interpreter listed")
		}
		if p.PID == 20 && (p.UID != other || p.ContainerRuntime != "docker" || p.ContainerID != id) {
			t.Fatalf("missing cross-user container fact: %+v", p)
		}
	}
	assertNoCanary(t, got)
	// Basic directory filtering still skips foreign process content entirely.
	spy.opened = map[int]bool{}
	basic := readProcessesMode(t.Context(), spy, root, uid, catalog.Rows(), false)
	for _, p := range basic.Processes {
		if p.UID != uid {
			t.Fatal("basic crossed uid")
		}
	}
	if basic.OtherUID != 2 {
		t.Fatalf("foreign filter count %d", basic.OtherUID)
	}
}

func TestAdvancedSessionsNeverGroupAcrossUIDs(t *testing.T) {
	child := processObservation{UID: 2, Membership: "outside-run", Name: "codex"}
	parent := child
	parent.UID = 1
	if sameSession(child, parent) {
		t.Fatal("cross-user grouping erased observation")
	}
	parent.UID = child.UID
	child.ContainerRuntime = "docker"
	child.ContainerID = strings.Repeat("a", 64)
	if sameSession(child, parent) {
		t.Fatal("container child grouped into host ancestor")
	}
	parent.ContainerRuntime = "docker"
	parent.ContainerID = strings.Repeat("b", 64)
	if sameSession(child, parent) {
		t.Fatal("different containers grouped")
	}
	parent.ContainerID = child.ContainerID
	if !sameSession(child, parent) {
		t.Fatal("same observed container session split")
	}

}

func TestAdvancedContainerPatterns(t *testing.T) {
	id := strings.Repeat("f", 64)
	for _, tc := range []struct{ path, runtime string }{{"/docker/" + id, "docker"}, {"/system.slice/docker-" + id + ".scope", "docker"}, {"/user.slice/libpod-" + id + ".scope", "podman"}, {"/kubepods.slice/cri-containerd-" + id + ".scope", "containerd"}, {"/docker/" + id[:12], ""}, {"/system.slice/docker-" + strings.ToUpper(id) + ".scope", ""}, {"/system.slice/docker-" + markerSecret + ".scope", ""}, {"/docker/" + id + "/libpod-" + id + ".scope", ""}} {
		r, v := parseContainer([]byte("0::" + tc.path + "\n"))
		if r != tc.runtime || r != "" && v != id {
			t.Fatalf("runtime %q id %q for %q", r, v, tc.path)
		}
	}
}

func TestAdvancedLocalAccounts(t *testing.T) {
	input := "root:x:0:0:" + markerSecret + ":/root:/bin/sh\nservice:x:997:997::/nonexistent:/usr/sbin/nologin\nme:x:1000:1000::/home/me:/bin/bash\n"
	a, e := parseLocalAccounts([]byte(input))
	if e != nil || len(a) != 3 {
		t.Fatalf("accounts %v %v", a, e)
	}
	assertNoCanary(t, a)
	for _, s := range []string{input + "me:x:2000:2000::/other:/bin/sh\n", "me:x:1:1::/home/../other:/bin/sh\n", "me:x:4294967295:1::/home/me:/bin/sh\n"} {
		if _, e := parseLocalAccounts([]byte(s)); e == nil {
			t.Fatal("ambiguous or unsafe account accepted")
		}
	}
	var b strings.Builder
	for i := 0; i < 4096; i++ {
		fmt.Fprintf(&b, "u%d:x:%d:1::/nonexistent:/bin/false\n", i, i)
	}
	if a, e := parseLocalAccounts([]byte(b.String())); e != nil || len(a) != 4096 {
		t.Fatalf("capacity: %d %v", len(a), e)
	}
	b.WriteString("overflow:x:9999:1::/nonexistent:/bin/false\n")
	if _, e := parseLocalAccounts([]byte(b.String())); e != errLimit {
		t.Fatal("account cap missing", e)
	}
}

func TestAdvancedCollectRootRefusalBeforeReads(t *testing.T) {
	o := commandOptions(t)
	o.Advanced = true
	o.Caller.InitialRoot = false
	o.OnProcRead = func(string) { t.Fatal("read before root guard") }
	got := Collect(t.Context(), o)
	if got.Snapshot.ExitCode() != 125 || got.Home != "" || got.Snapshot.Mode != "advanced" || got.Snapshot.As.Recipient != o.Caller.UID {
		t.Fatal("bad advanced refusal")
	}
	if _, e := result.Encode(got.Snapshot); e != nil {
		t.Fatal(e)
	}
	o.Advanced = false
	o.OnProcRead = nil
	if Collect(t.Context(), o).Snapshot.ExitCode() != 0 {
		t.Fatal("basic scan was disabled")
	}
}

func TestAdvancedCollectionSourcesAndPrivacy(t *testing.T) {
	o := commandOptions(t)
	baseCaller := o.Caller
	uid := baseCaller.UID
	second := t.TempDir()
	for _, home := range []string{o.Directory, second} {
		path := filepath.Join(home, ".config/systemd/user")
		if e := os.MkdirAll(path, 0700); e != nil {
			t.Fatal(e)
		}
		if e := os.WriteFile(filepath.Join(path, "agent.service"), []byte("[Service]\nExecStart=/usr/bin/codex --token="+markerSecret+"\nEnvironment=KEY="+markerSecret+"\n"), 0600); e != nil {
			t.Fatal(e)
		}
	}
	dropin := filepath.Join(second, ".config/systemd/user/agent.service.d")
	if e := os.MkdirAll(dropin, 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(dropin, "value.conf"), []byte("[Service]\nEnvironment=TOKEN="+markerSecret+"\n"), 0600); e != nil {
		t.Fatal(e)
	}
	o.Advanced = true
	o.BeforeRecipient = func(uint32, uint32) error { return nil }
	o.Caller.UID = 0
	o.Caller.EUID = 0
	o.Caller.InitialRoot = true
	o.Caller.Recipient = uid
	o.Check = true
	identify := func(ctx context.Context, fs procAccess, root, passwd, boot string, _ Caller, _ bool) (callerIdentity, string) {
		v, r := identifyCaller(ctx, fs, root, passwd, boot, baseCaller)
		v.Accounts = []localAccount{{UID: uid, Home: o.Directory, Name: "one"}, {UID: uid, Home: second, Name: "two"}}
		return v, r
	}
	processes := func(ctx context.Context, fs procAccess, root string, uid uint32, rows []catalog.Row) processSnapshot {
		return readProcessesMode(ctx, fs, root, uid, rows, true)
	}
	got := collectWithIdentity(t.Context(), o, processes, identify)
	s := got.Snapshot
	if s.Counts.Units != 2 || s.Counts.Running != 1 || s.Check != "outside-observed" || s.As.Recipient != uid {
		t.Fatalf("counts %+v check %s sources %+v", s.Counts, s.Check, s.Sources)
	}
	assertNoCanary(t, s)
	b, e := result.Encode(s)
	if e != nil {
		t.Fatal(e)
	}
	var wire any
	if e = json.Unmarshal(b, &wire); e != nil {
		t.Fatal(e)
	}
	if e = jsonschema.Check("../../spec/scan/v1/schema.json", wire); e != nil {
		t.Fatal(e)
	}
	for _, verbose := range []bool{false, true} {
		var out, errs bytes.Buffer
		if e = result.Render(&out, &errs, s, false, verbose, nil); e != nil {
			t.Fatal(e)
		}
		if strings.Contains(out.String()+errs.String(), markerSecret) {
			t.Fatal("render canary")
		}
	}
}

func FuzzScanContainer(f *testing.F) {
	f.Add([]byte("0::/system.slice/docker-" + strings.Repeat("a", 64) + ".scope\n"))
	f.Add([]byte("0::/" + markerSecret + "\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		r, id := parseContainer(b)
		if r != "" && (len(id) != 64 || strings.Trim(id, "0123456789abcdef") != "" || (r != "docker" && r != "podman" && r != "containerd")) {
			t.Fatal("invalid container hint")
		}
		assertNoCanary(t, struct{ Runtime, ID string }{r, id})
	})
}

func FuzzScanAccounts(f *testing.F) {
	f.Add([]byte("me:x:123:42:" + markerSecret + ":/home/me:/bin/sh\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		a, e := parseLocalAccounts(b)
		if e != nil && len(a) != 0 {
			t.Fatal("partial accounts")
		}
		for _, v := range a {
			if !plainPath(v.Home) || !plainAccountName(v.Name) {
				t.Fatal("invalid account metadata")
			}
		}
	})
}

func TestAdvancedUnreadableProgramsRemainUnknown(t *testing.T) {
	root := t.TempDir()
	uid := uint32(os.Getuid())
	processFixture(t, root, 10, 1, 100, "/bin/codex", []byte("codex\x00"+markerSecret+"\x00"), 0)
	fs, e := openProc(root)
	if e != nil {
		t.Fatal(e)
	}
	defer fs.close()
	spy := &spyProc{procAccess: fs, t: t, opened: map[int]bool{}, linkHook: func(_ int, name, value string, e error) (string, error) {
		if name == "exe" {
			return "", os.ErrPermission
		}
		return value, e
	}}
	advanced := readProcessesMode(t.Context(), spy, root, uid, catalog.Rows(), true)
	if !advanced.Unknown || len(advanced.UnreadablePIDs) != 0 || len(advanced.Processes) != 0 {
		t.Fatalf("advanced hidden program was accepted: %+v", advanced)
	}
	if len(advanced.Sources) != 2 || advanced.Sources[1].Reason != "permission" || advanced.Sources[1].State != "not-read" {
		t.Fatalf("hidden source missing: %+v", advanced.Sources)
	}
	basic := readProcessesMode(t.Context(), spy, root, uid, catalog.Rows(), false)
	if basic.Unknown || len(basic.UnreadablePIDs) != 1 {
		t.Fatalf("basic own-program exception changed: %+v", basic)
	}
	assertNoCanary(t, advanced)
}

func TestAdvancedAliasReadsSpendSharedInputBudget(t *testing.T) {
	root := unitFixtureRoot(t)
	body := []byte("[Service]\nExecStart=/usr/bin/codex\n")
	if e := os.WriteFile(filepath.Join(root, "real.service"), body, 0600); e != nil {
		t.Fatal(e)
	}
	for name, target := range map[string]string{"a.service": "real.service", "b.service": "a.service"} {
		if e := os.Symlink(target, filepath.Join(root, name)); e != nil {
			t.Fatal(e)
		}
	}
	budget := &contentBudget{remaining: 1 << 20}
	for i := 1; i <= 2; i++ {
		got := collectUnits(t.Context(), []string{root}, uint32(os.Getuid()), budget)
		if len(got.Items) != 1 {
			t.Fatalf("ordinary aliases refused: %+v", got.Sources)
		}
		want := i * (3*4097 + len(body))
		if used := (1 << 20) - budget.remaining; used != want {
			t.Fatalf("alias reads escaped shared budget: %d want %d", used, want)
		}
	}
	budget.remaining = 1
	got := collectUnits(t.Context(), []string{root}, uint32(os.Getuid()), budget)
	found := false
	for _, s := range got.Sources {
		if s.Reason == "limit" {
			found = true
		}
	}
	if !found || len(got.Items) != 0 || budget.remaining != 0 {
		t.Fatal("alias input exhaustion lost its warning or evidence")
	}
}

func TestAdvancedStableProcessOwners(t *testing.T) {
	uid := uint32(os.Getuid())
	for _, tc := range []struct {
		name             string
		owner, effective uint32
		unknown          bool
	}{
		{"nondumpable root metadata", 0, uid, false},
		{"nonroot effective uid", uid + 1, uid + 1, false},
		{"unrelated owner", uid + 2, uid + 1, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			processFixture(t, root, 10, 1, 100, "/bin/codex", []byte("codex\x00--token="+markerSecret+"\x00"), 0)
			status := bytes.Replace(statusFixture(uid), []byte(fmt.Sprintf("Uid:\t%d\t%d\t%d\t%d", uid, uid, uid, uid)), []byte(fmt.Sprintf("Uid:\t%d\t%d\t%d\t%d", uid, tc.effective, tc.effective, tc.effective)), 1)
			writeProcFile(t, root, "10/status", status)
			fs, e := openProc(root)
			if e != nil {
				t.Fatal(e)
			}
			defer fs.close()
			spy := &spyProc{procAccess: fs, t: t, opened: map[int]bool{}, ownerHook: func(_ int, _ uint32, e error) (uint32, error) { return tc.owner, e }}
			p, e := spy.open(10)
			if e != nil {
				t.Fatal(e)
			}
			defer p.close()
			got := readProcessMode(t.Context(), p, 10, uid, catalog.Rows(), filepath.Join(root, "10"), true)
			if got.critical != tc.unknown {
				t.Fatalf("stable process owner classification: %+v", got)
			}
			if !tc.unknown && (!got.own || got.observation.RuleID != "codex-native" || got.observation.UID != uid) {
				t.Fatalf("ordinary privileged process omitted: %+v", got)
			}
			assertNoCanary(t, got)
		})
	}
}
