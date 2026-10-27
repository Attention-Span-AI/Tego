// SPDX-License-Identifier: Apache-2.0

package adopt

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/runscope"
)

func TestIdentifyReadsTheFactsAndRefusesATornRead(t *testing.T) {
	m := terminal()
	p := mustIdentify(m, 200)
	if p.PID != 200 || p.Start != 1200 || p.PPID != 100 || p.Exe != "/usr/bin/node" || p.Cgroup != session ||
		p.Owner() != 1000 || p.Tgid != 200 || p.CgroupNS != 7 || p.PidNS != 8 || p.ExeFile != (FileID{1, 200}) {
		t.Fatalf("Identify = %+v", p)
	}
	// The pid is reused between the two reads of its start time: the facts read in between may be the new
	// process's, so the read is refused.
	calls := 0
	m.statHook = func(m *machine, pid int) {
		if pid != 200 {
			return
		}
		if calls++; calls == 2 {
			m.procs[200].start = 5000
		}
	}
	if _, err := Identify(m, 200); !errors.Is(err, ErrGone) {
		t.Fatalf("a torn read: err = %v, want ErrGone", err)
	}
	m.statHook = nil
	m.procs[201].state = 'Z'
	if _, err := Identify(m, 201); !errors.Is(err, ErrGone) {
		t.Fatalf("a zombie: err = %v, want ErrGone", err)
	}
	if _, err := Identify(m, 4242); !errors.Is(err, ErrGone) {
		t.Fatalf("no such pid: err = %v, want ErrGone", err)
	}
}

func TestParseStatus(t *testing.T) {
	s, err := ParseStatus([]byte("Name:\tclaude\nTgid:\t200\nPid:\t200\nUid:\t1000\t1001\t1002\t1003\nGid:\t5\t6\t7\t8\n"))
	if err != nil || s.Tgid != 200 || s.UID != [3]int{1000, 1001, 1002} || s.GID != [3]int{5, 6, 7} {
		t.Fatalf("ParseStatus = %+v, %v", s, err)
	}
	const gid = "Gid:\t1\t1\t1\t1\n"
	for _, bad := range []string{
		"Tgid:\t200\n" + gid,                               // no Uid line
		"Uid:\t1\t1\t1\t1\n" + gid,                         // no Tgid line
		"Tgid:\t200\nUid:\t1\t1\t1\t1\n",                   // no Gid line
		"Tgid:\t200\nUid:\t1\t1\n" + gid,                   // a short Uid line
		"Tgid:\tx\nUid:\t1\t1\t1\t1\n" + gid,               // a Tgid that is no number
		"Tgid:\t200\nUid:\t-1\t1\t1\t1\n" + gid,            // a negative uid
		"Tgid:\t0\nUid:\t1\t1\t1\t1\n" + gid,               // a Tgid of 0
		"Tgid:\t200\nUid:\ta\tb\tc\td\n" + gid,             // uids that are no numbers
		"Tgid:\t200\nUid:\t1\t1\t1\t1\nGid:\tx\t1\t1\t1\n", // a gid that is no number
	} {
		if _, err := ParseStatus([]byte(bad)); err == nil {
			t.Errorf("ParseStatus(%q) accepted", bad)
		}
	}
	if _, err := ParseStatus([]byte("Tgid:\t200\nUid:\t1\t1\t1\t1\n" + gid + "z:")); err != nil {
		t.Errorf("a stray line: %v", err)
	}
	maps := "7f00-7f10 r--p 00000000 08:01 1234 /usr/lib/libc.so.6\n" +
		"7f10-7f20 r-xp 00001000 08:01 1234 /usr/lib/libc.so.6\n" +
		"7f20-7f30 rw-s 00000000 08:01 99 /home/u/notes with space.db\n" +
		"7f30-7f40 rw-p 00000000 00:00 0 \n" +
		"7f40-7f50 rw-s 00000000 08:01 98 /tmp/gone (deleted)\n" +
		"7ffd-7ffe rw-p 00000000 00:00 0 [stack]\n"
	want := []Mapping{{Path: "/usr/lib/libc.so.6"}, {Path: "/home/u/notes with space.db", SharedWritable: true},
		{Path: "/tmp/gone", SharedWritable: true}}
	if got, cut := parseMappings([]byte(maps), nil, nil); !reflect.DeepEqual(got, want) || cut {
		t.Errorf("parseMappings(maps) = %+v %v, want %+v", got, cut, want)
	}
	// smaps: a shared mapping read-only now but of a file opened for writing (VmFlags mw) may be made writable by
	// mprotect with no open the plane sees, so it counts; one without mw cannot. A shared mapping whose VmFlags line
	// is missing counts, fail-closed.
	smaps := "7f00-7f10 r--s 00000000 08:01 7 /home/u/maywrite.db\nSize:   4 kB\nRss:   4 kB\n" +
		"VmFlags: rd sh mr mw me ms sd\n" +
		"7f10-7f20 r--s 00000000 08:01 8 /usr/share/fonts.cache\nSize:   4 kB\nVmFlags: rd sh mr me ms sd\n" +
		"7f20-7f30 r--p 00000000 08:01 9 /usr/lib/libz.so\nVmFlags: rd mr mw me sd\n" +
		"7f30-7f40 r--s 00000000 08:01 10 /home/u/unflagged\nSize:   4 kB\n"
	want = []Mapping{{Path: "/home/u/maywrite.db", SharedWritable: true}, {Path: "/usr/share/fonts.cache"},
		{Path: "/usr/lib/libz.so"}, {Path: "/home/u/unflagged", SharedWritable: true}}
	if got, cut := parseMappings([]byte(smaps), nil, nil); !reflect.DeepEqual(got, want) || cut {
		t.Errorf("parseMappings(smaps) = %+v %v, want %+v", got, cut, want)
	}
	var many strings.Builder
	for i := range maxMaps + 1 {
		fmt.Fprintf(&many, "%x-%x r--p 00000000 08:01 %d /lib/f%d\n", 0x1000*i, 0x1000*i+0x1000, i, i)
	}
	if got, cut := parseMappings([]byte(many.String()), nil, nil); len(got) != maxMaps || !cut {
		t.Errorf("past the cap: %d mappings, truncated %v; want %d and the truncation said", len(got), cut, maxMaps)
	}
	if got := parseFDFlags([]byte("pos:\t0\nflags:\t0100002\nmnt_id:\t30\n")); got != 0o100002 {
		t.Errorf("parseFDFlags = %o", got)
	}
	if !(FD{Target: "socket:[5]"}).Socket() || !(FD{Target: "/a"}).File() || !(FD{Flags: 0o2}).Writes() ||
		(FD{Flags: 0o100000}).Writes() {
		t.Error("FD predicates")
	}
}

// self is the adopter of the usual fake: a `tego adopt` run by sudo from the agent's own terminal, whose ancestors
// are sudo (800), the shell (100), sshd (90) and systemd (1).
func adopterSelf(m *machine) Self {
	m.add(800, 100, session, "/usr/bin/sudo", 0)
	m.add(801, 800, session, "/usr/local/bin/tego", 0)
	s, err := SelfOf(m, 801)
	if err != nil {
		panic(err)
	}
	return s
}

func TestSelfOfWalksTheAncestry(t *testing.T) {
	m := terminal()
	s := adopterSelf(m)
	if got := s.Ancestors; len(got) != 4 || got[0] != 800 || got[1] != 100 || got[2] != 90 || got[3] != 1 {
		t.Fatalf("ancestors = %v, want [800 100 90 1]", got)
	}
	// A /proc that loops (a pid that is its own grandparent) is not followed for ever.
	m.procs[90].ppid = 100
	s, err := SelfOf(m, 801)
	if err != nil || len(s.Ancestors) != 3 {
		t.Fatalf("a looping ancestry: %v %v", s.Ancestors, err)
	}
}

func TestCheckRefusesWhatIsNeverAdopted(t *testing.T) {
	m := terminal()
	self := adopterSelf(m)
	m.add(2, 0, "/", "", 0).comm = "kthreadd"
	m.add(400, 1, "/docker/abc", "/usr/bin/claude", 1000).cgns = 99
	m.add(401, 1, session, "/usr/bin/claude", 1000).pidns = 0
	m.add(500, 1, "/tego.slice/tego-w.slice/run-r-0a1b2c3d-0123456789abc-xyz123.scope", "/usr/bin/claude", 1000)
	m.add(501, 1, "/tego.slice/tego-w.slice/adopt-r-0a1b2c3d-0123456789abc-xyz123.scope", "/usr/bin/claude", 1000)
	m.add(502, 1, "/tego/claude/r-0a1b2c3d-0123456789abc-xyz123/c1", "/usr/bin/claude", 1000)
	m.add(503, 1, "", "/usr/bin/claude", 1000)
	// A run's name in the user's own subtree, where tego makes no run: not governed, so not refused as one.
	m.add(508, 1, "/user.slice/user-1000.slice/user@1000.service/app.slice/run-r-0a1b2c3d-0123456789abc-xyz123.scope",
		"/usr/bin/claude", 1000)
	m.add(504, 1, session, "/opt/other/tego", 1000)
	m.add(505, 1, session, "/usr/bin/node", 1000).tgid = 200
	m.add(506, 1, session, "/usr/bin/copy-of-tego", 0).exeFile = self.ExeFile
	m.add(507, 1, "/", "/usr/bin/claude", 1000)
	cases := []struct {
		pid  int
		rule string
	}{
		{1, RefuseInit},
		{2, RefuseKernel},
		{801, RefuseTego},      // this process
		{506, RefuseTego},      // tego's binary under another name
		{504, RefuseTego},      // another tego
		{800, RefuseAncestor},  // sudo
		{100, RefuseAncestor},  // the caller's shell
		{90, RefuseAncestor},   // sshd
		{50, RefuseManager},    // the user's systemd manager
		{400, RefuseNamespace}, // a container's process
		{401, RefuseNamespace}, // namespaces unreadable
		{500, RefuseGoverned},  // inside a tego run
		{501, RefuseGoverned},  // inside another adoption
		{502, RefuseGoverned},  // inside a Docker run
		{503, RefuseNoCgroup},
		{507, RefuseRoot}, // in the root cgroup: a release could not give it back
		{505, RefuseThread},
	}
	for _, c := range cases {
		p, err := Identify(m, c.pid)
		if err != nil {
			t.Fatalf("pid %d: %v", c.pid, err)
		}
		err = Check(p, self)
		rule, ok := IsRefusal(err)
		if !ok || rule != c.rule {
			t.Errorf("pid %d (%s): Check = %v, want a refusal under %s", c.pid, p.Exe, err, c.rule)
		}
	}
	// The agent itself, and a process of the sibling tab, are adoptable: Check says nothing about the tree.
	for _, pid := range []int{200, 201, 300, 508} {
		if err := Check(mustIdentify(m, pid), self); err != nil {
			t.Errorf("pid %d: Check = %v, want nil", pid, err)
		}
	}
}

func TestCheckRefusesTheCallersAncestorWhateverItRuns(t *testing.T) {
	// The ancestor rule is the one that keeps `sudo tego adopt --pid $PPID` from taking the operator's own shell,
	// terminal or tmux server: an otherwise adoptable process (uid 1000, in the session, not tego) is refused only
	// because it is above the caller.
	m := terminal()
	m.add(700, 1, session, "/usr/bin/tmux", 1000)
	m.add(701, 700, session, "/usr/bin/bash", 1000)
	m.add(702, 701, session, "/usr/local/bin/tego", 0)
	self, err := SelfOf(m, 702)
	if err != nil {
		t.Fatal(err)
	}
	for _, pid := range []int{700, 701} {
		if rule, ok := IsRefusal(Check(mustIdentify(m, pid), self)); !ok || rule != RefuseAncestor {
			t.Errorf("pid %d: want the ancestor refusal, got %v", pid, Check(mustIdentify(m, pid), self))
		}
	}
}

// TestScopeNameIsWhatRunscopeReads: the scope an adoption is made in is the one internal/runscope reads as that run's
// adoption (GovernedBy and its rules moved there, with their table).
func TestScopeNameIsWhatRunscopeReads(t *testing.T) {
	id := "r-0a1b2c3d-0123456789abc-xyz123"
	if ScopeName(id) != "adopt-"+id+".scope" {
		t.Errorf("ScopeName = %q", ScopeName(id))
	}
	cg := "/tego.slice/tego-a.slice/" + ScopeName(id)
	if got, adoption := runscope.GovernedBy(cg), runscope.AdoptionScopeRun(cg); got != id || adoption != id {
		t.Errorf("runscope reads %q as run %q, adoption %q; want %s", cg, got, adoption, id)
	}
}

func TestUIDsAdmitOnlyAListedOwner(t *testing.T) {
	m := terminal()
	m.add(600, 1, session, "/usr/bin/claude", 0)                                // root's
	m.add(601, 1, session, "/usr/bin/claude", 1001).uid = [3]int{1001, 0, 1001} // a set-user-id switch
	m.add(602, 1, session, "/usr/bin/claude", 1001)
	cases := []struct {
		uids UIDs
		pid  int
		ok   bool
		why  string
	}{
		{UIDs{1000}, 200, true, ""},
		{UIDs{1000}, 600, false, "root (uid 0)"},
		{UIDs{1000, 0}, 600, true, ""},
		{UIDs{1000, 1001, 0}, 601, false, "differ"},
		{UIDs{1000}, 602, false, "uid 1001"},
		{nil, 200, false, "uid 1000"},
	}
	for _, c := range cases {
		ok, why := c.uids.Admits(mustIdentify(m, c.pid))
		if ok != c.ok || !strings.Contains(why, c.why) {
			t.Errorf("%v admits pid %d = %v %q, want %v containing %q", c.uids, c.pid, ok, why, c.ok, c.why)
		}
		if err := c.uids.Admit(mustIdentify(m, c.pid)); (err == nil) != c.ok {
			t.Errorf("%v Admit pid %d = %v", c.uids, c.pid, err)
		} else if err != nil {
			if rule, _ := IsRefusal(err); rule != RefuseUID {
				t.Errorf("Admit's refusal rule = %q", rule)
			}
		}
	}
}
