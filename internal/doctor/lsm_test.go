// SPDX-License-Identifier: Apache-2.0

package doctor

import (
	"errors"
	"fmt"
	"github.com/attention-span-ai/tego/internal/platform/tomoyo"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func TestParseLSMList(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want []string
	}{
		{"debian 13", "lockdown,capability,landlock,yama,apparmor,bpf,ima,evm",
			[]string{"lockdown", "capability", "landlock", "yama", "apparmor", "bpf", "ima", "evm"}},
		{"trailing newline", "capability,bpf\n", []string{"capability", "bpf"}},
		{"spaces", " capability , bpf ", []string{"capability", "bpf"}},
		{"single", "capability", []string{"capability"}},
		{"empty fields", ",,capability,,", []string{"capability"}},
		{"empty", "", nil},
		{"only separators", ",,,", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ParseLSMList([]byte(tc.in)); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("ParseLSMList(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestParseLSMLog(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want []string
		ok   bool
	}{
		{"one line", "6,1,0,-;LSM: initializing lsm=capability,landlock,bpf\n",
			[]string{"capability", "landlock", "bpf"}, true},
		{"surrounded by other lines", "5,0,0,-;Linux version 6.17\n6,1,0,-;LSM: initializing lsm=capability,yama\n7,2,0,-;x\n",
			[]string{"capability", "yama"}, true},
		{"trailing text on the line", "6,1,0,-;LSM: initializing lsm=capability,bpf extra\n",
			[]string{"capability", "bpf"}, true},
		{"a later line wins", "a;LSM: initializing lsm=capability\nb;LSM: initializing lsm=capability,bpf\n",
			[]string{"capability", "bpf"}, true},
		{"no marker", "6,1,0,-;Linux version 6.17\n", nil, false},
		{"marker with an empty list", "x;LSM: initializing lsm=\n", nil, true},
		{"empty", "", nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := ParseLSMLog([]byte(tc.in))
			if ok != tc.ok || !reflect.DeepEqual(got, tc.want) {
				t.Errorf("ParseLSMLog(%q) = %q, %v; want %q, %v", tc.in, got, ok, tc.want, tc.ok)
			}
		})
	}
}

// TestGRUBFixKeepsTheActiveList is R27's one-line fix: it must add bpf to what the machine already
// runs, never replace it — a bare lsm=bpf would disable every other LSM at the next boot.
func TestGRUBFixKeepsTheActiveList(t *testing.T) {
	s := LSMState{Modules: []string{"lockdown", "capability", "landlock", "yama", "apparmor"}}
	fix := s.GRUBFixFor(bootDebian)
	for _, want := range []string{"lsm=lockdown,capability,landlock,yama,apparmor,bpf", "GRUB_CMDLINE_LINUX_DEFAULT", "reboot"} {
		if !strings.Contains(fix, want) {
			t.Errorf("fix %q does not contain %q", fix, want)
		}
	}
	empty := LSMState{}.GRUBFix()
	if !strings.Contains(empty, "lsm=bpf") {
		t.Errorf("with no known list the fix is %q", empty)
	}
}

func TestLSMState(t *testing.T) {
	s := lsmState([]string{"capability", "bpf"}, LSMSourceSyscall)
	if !s.BPFActive || s.Source != LSMSourceSyscall {
		t.Errorf("state %+v", s)
	}
	if lsmState([]string{"capability"}, LSMSourceSecurityFS).BPFActive {
		t.Error("bpf reported active when it is not in the list")
	}
}

// TestReadLSMStateOnThisMachine exercises whichever of the three mechanisms this kernel offers.
func TestReadLSMStateOnThisMachine(t *testing.T) {
	s, err := ReadLSMState()
	if err != nil {
		t.Skipf("no LSM list is readable here: %v", err)
	}
	if len(s.Modules) == 0 {
		t.Fatal("an answer with no modules")
	}
	if s.Source == LSMSourceNone {
		t.Errorf("state %+v has modules but no source", s)
	}
	var capability bool
	for _, m := range s.Modules {
		if m == "capability" {
			capability = true
		}
	}
	if !capability {
		t.Errorf("the capability LSM is always active; got %q", s.Modules)
	}
	t.Logf("%s via %s (bpf active: %v)", strings.Join(s.Modules, ","), s.Source, s.BPFActive)
}

func FuzzParseLSMList(f *testing.F) {
	f.Add("capability,bpf")
	f.Add(",,")
	f.Fuzz(func(t *testing.T, in string) {
		mods := ParseLSMList([]byte(in))
		for _, m := range mods {
			if m == "" || strings.Contains(m, ",") || strings.TrimSpace(m) != m {
				t.Fatalf("module %q from %q is empty, holds a comma or is not trimmed", m, in)
			}
		}
		// The list written back as the kernel writes it reads as itself.
		if again := ParseLSMList([]byte(strings.Join(mods, ","))); !slices.Equal(again, mods) {
			t.Fatalf("ParseLSMList(%q) = %q, which reads back as %q", in, mods, again)
		}
	})
}

// FuzzParseLSMLog: a list is found exactly when the boot line's marker is in the log, its modules are names
// ParseLSMList could return, and a log that is only that line with them reads back as them, which the
// earlier version of this fuzz target never checked.
func FuzzParseLSMLog(f *testing.F) {
	const marker = "LSM: initializing lsm="
	f.Add("x;LSM: initializing lsm=capability,bpf\n")
	f.Add("LSM: initializing lsm=")
	f.Add("[0.0] LSM: initializing lsm=lockdown,capability landlock\nLSM: initializing lsm=a,,b\t\n")
	f.Fuzz(func(t *testing.T, in string) {
		mods, ok := ParseLSMLog([]byte(in))
		if ok != strings.Contains(in, marker) {
			t.Fatalf("ParseLSMLog(%q) found a list = %v, but the marker is there = %v", in, ok, !ok)
		}
		for _, m := range mods {
			if m == "" || strings.ContainsAny(m, ", \t\n") {
				t.Fatalf("module %q from %q is empty or holds a separator", m, in)
			}
		}
		if !ok {
			return
		}
		if again, ok := ParseLSMLog([]byte(marker + strings.Join(mods, ","))); !ok || !slices.Equal(again, mods) {
			t.Fatalf("ParseLSMLog(%q) = %q, which reads back as %q, %v", in, mods, again, ok)
		}
	})
}

// TestGRUBFixPerFamily holds the boot fix to the tool each distribution family uses, keeping the live list, with a
// golden per family.
func TestGRUBFixPerFamily(t *testing.T) {
	s := LSMState{Modules: []string{"lockdown", "capability", "landlock", "yama", "apparmor"}}
	for fam, name := range map[string]string{bootDebian: "debian", bootRHEL: "rhel", bootUnknown: "unknown"} {
		checkGolden(t, "grubfix-"+name+".golden", s.GRUBFixFor(fam)+"\n")
	}
	if strings.Contains(s.GRUBFixFor(bootRHEL), "update-grub") || !strings.Contains(s.GRUBFixFor(bootRHEL), "grubby --update-kernel=ALL --args") {
		t.Errorf("rhel fix: %s", s.GRUBFixFor(bootRHEL))
	}
	if strings.Contains(s.GRUBFixFor(bootDebian), "grubby") {
		t.Errorf("debian fix: %s", s.GRUBFixFor(bootDebian))
	}
}

// TestBootFamilyOf reads the family from /etc/os-release's ID and ID_LIKE.
func TestBootFamilyOf(t *testing.T) {
	cases := map[string]string{
		"ID=ubuntu\nID_LIKE=debian\n":                    bootDebian,
		"ID=debian\n":                                    bootDebian,
		"ID=linuxmint\nID_LIKE=\"ubuntu debian\"\n":      bootDebian,
		"ID=fedora\n":                                    bootRHEL,
		"ID=\"amzn\"\nID_LIKE=\"fedora\"\n":              bootRHEL,
		"ID=\"rocky\"\nID_LIKE=\"rhel centos fedora\"\n": bootRHEL,
		"ID=alpine\n":                                    bootUnknown,
		"":                                               bootUnknown,
	}
	for in, want := range cases {
		if got := bootFamilyOf(in); got != want {
			t.Errorf("bootFamilyOf(%q) = %q, want %q", in, got, want)
		}
	}
	old := osReleasePath
	t.Cleanup(func() { osReleasePath = old })
	osReleasePath = filepath.Join(t.TempDir(), "absent")
	if got := bootFamily(); got != bootUnknown {
		t.Errorf("no os-release: %q", got)
	}
	f := filepath.Join(t.TempDir(), "os-release")
	if err := os.WriteFile(f, []byte("ID=amzn\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	osReleasePath = f
	if got := (LSMState{Modules: []string{"capability"}}).GRUBFix(); !strings.Contains(got, "grubby") ||
		!strings.Contains(got, "lsm=capability,bpf") {
		t.Errorf("GRUBFix on an AL2023 machine: %s", got)
	}
}

func TestTOMOYOHeldOpenDetail(t *testing.T) {
	t.Cleanup(tomoyo.SetLoaderOmissionForTest(func() string { return "" }))
	moved := fmt.Sprintf("Policy %-30s %10d (Last: 2026/11/19 12:00:00)\n", "update:", 3)
	for _, tc := range []struct{ name, domain, missing, line, profile, want string }{
		{name: "Debian stock", domain: "<kernel>", want: "TOMOYO has no policy update since boot and does not prevent held file opens"},
		{name: "loaded policy", domain: "<kernel> /usr/bin/tego", want: "held opens are refused on this machine"},
		{name: "updated", domain: "<kernel>", line: "Policy update:                                 1\n", want: "until TOMOYO is unused again after a restart"},
		{name: "updated, a root thread's profile proof", domain: "<kernel> /usr/bin/tego", line: moved, profile: "PROFILE_VERSION=20150505\n0-CONFIG={ mode=disabled grant_log=no reject_log=yes }\n",
			want: "profile, read now, enforces nothing"},
		{name: "updated, the profile enforces", domain: "<kernel>", line: moved, profile: "PROFILE_VERSION=20150505\n0-CONFIG={ mode=enforcing grant_log=no reject_log=yes }\n",
			want: "held opens are refused on this machine (TOMOYO profile"},
		{name: "hidden securityfs", missing: "/sys/kernel/security/tomoyo/stat", want: "expose readable /sys/kernel/security/tomoyo"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			read := func(path string) ([]byte, error) {
				if path == tc.missing {
					return nil, os.ErrPermission
				}
				if strings.HasSuffix(path, "self_domain") {
					return []byte(tc.domain), nil
				}
				if strings.HasSuffix(path, "/profile") {
					if tc.profile == "" {
						return nil, os.ErrPermission // a thread that is not root
					}
					return []byte(tc.profile), nil
				}
				if tc.line != "" {
					return []byte(tc.line), nil
				}
				return []byte("Policy update:                                 0\n"), nil
			}
			got := tomoyoHeldOpenDetail(LSMState{Modules: []string{"apparmor", "tomoyo"}}, read)
			if !strings.Contains(got, tc.want) || !strings.Contains(got, "TOMOYO") || strings.Contains(got, "AppArmor") {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
			if got := tomoyoHeldOpenDetail(LSMState{Modules: []string{"apparmor"}}, func(string) ([]byte, error) { t.Fatal("read TOMOYO on another boot"); return nil, nil }); got != "" {
				t.Fatal(got)
			}
		})
	}
}

// TestTOMOYOHeldOpenDetailNamesTheFactsPath: the doctor line names which files TOMOYO's facts came from, the kernel's
// path or the administrator's tomoyo.facts_dir; a hidden kernel path is answered with the bind remedy, a configured one
// that fails is not told to expose the kernel's path, and no wording offers to assume TOMOYO enforces nothing.
func TestTOMOYOHeldOpenDetailNamesTheFactsPath(t *testing.T) {
	t.Cleanup(tomoyo.SetLoaderOmissionForTest(func() string { return "" }))
	t.Cleanup(func() { _ = tomoyo.SetFactsDir("") })
	state := LSMState{Modules: []string{"tomoyo"}}
	hidden := func(string) ([]byte, error) { return nil, os.ErrPermission }
	stock := func(p string) ([]byte, error) {
		if strings.HasSuffix(p, "self_domain") {
			return []byte("<kernel>\n"), nil
		}
		return []byte("Policy update:                                 0\n"), nil
	}
	got := tomoyoHeldOpenDetail(state, hidden)
	for _, want := range []string{"TOMOYO facts read from /sys/kernel/security/tomoyo", "tomoyo.facts_dir", "read-only"} {
		if !strings.Contains(got, want) {
			t.Errorf("default, hidden: %q lacks %q", got, want)
		}
	}
	if err := tomoyo.SetFactsDir("/run/tego-tomoyo"); err != nil {
		t.Fatal(err)
	}
	if got := tomoyoHeldOpenDetail(state, stock); !strings.Contains(got, "TOMOYO facts read from /run/tego-tomoyo (tomoyo.facts_dir)") ||
		!strings.Contains(got, "does not prevent held file opens") {
		t.Errorf("configured, stock: %q", got)
	}
	got = tomoyoHeldOpenDetail(state, hidden)
	if !strings.Contains(got, "TOMOYO facts read from /run/tego-tomoyo (tomoyo.facts_dir)") || strings.Contains(got, "expose readable") {
		t.Errorf("configured, failing: %q", got)
	}
	for _, s := range []string{got, tomoyoHeldOpenDetail(state, stock)} {
		if strings.Contains(strings.ToLower(s), "assume") {
			t.Errorf("an assume-style wording: %q", s)
		}
	}
}

// TestUnreadLSMListDoctorWords: a list no mechanism could read is said with the cause of each failure, what it
// stops (tier bpflsm cannot be decided; held file opens are refused) and the option that would let tego read it, in
// place of the host-only "mount securityfs" line. errors.Is(ErrLSMList) still holds.
func TestUnreadLSMListDoctorWords(t *testing.T) {
	err := error(&LSMReadError{
		Syscall:    fmt.Errorf("lsm_list_modules(2): %w", unix.EPERM),
		SecurityFS: &os.PathError{Op: "open", Path: "/sys/kernel/security/lsm", Err: unix.EACCES},
	})
	if !errors.Is(err, ErrLSMList) {
		t.Fatalf("%v is not ErrLSMList", err)
	}
	d, fix := lsmUnreadDetail(err), lsmUnreadFixFor(err)
	for _, w := range []string{"cannot read the active LSM list", "lsm_list_modules(2) was refused", "docker-default AppArmor",
		"tier bpflsm cannot be decided safely", "held file opens", "held-label-unavailable"} {
		if !strings.Contains(d, w) {
			t.Errorf("detail %q lacks %q", d, w)
		}
	}
	for _, w := range []string{"permit lsm_list_modules in the outer seccomp filter", "expose a readable /sys/kernel/security/lsm", "mount securityfs"} {
		if !strings.Contains(fix, w) {
			t.Errorf("fix %q lacks %q", fix, w)
		}
	}
	// An error with no causes (a caller's own) keeps the generic words and the host fix.
	if d := lsmUnreadDetail(ErrLSMList); !strings.Contains(d, "held file opens") || strings.Contains(d, "lsm_list_modules(2)") {
		t.Errorf("bare ErrLSMList detail %q", d)
	}
	if fix := lsmUnreadFixFor(ErrLSMList); fix != lsmUnreadFix {
		t.Errorf("bare ErrLSMList fix %q, want %q", fix, lsmUnreadFix)
	}
}
