// SPDX-License-Identifier: Apache-2.0

package doctor

import (
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
