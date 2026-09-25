// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	cgroupenforce "github.com/attention-span-ai/tego/internal/runtime/enforce/cgroup"
)

// doctorBuildRows are one build of each kind doctor's builds section tells apart (ADR 0022 (5), (8)): held by a
// launcher; idle inside its linger with its timer running; idle with no timer; past its linger; kept past it by a run
// it enforces that is alive, past its linger and inside it; kept because its run set cannot be read; one the sweep
// could not look at; and one whose objects' memlock the kernel did not all report. A kept row says whether its timer
// runs, as every other idle row does.
var doctorBuildRows = []cgroupenforce.BuildInfo{
	{Hash: "aaaa", InUse: true, Programs: 17, Links: 9, CaptureProbes: 7, CaptureLibraries: []string{"2-1497-x"},
		Rings: 2, RingBytes: 4 << 20, MemlockBytes: 1_310_720, Path: "/sys/fs/bpf/tego/aaaa"},
	{Hash: "bbbb", Idle: 90 * time.Second, IdleS: 90, Programs: 17, Links: 9, Timer: true, TimerPID: 4242,
		MemlockBytes: 1_200_128, Path: "/sys/fs/bpf/tego/bbbb"},
	{Hash: "cccc", Idle: 90 * time.Second, IdleS: 90, Programs: 17, Links: 9, MemlockBytes: 1_200_128,
		Path: "/sys/fs/bpf/tego/cccc"},
	{Hash: "dddd", Idle: time.Hour, IdleS: 3600, MemlockBytes: 4096, Path: "/sys/fs/bpf/tego/dddd"},
	{Hash: "eeee", Idle: time.Hour, IdleS: 3600, Programs: 17, Links: 9, Runs: []string{"r-orphan"},
		Kept: cgroupenforce.KeptLive, Timer: true, TimerPID: 77, MemlockBytes: 1_200_128, Path: "/sys/fs/bpf/tego/eeee"},
	{Hash: "ffff", Idle: time.Hour, IdleS: 3600, Programs: 17, Links: 9,
		Kept: cgroupenforce.KeptUnread, KeptCause: "map key size 4, want 8", MemlockBytes: 900_000,
		Path: "/sys/fs/bpf/tego/ffff"},
	{Hash: "gggg", Idle: 30 * time.Second, IdleS: 30, Programs: 3, MemlockUnreported: 3, Timer: true, TimerPID: 9,
		Path: "/sys/fs/bpf/tego/gggg"},
	{Hash: "hhhh", Idle: 30 * time.Second, IdleS: 30, Programs: 3, MemlockBytes: 8192, MemlockUnreported: 1,
		Timer: true, TimerPID: 10, Path: "/sys/fs/bpf/tego/hhhh"},
	{Hash: "iiii", Idle: 90 * time.Second, IdleS: 90, Programs: 17, Links: 9, Runs: []string{"r-orphan2"},
		Kept: cgroupenforce.KeptLive, Timer: true, TimerPID: 55, MemlockBytes: 1_200_128, Path: "/sys/fs/bpf/tego/iiii"},
	{Hash: "jjjj", Idle: time.Hour, IdleS: 3600, Programs: 17, Links: 9, Kept: cgroupenforce.KeptSweepFailed,
		KeptCause: "lock the build: permission denied", MemlockBytes: 1_200_128, Path: "/sys/fs/bpf/tego/jjjj"},
}

// TestDoctorBuildsGolden is limits-check-doctor-cli.md R27's builds section, byte for byte in text and --json
// (testdata/doctor-builds.golden, doctor-builds-json.golden): one line per tier-2 build, a held one as in use, an
// idle one with its idle time, whether its timer runs (with its pid) and so when it goes, a build kept past its
// linger with why and that `tego gc --builds` does not remove it, what it holds and the memory its programs and maps
// charge (memlock, ADR 0022 (8)), and a heading that sums that memory over the builds.
func TestDoctorBuildsGolden(t *testing.T) {
	var out bytes.Buffer
	rings := &cgroupenforce.RingUse{Budget: 256 << 20, Used: 4 << 20, Rings: 2}
	if err := writeBuilds(&out, doctorBuildRows, 5*time.Minute, rings); err != nil {
		t.Fatal(err)
	}
	// The report's builds and rings, in its key order; the version banner and the probes have goldens of their own.
	b, err := json.Marshal(doctorReport{Builds: doctorBuildRows, Rings: rings})
	if err != nil {
		t.Fatal(err)
	}
	var part struct {
		Builds json.RawMessage `json:"builds"`
		Rings  json.RawMessage `json:"rings"`
	}
	if err := json.Unmarshal(b, &part); err != nil {
		t.Fatal(err)
	}
	j, err := json.MarshalIndent(part, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	for name, got := range map[string][]byte{"doctor-builds.golden": out.Bytes(), "doctor-builds-json.golden": append(j, '\n')} {
		golden := filepath.Join("testdata", name)
		if *updateGolden {
			if err := os.WriteFile(golden, got, 0o644); err != nil {
				t.Fatal(err)
			}
			continue
		}
		want, err := os.ReadFile(golden)
		if err != nil {
			t.Fatalf("%v (go test -run TestDoctorBuildsGolden -update writes it)", err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("doctor's builds section differs from %s:\ngot:\n%s\nwant:\n%s", golden, got, want)
		}
	}
}
