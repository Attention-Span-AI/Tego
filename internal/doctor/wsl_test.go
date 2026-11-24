// SPDX-License-Identifier: Apache-2.0

package doctor

import (
	"context"
	"encoding/json"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"io/fs"
	"os"
	"strings"
	"testing"
	"testing/fstest"
)

func TestWSLHostReach(t *testing.T) {
	for _, tc := range []struct {
		name, kernel, fixture, path string
		want, absent                []string
	}{
		{name: "linux", kernel: "6.17.0-generic", fixture: "linux", want: nil, absent: []string{"Windows"}},
		{name: "wsl1", kernel: "4.4.0-microsoft", fixture: "linux", want: nil, absent: []string{"Windows"}},
		{name: "closed", kernel: "6.6.87.2-microsoft-standard-WSL2", fixture: "closed", path: "/usr/bin:/bin", want: []string{"AF_VSOCK", "Windows network services", "cross-distribution", "interop sockets", "handler enabled"}, absent: []string{"Windows filesystem mount", "WSLg GUI", "Windows PATH"}},
		{name: "open", kernel: "6.6.87.2-microsoft-standard-WSL2", fixture: "open", path: "/bin:/mnt/c/Windows/System32", want: []string{"AF_VSOCK", "Windows network services", "Windows filesystem mount at /mnt/c", "cross-distribution", "interop sockets", "handler enabled", "Windows PATH"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			files, err := fs.Sub(os.DirFS("testdata/wsl"), tc.fixture)
			if err != nil {
				t.Fatal(err)
			}
			got := strings.Join(wslHostReach(tc.kernel, files, tc.path, ""), "; ")
			for _, want := range tc.want {
				if !strings.Contains(got, want) {
					t.Errorf("missing %q: %s", want, got)
				}
			}
			for _, absent := range tc.absent {
				if strings.Contains(got, absent) {
					t.Errorf("unexpected %q: %s", absent, got)
				}
			}
		})
	}
	got := strings.Join(wslHostReach("6.6.0-microsoft-standard-WSL2", fstest.MapFS{}, "", ""), "; ")
	if !strings.Contains(got, "mounts unknown") {
		t.Fatal(got)
	}
}

func TestWSLgDirectoryDoesNotClaimSocketExposure(t *testing.T) {
	files := fstest.MapFS{
		"mnt/wslg/placeholder": &fstest.MapFile{},
		"proc/self/mountinfo":  &fstest.MapFile{Data: []byte("1 0 8:64 / / rw - ext4 /dev/sde rw\n")},
	}
	got := strings.Join(wslHostReach("6.18.58.1-microsoft-standard-WSL2", files, "", ""), "; ")
	if strings.Contains(got, "WSLg GUI/audio") {
		t.Fatalf("an ordinary directory was reported as exposed GUI/audio sockets: %s", got)
	}
	files["mnt/wslg/PulseServer"] = &fstest.MapFile{Mode: fs.ModeSocket | 0o666}
	got = strings.Join(wslHostReach("6.18.58.1-microsoft-standard-WSL2", files, "", ""), "; ")
	if !strings.Contains(got, "WSLg GUI/audio") || !strings.Contains(got, "/mnt/wslg/PulseServer") {
		t.Fatalf("a real socket mode was not reported: %s", got)
	}
}

func TestWSLSessionAndCustomKernel(t *testing.T) {
	files, err := fs.Sub(os.DirFS("testdata/wsl"), "closed")
	if err != nil {
		t.Fatal(err)
	}
	closed := strings.Join(wslHostReach("custom-kernel", files, "/bin", ""), "; ")
	opened := strings.Join(wslHostReach("custom-kernel", files, "/bin", "/run/WSL/123_interop"), "; ")
	if !strings.Contains(closed, "Windows network services") || strings.Contains(closed, "OPEN for this session") {
		t.Fatal(closed)
	}
	if !strings.Contains(opened, "Windows program execution is OPEN for this session") {
		t.Fatal(opened)
	}
	many := wslHostReach("custom-kernel", files, strings.Repeat("/mnt/c/Windows:", 40), "")
	if len(many) > 9 || !strings.Contains(strings.Join(many, ";"), "more host-reach observations") {
		t.Fatal(many)
	}
}

func TestRunAttachesWSLWarnings(t *testing.T) {
	old := wslWarnings
	t.Cleanup(func() { wslWarnings = old })
	calls := 0
	wslWarnings = func(string) []string { calls++; return []string{"fixture wired host reach"} }
	report, err := Run(context.Background(), &config.Machine{}, "")
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("Run requested WSL observations %d times, want 1", calls)
	}
	found := false
	for _, result := range report.Results {
		if result.ID == CheckKernel {
			found = strings.HasSuffix(result.Detail, "; WARNING: WSL host reach: fixture wired host reach")
		} else if strings.Contains(result.Detail, "fixture wired host reach") {
			t.Fatalf("WSL warning attached to %s", result.ID)
		}
	}
	if !found {
		t.Fatal("Run did not attach WSL observations to the kernel result")
	}
}

func TestWSLWarningsInReportOnlyChangeKernelDetail(t *testing.T) {
	old := wslWarnings
	t.Cleanup(func() { wslWarnings = old })
	wslWarnings = func(string) []string { return nil }
	m := &config.Machine{}
	before, err := Run(context.Background(), m, "")
	if err != nil {
		t.Fatal(err)
	}
	// Exercise the exact attachment called by Run, on its full report. Deriving
	// the status again would repeat kernel probes and introduce unrelated races.
	exitBefore := before.ExitCode()
	rawBefore, err := json.Marshal(before)
	if err != nil {
		t.Fatal(err)
	}
	wslWarnings = func(string) []string { return []string{"fixture host reach"} }
	before.addWSLWarnings()
	found := false
	for i := range before.Results {
		if before.Results[i].ID == CheckKernel {
			suffix := "; WARNING: WSL host reach: fixture host reach"
			if !strings.HasSuffix(before.Results[i].Detail, suffix) {
				t.Fatal(before.Results[i])
			}
			before.Results[i].Detail = strings.TrimSuffix(before.Results[i].Detail, suffix)
			found = true
		}
	}
	if !found {
		t.Fatal("Run did not report kernel")
	}
	rawAfter, err := json.Marshal(before)
	if err != nil {
		t.Fatal(err)
	}
	if before.ExitCode() != exitBefore {
		t.Fatal("warning changed doctor exit status")
	}
	if string(rawBefore) != string(rawAfter) {
		t.Fatal("host warning changed report fields other than kernel detail")
	}
}

func TestWSLDisabledHandlerGPUAndUnreadable(t *testing.T) {
	files := fstest.MapFS{
		"run/WSL/marker":                     &fstest.MapFile{},
		"dev/dxg":                            &fstest.MapFile{Mode: fs.ModeDevice | fs.ModeCharDevice | 0o666},
		"proc/sys/fs/binfmt_misc/WSLInterop": &fstest.MapFile{Data: []byte("disabled\n")},
	}
	got := strings.Join(wslHostReach("custom", files, "", ""), "; ")
	if !strings.Contains(got, "Windows GPU device") || strings.Contains(got, "handler enabled") {
		t.Fatal(got)
	}
	got = strings.Join(wslHostReach("custom", deniedWSLFS{files}, "", ""), "; ")
	if !strings.Contains(got, "handler unreadable: reach unknown") {
		t.Fatal(got)
	}
}

type deniedWSLFS struct{ fs.FS }

func (f deniedWSLFS) Open(name string) (fs.File, error) {
	if name == "proc/sys/fs/binfmt_misc/WSLInterop" {
		return nil, fs.ErrPermission
	}
	return f.FS.Open(name)
}
