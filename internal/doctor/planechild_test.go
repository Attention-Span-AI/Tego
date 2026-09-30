// SPDX-License-Identifier: Apache-2.0

package doctor

import (
	"bufio"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	bpfobj "github.com/attention-span-ai/tego/internal/bpf"
)

// startTestPlaneChild runs this test binary as the plane probe's child on a fresh fixtures tree with extra as its
// inherited descriptors, sends go, and returns its answers per hook and its exit error.
func startTestPlaneChild(t *testing.T, dir string, extra ...*os.File) (map[string]string, error) {
	t.Helper()
	if err := makePlaneFixtures(dir); err != nil {
		t.Fatal(err)
	}
	closeSockets, err := bindPlaneSockets(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer closeSockets()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, PlaneProbeCommand, "child", dir)
	cmd.ExtraFiles = extra
	cmd.Stdin = strings.NewReader("go\n")
	cmd.Stderr = os.Stderr
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	sc := bufio.NewScanner(out)
	for sc.Scan() {
		if name, res, ok := strings.Cut(sc.Text(), "\t"); ok {
			got[name] = res
		}
	}
	return got, cmd.Wait()
}

// TestPlaneChildExecsTheInheritedImage: the probe child's bprm_check execs the image doctor made and passed it,
// not a copy of the binary of its own, so a probe copies the binary once, not once per side.
func TestPlaneChildExecsTheInheritedImage(t *testing.T) {
	short := os.Getenv("TMPDIR")
	if short == "" {
		short = os.TempDir()
	}
	dir, err := os.MkdirTemp(short, "pc")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	marker := filepath.Join(dir, "ran")
	const mfdExec = 0x10
	fd, err := unix.MemfdCreate(planeImageName, unix.MFD_CLOEXEC|mfdExec)
	if errors.Is(err, unix.EINVAL) {
		fd, err = unix.MemfdCreate(planeImageName, unix.MFD_CLOEXEC)
	}
	if err != nil {
		t.Skipf("memfd: %v", err)
	}
	img := os.NewFile(uintptr(fd), planeImageName)
	defer func() { _ = img.Close() }()
	if _, err := img.WriteString("#!/bin/sh\n: > " + marker + "\n"); err != nil {
		t.Fatal(err)
	}
	got, err := startTestPlaneChild(t, filepath.Join(dir, "in"), img)
	if err != nil {
		t.Fatalf("child: %v (answers %v)", err, got)
	}
	if len(got) != len(bpfobj.PlaneHooks) {
		t.Errorf("answers %v, want one per hook", got)
	}
	if got["bprm_check"] != planePassed {
		if strings.Contains(got["bprm_check"], "permission denied") {
			t.Skipf("this host refuses an executable memfd: %s", got["bprm_check"])
		}
		t.Fatalf("bprm_check %q, want passed", got["bprm_check"])
	}
	if _, err := os.Stat(marker); err != nil {
		t.Errorf("the child's exec did not run the inherited image: %v", err)
	}
}

// TestPlaneChildRefusesWithoutAnImage: a child started with no exec image on its descriptor 3 exits failing before
// it says ready, rather than exec whatever that descriptor is.
func TestPlaneChildRefusesWithoutAnImage(t *testing.T) {
	dir, err := os.MkdirTemp(os.Getenv("TMPDIR"), "pc")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	other, err := os.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = other.Close() }()
	for i, extra := range [][]*os.File{nil, {other}} {
		got, err := startTestPlaneChild(t, filepath.Join(dir, strconv.Itoa(i)), extra...)
		if err == nil || len(got) != 0 {
			t.Errorf("with %d extra descriptors: answers %v, exit %v; want a failure before any answer", len(extra), got, err)
		}
	}
}
