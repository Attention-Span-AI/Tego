// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// multicallHost lays out, under a temp dir, the two layouts doctor names: uutils' (bin/ls a symlink to one of three hard
// links of one file) and busybox's (bbin/ls a symlink to a file named busybox), and a GNU one (gbin/ls, one link). Each
// file is a script that, if run, leaves a file named ran beside it, so the test can show doctor runs none of them.
func multicallHost(t *testing.T) (root string) {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{"lib/mc", "lib/bb", "bin", "bbin", "gbin"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	script := func(p string) {
		t.Helper()
		if err := os.WriteFile(p, []byte("#!/bin/sh\n: > \"$(dirname \"$0\")/ran\"\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	script(filepath.Join(root, "lib/mc/ls"))
	script(filepath.Join(root, "lib/bb/busybox"))
	script(filepath.Join(root, "gbin/ls"))
	for _, n := range []string{"cat", "sleep"} {
		if err := os.Link(filepath.Join(root, "lib/mc/ls"), filepath.Join(root, "lib/mc", n)); err != nil {
			t.Fatal(err)
		}
	}
	for link, target := range map[string]string{"bin/ls": "../lib/mc/ls", "bbin/ls": "../lib/bb/busybox"} {
		if err := os.Symlink(target, filepath.Join(root, link)); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// TestDoctorMulticallGolden: doctor's multicall line, byte for byte in text and --json (testdata/doctor-multicall.golden,
// doctor-multicall-json.golden), for a uutils host (the file ls leads to, its link count, what an entry admits at each
// tier) and a busybox host (the dispatcher, every program at every tier). A GNU host, whose ls is one file of one link,
// and a PATH with no ls get no line and no --json key. ls is found on PATH and read by stat: no layout's file is run.
func TestDoctorMulticallGolden(t *testing.T) {
	root := multicallHost(t)
	var text bytes.Buffer
	parts := map[string]json.RawMessage{}
	for _, tc := range []struct{ name, dir string }{{"uutils", "bin"}, {"busybox", "bbin"}} {
		t.Setenv("PATH", filepath.Join(root, tc.dir))
		c := checkMulticall()
		if c == nil {
			t.Fatalf("%s: no multicall line", tc.name)
		}
		if err := writeMulticallCheck(&text, c); err != nil {
			t.Fatal(err)
		}
		b, err := json.Marshal(doctorReport{Multicall: c})
		if err != nil {
			t.Fatal(err)
		}
		var part struct {
			Multicall json.RawMessage `json:"multicall"`
		}
		if err := json.Unmarshal(b, &part); err != nil {
			t.Fatal(err)
		}
		parts[tc.name] = part.Multicall
	}
	for _, dir := range []string{"gbin", "nothing-here"} {
		t.Setenv("PATH", filepath.Join(root, dir))
		c := checkMulticall()
		if c != nil {
			t.Errorf("PATH %s: a line where none is due: %+v", dir, c)
		}
		var none bytes.Buffer
		if err := writeMulticallCheck(&none, c); err != nil || none.Len() != 0 {
			t.Errorf("PATH %s: wrote %q (%v), want nothing", dir, none.String(), err)
		}
		b, err := json.Marshal(doctorReport{Multicall: c})
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(b), `"multicall"`) {
			t.Errorf("PATH %s: --json has a multicall key: %s", dir, b)
		}
	}
	for _, d := range []string{"lib/mc", "lib/bb", "gbin"} {
		if _, err := os.Stat(filepath.Join(root, d, "ran")); err == nil {
			t.Errorf("doctor ran the file in %s", d)
		}
	}
	j, err := json.MarshalIndent(parts, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	for name, got := range map[string][]byte{
		"doctor-multicall.golden":      []byte(strings.ReplaceAll(text.String(), root, "<root>")),
		"doctor-multicall-json.golden": []byte(strings.ReplaceAll(string(j), root, "<root>") + "\n"),
	} {
		golden := filepath.Join("testdata", name)
		if *updateGolden {
			if err := os.WriteFile(golden, got, 0o644); err != nil {
				t.Fatal(err)
			}
			continue
		}
		want, err := os.ReadFile(golden)
		if err != nil {
			t.Fatalf("%v (go test -run TestDoctorMulticallGolden -update writes it)", err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("doctor's multicall line differs from %s:\ngot:\n%s\nwant:\n%s", golden, got, want)
		}
	}
}
