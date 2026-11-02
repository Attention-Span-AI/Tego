// SPDX-License-Identifier: Apache-2.0

package tego

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
)

// TestWriteLicensesPrintsTheTreesLicenceFiles (docs/GAPS.md B12): what the binaries print is every licence file of
// the tree, whole, under a line naming it: LICENSE, NOTICE and THIRD_PARTY_NOTICES.txt, then each text under
// LICENSES/ by name, and nothing else. The want is read from the files themselves, so a text added under LICENSES/ is
// one the binaries print without a change here.
func TestWriteLicensesPrintsTheTreesLicenceFiles(t *testing.T) {
	full, err := filepath.Glob(filepath.Join("LICENSES", "*.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if len(full) < 4 {
		t.Fatalf("LICENSES/ holds %v, want the GPL, BSD, LGPL and Lucide texts", full)
	}
	var want strings.Builder
	for i, name := range append([]string{"LICENSE", "NOTICE", "THIRD_PARTY_NOTICES.txt"}, full...) {
		b, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		if i > 0 {
			want.WriteString("\n")
		}
		want.WriteString("==> " + filepath.ToSlash(name) + " <==\n" + string(b))
		if !bytes.HasSuffix(b, []byte("\n")) {
			want.WriteString("\n")
		}
	}
	var got bytes.Buffer
	if err := WriteLicenses(&got); err != nil {
		t.Fatal(err)
	}
	if got.String() != want.String() {
		g, w := strings.Split(got.String(), "\n"), strings.Split(want.String(), "\n")
		for i := 0; i < len(g) && i < len(w); i++ {
			if g[i] != w[i] {
				t.Fatalf("line %d: got %q, want %q", i+1, g[i], w[i])
			}
		}
		t.Fatalf("got %d lines, want %d", len(g), len(w))
	}
	first, _, _ := strings.Cut(strings.TrimPrefix(got.String(), "==> LICENSE <==\n"), "\n==> ")
	if !strings.HasPrefix(got.String(), "==> LICENSE <==\n") || !strings.Contains(first, "Apache License") ||
		!strings.Contains(first, "Version 2.0, January 2004") {
		t.Fatalf("the print does not open with the Apache-2.0 text: %.160q", got.String())
	}
}

// TestWriteOrdersAndEndsEveryText: the lead files come first whatever their names sort as, the texts under LICENSES/
// follow by name, a file without a final newline gets one so the next name line starts a line, and a file of
// LICENSES/ that is not a .txt is no licence text.
func TestWriteOrdersAndEndsEveryText(t *testing.T) {
	fsys := fstest.MapFS{
		"THIRD_PARTY_NOTICES.txt": {Data: []byte("third\n")},
		"NOTICE":                  {Data: []byte("notice")},
		"LICENSE":                 {Data: []byte("licence\n")},
		"LICENSES/Zed.txt":        {Data: []byte("zed\n")},
		"LICENSES/Abc.txt":        {Data: []byte("abc")},
		"LICENSES/README.md":      {Data: []byte("readme\n")},
	}
	var got bytes.Buffer
	if err := write(&got, fsys); err != nil {
		t.Fatal(err)
	}
	want := "==> LICENSE <==\nlicence\n\n==> NOTICE <==\nnotice\n\n==> THIRD_PARTY_NOTICES.txt <==\nthird\n\n" +
		"==> LICENSES/Abc.txt <==\nabc\n\n==> LICENSES/Zed.txt <==\nzed\n"
	if got.String() != want {
		t.Fatalf("got\n%s\nwant\n%s", got.String(), want)
	}
}

// TestWriteReportsWhatFails: a lead file missing from the set, and a writer that refuses, are errors naming the file,
// never a short print that looks whole.
func TestWriteReportsWhatFails(t *testing.T) {
	fsys := fstest.MapFS{"LICENSE": {Data: []byte("licence\n")}, "THIRD_PARTY_NOTICES.txt": {Data: []byte("third\n")}}
	if err := write(&bytes.Buffer{}, fsys); err == nil || !strings.Contains(err.Error(), "NOTICE") {
		t.Fatalf("a set without NOTICE: %v, want an error naming it", err)
	}
	if err := WriteLicenses(refusing{}); !errors.Is(err, errRefused) || !strings.Contains(err.Error(), "LICENSE") {
		t.Fatalf("a refusing writer: %v, want %v naming LICENSE", err, errRefused)
	}
}

var errRefused = errors.New("refused")

// refusing is a writer every write fails on.
type refusing struct{}

func (refusing) Write([]byte) (int, error) { return 0, errRefused }
