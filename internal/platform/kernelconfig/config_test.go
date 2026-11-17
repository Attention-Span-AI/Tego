// SPDX-License-Identifier: Apache-2.0

package kernelconfig

import (
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type failedReader struct{}

func (failedReader) Read([]byte) (int, error) { return 0, errors.New("incomplete configuration") }

func TestRead(t *testing.T) {
	const text = "CONFIG_PREEMPT_VOLUNTARY=y\nCONFIG_LTO_CLANG=y\nCONFIG_SECURITY_TOMOYO_OMIT_USERSPACE_LOADER=y\n# CONFIG_PREEMPT is not set\n"
	var compressed bytes.Buffer
	w := gzip.NewWriter(&compressed)
	if _, err := w.Write([]byte(text)); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		data []byte
		ok   bool
	}{
		{"plain", []byte(text), true}, {"valid.gz", compressed.Bytes(), true},
		{"invalid.gz", []byte(text), false}, {"truncated.gz", compressed.Bytes()[:compressed.Len()-4], false},
		{"empty", nil, false}, {"stub", []byte("no configuration"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), tc.name)
			if err := os.WriteFile(p, tc.data, 0o600); err != nil {
				t.Fatal(err)
			}
			cfg, ok := Read(p)
			if ok != tc.ok || (ok && (!cfg["CONFIG_SECURITY_TOMOYO_OMIT_USERSPACE_LOADER"] || !cfg["CONFIG_LTO_CLANG"] || cfg["CONFIG_PREEMPT"])) {
				t.Fatalf("%v,%t", cfg, ok)
			}
		})
	}
	if _, ok := Read(filepath.Join(t.TempDir(), "missing")); ok {
		t.Fatal("missing config accepted")
	}
	if _, ok := Scan(io.MultiReader(strings.NewReader(text), failedReader{})); ok {
		t.Fatal("partial config accepted")
	}
}
