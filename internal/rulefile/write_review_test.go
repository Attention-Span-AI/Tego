// SPDX-License-Identifier: Apache-2.0

package rulefile

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestWriterRefusesWhenPublicationReviewChanges(t *testing.T) {
	for _, replace := range []bool{false, true} {
		name := "create"
		if replace {
			name = "replace"
		}
		t.Run(name, func(t *testing.T) {
			g, path := fixture(t)
			if !replace {
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			}
			changed := errors.New("review changed")
			calls := 0
			g.BeforePublish = func() error { calls++; return changed }
			var err error
			if replace {
				_, err = Replace(context.Background(), g, path, Sum([]byte(textA)), []byte(textB), Change{})
			} else {
				_, err = Create(context.Background(), g, path, []byte(textB), Change{})
			}
			if !errors.Is(err, changed) || calls != 1 {
				t.Fatalf("publication review calls=%d, err=%v", calls, err)
			}
			if replace {
				if got := mustRead(t, path); got != textA {
					t.Fatalf("changed review replaced old bytes: %q", got)
				}
			} else if _, err = os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("changed review created final file: %v", err)
			}
			entries, err := os.ReadDir(filepath.Dir(path))
			if err != nil {
				t.Fatal(err)
			}
			for _, entry := range entries {
				if entry.Name() != filepath.Base(path) && entry.Name() != filepath.Base(path)+".bak" {
					t.Errorf("temporary file left: %s", entry.Name())
				}
			}
		})
	}
}
