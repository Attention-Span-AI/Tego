// SPDX-License-Identifier: Apache-2.0

package rulefile

import (
	"context"
	"errors"
	"os"
	"testing"
)

func TestReplaceRefusesSameBytesOnDifferentInode(t *testing.T) {
	g, path := fixture(t)
	setHook(t, func(s string) error {
		if s != "temp" {
			return nil
		}
		if err := os.Rename(path, path+".reviewed"); err != nil {
			return err
		}
		return os.WriteFile(path, []byte(textA), 0600)
	})
	if _, err := Replace(context.Background(), g, path, Sum([]byte(textA)), []byte(textB), Change{}); !errors.Is(err, ErrStale) {
		t.Fatalf("replaced a different inode with identical bytes: %v", err)
	}
	if got := mustRead(t, path); got != textA {
		t.Fatalf("replacement identity lost: %q", got)
	}
}
