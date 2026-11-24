// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"errors"
	"os"
	"strings"
	"syscall"
	"testing"
)

type failingProfileRead struct{ cause error }

func (p failingProfileRead) Resolve(string) (string, []byte, error) {
	return "", nil, &os.PathError{Op: "read", Path: "/profiles/base.yaml", Err: p.cause}
}

func TestProfileReadFailureKeepsCause(t *testing.T) {
	const text = "version: 0\nname: demo\ncommand: [sh]\nextends: base\n"
	// A missing profile must still be distinct from a missing top-level file.
	_, _, missing := LoadBytes("agent.yaml", []byte(text), failingProfileRead{os.ErrNotExist})
	if errors.Is(missing, os.ErrNotExist) || !errors.Is(missing, ErrProfileNotFound) {
		t.Fatalf("missing-profile control: %v", missing)
	}
	for _, cause := range []error{syscall.EIO, syscall.ENOTCONN, context.DeadlineExceeded} {
		t.Run(cause.Error(), func(t *testing.T) {
			_, ds, err := LoadBytes("agent.yaml", []byte(text), failingProfileRead{cause})
			if !errors.Is(err, cause) || !errors.Is(err, ErrProfileNotFound) || !errors.Is(err, ErrInvalidContract) {
				t.Fatalf("load lost profile read cause %v: %v", cause, err)
			}
			if len(ds) != 1 || !strings.Contains(ds[0].Fix, cause.Error()) || strings.Contains(ds[0].Error(), cause.Error()) {
				t.Fatalf("cause changed diagnostic words: %+v", ds)
			}
		})
	}
}
