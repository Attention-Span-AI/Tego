// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"errors"
	"strings"
	"testing"

	ebpfbindings "github.com/attention-span-ai/tego/internal/bpf"
)

// TestBuildHashNamesTheOneRemedy: a binary without the objects that reaches Prepare names BuildFix, the
// remedy internal/runtime/enforce.Buildable and so `tego doctor` give for the same condition. The two
// used to differ ("make gen, then make build-bpf" against "the objects are committed"), and bpf/README.md
// settles it: the bpf2go output is committed, so `make build-bpf` needs no `make gen`.
func TestBuildHashNamesTheOneRemedy(t *testing.T) {
	if ebpfbindings.Available() {
		t.Skip("this test binary embeds the objects; the refusal is an untagged build's")
	}
	_, err := New(Options{}).buildHash()
	if !errors.Is(err, ErrProgramLoad) || !strings.Contains(err.Error(), BuildFix) {
		t.Errorf("buildHash without the objects: %v, want ErrProgramLoad naming %q", err, BuildFix)
	}
	if strings.Contains(BuildFix, "make gen,") || !strings.Contains(BuildFix, "make build-bpf") {
		t.Errorf("BuildFix %q: the objects are committed, so the remedy is make build-bpf alone", BuildFix)
	}
}
