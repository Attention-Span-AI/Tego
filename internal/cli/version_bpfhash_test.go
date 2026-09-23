// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"
	"runtime/debug"
	"testing"

	ebpfbindings "github.com/attention-span-ai/tego/internal/bpf"
)

// TestVersionReportsTheEmbeddedBPFHash is R30's bpf_hash: the hash of the objects the binary embeds, and
// "none" only for a build without them. It was hard-coded "none", so a tegobpf build could not be told
// from an untagged one and run_start of a tier-2 run carried no hash.
func TestVersionReportsTheEmbeddedBPFHash(t *testing.T) {
	prev := embeddedBPFHash
	t.Cleanup(func() { embeddedBPFHash = prev })

	embeddedBPFHash = func() (string, error) { return "0123456789abcdef", nil }
	if got := buildInfo(func() (*debug.BuildInfo, bool) { return nil, false }).BPFHash; got != "0123456789abcdef" {
		t.Errorf("a build with objects reports bpf_hash %q", got)
	}
	if got := runBuild().BPFHash; got != "0123456789abcdef" {
		t.Errorf("run_start is handed %q, want the build's hash", got)
	}

	embeddedBPFHash = func() (string, error) {
		return "", fmt.Errorf("%w: test", ebpfbindings.ErrNotGenerated)
	}
	if got := buildInfo(func() (*debug.BuildInfo, bool) { return nil, false }).BPFHash; got != none {
		t.Errorf("a build without objects reports bpf_hash %q, want %q", got, none)
	}
	if got := runBuild().BPFHash; got != "" {
		t.Errorf("run_start is handed %q, want empty rather than the word none", got)
	}
}

// TestVersionBPFHashIsThisBuilds ties the seam to the binary under test.
func TestVersionBPFHashIsThisBuilds(t *testing.T) {
	got := buildInfo(debug.ReadBuildInfo).BPFHash
	want, err := ebpfbindings.Hash()
	if err != nil {
		want = none
	}
	if got != want {
		t.Errorf("bpf_hash %q, want %q (objects embedded: %v)", got, want, ebpfbindings.Available())
	}
}
