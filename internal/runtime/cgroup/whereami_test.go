// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/platform/whereami"
)

// This package's tests describe a host unless a test says where it is.
func init() { whereami.Here = func() whereami.Kind { return whereami.Host } }

// TestDelegationRemedyByPlace: the refusal of a uid with no delegated subtree carries the delegation fix on a host and
// on WSL, byte for byte what v0.2.0-rc.1 printed, and the container's cure in a container.
func TestDelegationRemedyByPlace(t *testing.T) {
	const hostFix = "enable systemd user delegation (Delegate=cpu memory pids in " +
		"/etc/systemd/system/user@.service.d/delegate.conf, then systemctl daemon-reload and re-login)"
	for _, c := range []struct {
		name string
		kind whereami.Kind
		want string
	}{{"host", whereami.Host, hostFix}, {"WSL", whereami.WSL, hostFix}, {"container", whereami.Container, whereami.ContainerCgroupCure}} {
		t.Run(c.name, func(t *testing.T) {
			was := whereami.Here
			whereami.Here = func() whereami.Kind { return c.kind }
			t.Cleanup(func() { whereami.Here = was })
			missing := filepath.Join(t.TempDir(), "user.slice", "user-1000.slice", "user@1000.service")
			_, err := firstWritable(1000, []string{missing})
			var de *DetectError
			if !errors.As(err, &de) || !errors.Is(err, ErrNotDelegated) {
				t.Fatalf("firstWritable = %v, want a DetectError for ErrNotDelegated", err)
			}
			if de.Remedy != c.want {
				t.Errorf("remedy %q, want %q", de.Remedy, c.want)
			}
			if !strings.HasSuffix(err.Error(), "; fix: "+c.want) {
				t.Errorf("the refusal reads %q", err.Error())
			}
		})
	}
}
