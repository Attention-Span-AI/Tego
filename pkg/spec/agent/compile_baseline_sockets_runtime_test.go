// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"os"
	"path/filepath"
	"testing"
)

func TestBaselineSocketsKeepsDNSBrokerGrant(t *testing.T) {
	// newDNSDirectory verifies /tmp before creating the run-owned broker there.
	// This test models that published grant; it creates no host runtime socket.
	mountinfo := filepath.Join(t.TempDir(), "mountinfo")
	if err := os.WriteFile(mountinfo, []byte("1 0 0:1 / / rw - ext4 fixture rw\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	rt := &RuleTable{
		Baseline: &BaselineTable{Applied: true, Entries: []BaselineRule{{}}, MountInfo: mountinfo},
		Builtins: &BuiltinRefusals{Runtime: []string{"/run/user/1234"}},
		Net: []NetRule{{
			Raw: "unix:/tmp/tego-dns-fixture/resolver.sock", Proto: ProtoUnix,
			UnixPath: "/tmp/tego-dns-fixture/resolver.sock", Static: true,
			Verdict: VerdictAllow, Runtime: DNSBrokerGrant,
		}},
	}
	if err := rt.ValidateBaselineSockets(); err != nil {
		t.Fatalf("ordinary verified-/tmp broker grant refused: %v", err)
	}
	// Runtime provenance cannot make an actual host-IPC endpoint an exception.
	rt.Net[0].UnixPath = "/run/user/1234/bus"
	rt.Net[0].Raw = "unix:" + rt.Net[0].UnixPath
	if err := rt.ValidateBaselineSockets(); err == nil {
		t.Fatal("runtime marker bypassed protected host-IPC classification")
	}
}
