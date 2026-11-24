// SPDX-License-Identifier: Apache-2.0

package tego_test

import (
	"bytes"
	"embed"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// Embedding makes the delegated permission regression testable with go test
// -overlay, including workflows that GitHub rejects before running any job.
//
//go:embed .github/workflows/ci-receipt.yml
var receiptWorkflow []byte

//go:embed action/scripts/signing.py action/scripts/sign.sh action/scripts/check.sh action/scripts/eligibility.py action/TEST-PLAN.md
var signingSources embed.FS

func TestSigningPlanNamesCryptographicCoverage(t *testing.T) {
	data, err := signingSources.ReadFile("action/TEST-PLAN.md")
	if err != nil {
		t.Fatal(err)
	}
	text := strings.Join(strings.Fields(string(data)), " ")
	for _, fact := range []string{
		"`TestPublicReleaseBundleShape` parses",
		"boundary fixtures substitute a successful cosign operation",
		"does not perform successful cryptographic verification",
		"separate manual scratch measurement",
	} {
		if !strings.Contains(text, fact) {
			t.Errorf("signing plan lacks coverage limit %q", fact)
		}
	}
}

// Run the committed offline scripts against embedded production sources. An
// overlay of either signing source therefore exercises the real regression
// harness without changing files in the checkout.
func TestSigningOfflineRegressions(t *testing.T) {
	root := t.TempDir()
	for _, dir := range []string{"action", ".github/workflows"} {
		err := filepath.WalkDir(dir, func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() && entry.Name() == "__pycache__" {
				return filepath.SkipDir
			}
			dst := filepath.Join(root, path)
			if entry.IsDir() {
				return os.MkdirAll(dst, 0o700)
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			return os.WriteFile(dst, data, 0o700)
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"action/scripts/signing.py", "action/scripts/sign.sh", "action/scripts/check.sh", "action/scripts/eligibility.py"} {
		data, err := signingSources.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, name), data, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, ".github/workflows/ci-receipt.yml"), receiptWorkflow, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, script := range []string{"signing-policy-tests.py", "signing-tests.py"} {
		t.Run(script, func(t *testing.T) {
			cmd := exec.Command("/usr/bin/python3", "-I", filepath.Join(root, "action/test", script))
			cmd.Env = append(os.Environ(), "WORK="+root, "ACTION_UNDER_TEST="+filepath.Join(root, "action"))
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("%v\n%s", err, out)
			}
		})
	}
}

func TestUnsignedReceiptNeedsNoOIDCPermission(t *testing.T) {
	if bytes.Contains(receiptWorkflow, []byte("id-token")) {
		t.Fatal("unsigned reusable workflow delegates OIDC authority")
	}
	var workflow struct {
		Jobs map[string]struct {
			Permissions map[string]string
		}
	}
	if err := yaml.Unmarshal(receiptWorkflow, &workflow); err != nil {
		t.Fatal(err)
	}
	if len(workflow.Jobs) != 2 {
		t.Fatalf("unsigned workflow has %d jobs, want agent and report", len(workflow.Jobs))
	}
	for _, name := range []string{"agent", "report"} {
		job, ok := workflow.Jobs[name]
		if !ok {
			t.Fatalf("missing %s", name)
		}
		for permission, value := range job.Permissions {
			if value != "read" || (permission != "contents" && permission != "actions") {
				t.Errorf("%s requests %s: %s", name, permission, value)
			}
		}
	}
}
