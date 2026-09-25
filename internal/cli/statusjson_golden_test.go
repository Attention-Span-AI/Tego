// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// statusVolatile is every value of a status --json object that changes from one test run to the next: the run
// id and the times. The golden file holds the rest byte for byte, the key order included (R31).
var statusVolatile = []struct {
	re   *regexp.Regexp
	with string
}{
	{regexp.MustCompile(`"run":"r-[0-9a-z-]+"`), `"run":"<run>"`},
	{regexp.MustCompile(`"since_ts":"[^"]*"`), `"since_ts":"<ts>"`},
	{regexp.MustCompile(`"since_mono_ns":[0-9]+`), `"since_mono_ns":<mono>`},
	{regexp.MustCompile(`"idle_s":[0-9.e+-]+`), `"idle_s":<idle>`},
	{regexp.MustCompile(`"ledger_bytes":[0-9]+`), `"ledger_bytes":<bytes>`},
}

// TestStatusJSONGolden pins status --json's object for an ended run, and in it limits-check-doctor-cli.md §6 case 9 (E9)'s field:
// tego_version is the run's own, from run_start ("test" in the fixture), never this binary's version.
func TestStatusJSONGolden(t *testing.T) {
	root := gcRoot(t)
	id := endedRun(t, root, time.Now())
	code, out, errs := run(t, "status", id, "--json")
	if code != identity.ExitOK {
		t.Fatalf("exit %d: %s", code, errs)
	}
	for _, v := range statusVolatile {
		out = v.re.ReplaceAllString(out, v.with)
	}
	golden := filepath.Join("testdata", "status-json.golden")
	if *updateGolden {
		if err := os.WriteFile(golden, []byte(out), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("%v (go test -run TestStatusJSONGolden -update writes it)", err)
	}
	if out != string(want) {
		t.Fatalf("status --json differs from %s:\ngot:  %s\nwant: %s", golden, out, want)
	}
}
