// SPDX-License-Identifier: Apache-2.0

package record

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// runIdentityKeys are run_start's ADR 0073 keys, in the order the README lists them.
var runIdentityKeys = []string{"launcher_uid", "launcher_user", "sudo_uid", "sudo_user", "host", "parent_run", "labels",
	"role", "contract_revision"}

// TestReadmeNamesTheRunIdentityMinor: the record README documents the run identity at the revision the writer stamps,
// by the constant's name and its number, and lists every key of it in its own entry.
func TestReadmeNamesTheRunIdentityMinor(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "spec", "record", "v1", "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	want := "At `record_minor` " + strconv.Itoa(MinorRunIdentity) + " (`MinorRunIdentity`;"
	i := strings.Index(string(b), want)
	if i < 0 {
		t.Fatalf("spec/record/v1/README.md does not name the run identity's revision as %q", want)
	}
	section := string(b[i:min(len(b), i+4000)])
	if end := strings.Index(section, "Fixture: `fixtures/run-identity.jsonl`."); end < 0 {
		t.Fatal("the run identity paragraph names no fixture/run-identity.jsonl")
	} else {
		section = section[:end]
	}
	for _, k := range runIdentityKeys {
		if !strings.Contains(section, "\n- `"+k+"`") && !strings.Contains(section, " and `"+k+"`") {
			t.Errorf("the run identity paragraph has no entry for %s", k)
		}
	}
}

// TestRunIdentityFixture: run-identity.jsonl is a run at record_minor 17 whose run_start carries every run identity
// key, a root launcher's sudo_uid included, read through Decode and Validate alone.
func TestRunIdentityFixture(t *testing.T) {
	events := readFixture(t, "run-identity.jsonl")
	var p RunStartPayload
	if len(events) < 2 || events[0].Kind != KindRunStart || events[0].DecodePayload(&p) != nil {
		t.Fatalf("no run_start: %+v", events)
	}
	if p.RecordMinor != MinorRunIdentity || p.LauncherUID == nil || *p.LauncherUID != 0 || p.LauncherUser != "root" ||
		p.SudoUID == nil || *p.SudoUID != 1000 || p.SudoUser != "u" || p.Host == "" || p.ParentRun == "" ||
		len(p.Labels) != 2 || p.Role != "check" || p.ContractRevision == "" {
		t.Fatalf("run_start = %+v", p)
	}
	line := string(events[0].Payload)
	for _, k := range runIdentityKeys {
		if !strings.Contains(line, `"`+k+`":`) {
			t.Errorf("run_start has no %s: %s", k, line)
		}
	}
	if last := events[len(events)-1]; last.Kind != KindRunEnd {
		t.Fatalf("the fixture ends with %s, want run_end", last.Kind)
	}
}

// TestFixturesAtRunIdentityCarryLauncherUID: every frozen fixture whose run_start is at MinorRunIdentity or later
// carries launcher_uid, which that revision writes on every run (absent there is a writer fault, ADR 0073), so no
// fixture of a later revision (the held-reads run at 18, ADR 0069) shows readers a run_start no writer makes.
func TestFixturesAtRunIdentityCarryLauncherUID(t *testing.T) {
	names, err := filepath.Glob(filepath.Join(fixturesDir, "*.jsonl"))
	if err != nil || len(names) == 0 {
		t.Fatalf("no fixtures under %s (%v)", fixturesDir, err)
	}
	n := 0
	for _, name := range names {
		for _, e := range readFixture(t, filepath.Base(name)) {
			var p RunStartPayload
			if e.Kind != KindRunStart || e.DecodePayload(&p) != nil || p.RecordMinor < MinorRunIdentity {
				continue
			}
			n++
			if p.LauncherUID == nil {
				t.Errorf("%s: run_start at record_minor %d has no launcher_uid", filepath.Base(name), p.RecordMinor)
			}
		}
	}
	if n < 2 {
		t.Fatalf("%d run_starts at record_minor %d or later, want the run identity and held-reads runs", n, MinorRunIdentity)
	}
}
