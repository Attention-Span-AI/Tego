// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// TestTestTableDirKey: a filesystem row's `dir: true` makes its object a directory (Action.Dir, ADR 0043: a name
// entry never decides one, and a directory rename is asked D5); RunResolved sets it for a row whose path exists as a
// directory; a value other than true or false is a schema error.
func TestTestTableDirKey(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "file"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	tab, ds, err := LoadTestTableBytes("t.yaml", []byte(`version: 0
tests:
  - action: fs.rename
    path: later
    dest: elsewhere
    dir: true
    expect: allow
  - action: fs.rename
    path: sub
    dest: sub2
    expect: allow
  - action: fs.read
    path: file
    expect: allow
`))
	if err != nil {
		t.Fatalf("%v\n%s", err, render(ds))
	}
	var got []bool
	eval := func(_ *RuleTable, a Action, _ backend.Tier) EvalResult {
		got = append(got, a.Dir)
		return EvalResult{Verdict: VerdictAllow}
	}
	tab.RunResolved(eval, &RuleTable{Tier: backend.TierBPFLSM}, dir, evalLanders, backend.TierBPFLSM)
	if len(got) != 3 || !got[0] || !got[1] || got[2] {
		t.Errorf("Dir per row = %v, want the declared directory, the existing one, and a file", got)
	}
	if !tab.Rows[0].Dir || tab.Rows[1].Dir {
		t.Errorf("rows %+v", tab.Rows)
	}
	if _, _, err := LoadTestTableBytes("t.yaml", []byte("version: 0\ntests:\n  - action: fs.read\n    path: x\n    dir: maybe\n    expect: allow\n")); err == nil {
		t.Error("dir: maybe loaded")
	}
}
