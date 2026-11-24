// SPDX-License-Identifier: Apache-2.0

package web

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ledgerRun writes one run: a run_start at start, the lines build adds, and a run_end with endBody at end (none when
// endBody is empty, which is a run that is still going or was lost).
func ledgerRun(t *testing.T, root, id, agent string, start time.Time, endBody string, end time.Time, build func(add func(at time.Time, kind, body string))) {
	t.Helper()
	var b strings.Builder
	seq := 0
	add := func(at time.Time, kind, body string) {
		fmt.Fprintf(&b, `{"v":1,"seq":%d,"id":"%064x","prev":"","ts":%q,"run":%q,"agent":%q,"pid":7,"tid":7,"cgroup":1,"mono_ns":%d,"source":"supervisor","kind":%q,%s}`+"\n",
			seq, seq+1, at.Format(time.RFC3339Nano), id, agent, seq+1, kind, body)
		seq++
	}
	add(start, "run_start", `"tier":"observe","command":["sh"]`)
	build(add)
	if endBody != "" {
		add(end, "run_end", endBody)
	}
	if err := os.MkdirAll(filepath.Join(root, id), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, id, "events.jsonl"), []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
}
