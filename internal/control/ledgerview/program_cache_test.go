// SPDX-License-Identifier: Apache-2.0

package ledgerview

import (
	"fmt"
	"testing"
	"time"
)

// TestProgramIndexOfManyRunsIsKept: the program index of every run a Logs page reads is kept, whatever the number
// of runs. A cache that dropped all its entries when it passed a fixed count made a page over more runs than that
// walk every line of every run again on each request: asked twice over the same runs, the second answers must be
// the first's slices, not a rebuild.
func TestProgramIndexOfManyRunsIsKept(t *testing.T) {
	const runs = 150
	root := t.TempDir()
	ids := make([]string, runs)
	for i := range ids {
		ids[i] = fmt.Sprintf("r-3f9c2a1b-%013d-pidx%02d", i, i%100)
		x := &xrun{root: root, run: ids[i], start: time.Date(2026, 10, 26, 3, 38, 51, 0, time.UTC)}
		x.add(100, `"kind":"run_start","source":"supervisor","command":["codex"],"cwd":"/home/u/proj","tier":"landlock","launcher_pid":100,"launcher_start_ns":5,"launcher_uid":1000,"launcher_user":"alice"`)
		x.exec(200, 6, "100/5", false, "codex", "--no-daemon")
		writeRun(t, root, ids[i], x.lines...)
	}
	st := Open(root)
	var first [runs]*int32
	pass := func(check bool) {
		for i, id := range ids {
			r, err := st.Run(id)
			if err != nil {
				t.Fatal(err)
			}
			_, _, of := r.progsFull()
			if len(of) != 2 || of[1] < 0 {
				t.Fatalf("%s: program index %v, want the exec's program on line 1", id, of)
			}
			if !check {
				first[i] = &of[0]
			} else if first[i] != &of[0] {
				t.Errorf("%s: the program index was built again on the second pass", id)
			}
		}
	}
	pass(false)
	pass(true)
}
