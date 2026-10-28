// SPDX-License-Identifier: Apache-2.0

package ledgerview

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// adjustableStart is an Adjustable run's run_start: a read that is new access, a destination, and a program the
// contract refused.
const adjustableStart = `"tier":"cgroup","command":["sh"],"record_minor":25,"fs_reads":{"reads":"held","why":"contract"},` +
	`"live_mode":"adjustable","live_fence":{"sha256":"0a0a","entries":[` +
	`{"kind":"read","value":"/srv/exports","source":"new","rule":"live.fence[read:/srv/exports]"},` +
	`{"kind":"net","value":"api.stripe.com:443","source":"new","rule":"live.fence[net:api.stripe.com:443]"},` +
	`{"kind":"exec","value":"/usr/bin/psql","source":"deny","rule":"live.fence[exec:/usr/bin/psql]"}]}`

// fenceGap is a launcher's fence line.
func fenceGap(run string, seq int, ts time.Time, why, op, kind, value, by string, serial int, until, refused string) string {
	extra := ""
	if until != "" {
		extra += `,"until":"` + until + `"`
	}
	if refused != "" {
		extra += `,"refused":"` + refused + `"`
	}
	return line(run, "probe", seq, ts, "gap", fmt.Sprintf(
		`"what":"enforce","why":"%s","live_block":{"op":"%s","kind":"%s","value":"%s","rule":"live.fence[%s:%s]","by":"%s","serial":%d,"at":"2026-10-27T12:00:00Z"%s}`,
		why, op, kind, value, kind, value, by, serial, extra))
}

// TestFenceRows: the fence folds the launcher's lines: a lift (with and without a limit), its expiry, a person's
// restore, a refused lift, and the restore the launcher makes when the overlay cannot be read; a lift whose limit has
// passed by the page's clock is refused before its expiry line arrives; a Locked run has no rows.
func TestFenceRows(t *testing.T) {
	root := t.TempDir()
	t0 := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	const run = "r-aaaa-0001-adjust"
	by := "uid:1000 pid:9 dashboard"
	writeRun(t, root, run,
		line(run, "probe", 0, t0, "run_start", adjustableStart),
		// read: lifted for an hour, ended by its limit, lifted again for the rest of the run, then the overlay broke.
		fenceGap(run, 1, t0.Add(1*time.Second), "live-rule-lifted", "lift", "read", "/srv/exports", by, 1, "2026-10-27T13:00:00Z", ""),
		fenceGap(run, 2, t0.Add(2*time.Second), "live-lift-expired", "expire", "read", "/srv/exports", by, 1, "2026-10-27T13:00:00Z", ""),
		fenceGap(run, 3, t0.Add(3*time.Second), "live-rule-lifted", "lift", "read", "/srv/exports", by, 2, "", ""),
		fenceGap(run, 4, t0.Add(4*time.Second), "live-rule-restored", "restore", "read", "/srv/exports", FenceByOverlay, 2, "", ""),
		// net: lifted until 14:00, and a later lift refused (a replay): the lift stands.
		fenceGap(run, 5, t0.Add(5*time.Second), "live-rule-lifted", "lift", "net", "api.stripe.com:443", by, 3, "2026-10-27T14:00:00Z", ""),
		fenceGap(run, 6, t0.Add(6*time.Second), "live-lift-refused", "lift", "net", "api.stripe.com:443", by, 3, "", "mac"),
		// exec: lifted, then restored by a person.
		fenceGap(run, 7, t0.Add(7*time.Second), "live-rule-lifted", "lift", "exec", "/usr/bin/psql", by, 4, "", ""),
		fenceGap(run, 8, t0.Add(8*time.Second), "live-rule-restored", "restore", "exec", "/usr/bin/psql", "uid:1000 pid:9 cli", 5, "", ""),
		// A refused lift outside the fence has no row.
		fenceGap(run, 9, t0.Add(9*time.Second), "live-lift-refused", "lift", "read", "/etc", by, 6, "", "outside-fence"))
	r, err := LoadRun(root, run)
	if err != nil {
		t.Fatal(err)
	}
	rows := FenceRows(r, t0.Add(time.Minute))
	if len(rows) != 3 {
		t.Fatalf("rows %+v, want 3", rows)
	}
	read, net, exec := rows[0], rows[1], rows[2]
	if read.State != FenceRefused || read.Note != FenceNoteUnreadable || read.Source != "new" || !read.At.Equal(t0.Add(4*time.Second)) {
		t.Errorf("read row %+v: want refused again, the overlay unreadable", read)
	}
	until := time.Date(2026, 10, 27, 14, 0, 0, 0, time.UTC)
	if net.State != FenceLifted || !net.Until.Equal(until) || net.By != by || !strings.HasPrefix(net.Note, FenceNoteRefusedPrefix) ||
		!strings.Contains(net.Note, "replayed") {
		t.Errorf("net row %+v: want lifted until 14:00, with the refused replay noted", net)
	}
	if exec.State != FenceRefused || exec.Note != "" || exec.By != "uid:1000 pid:9 cli" || exec.Source != "deny" ||
		exec.Rule != "live.fence[exec:/usr/bin/psql]" {
		t.Errorf("exec row %+v: want refused by a person's restore", exec)
	}
	// By 14:00 the net lift has ended, though the launcher's expiry line is not there yet.
	if late := FenceRows(r, until); late[1].State != FenceRefused || late[1].Note != FenceNoteExpired {
		t.Errorf("net row at its limit %+v: want refused, ended", late[1])
	}
	const locked = "r-aaaa-0002-locked"
	writeRun(t, root, locked, line(locked, "probe", 0, t0, "run_start", `"tier":"cgroup","command":["sh"],"record_minor":25`))
	lr, err := LoadRun(root, locked)
	if err != nil {
		t.Fatal(err)
	}
	if rows := FenceRows(lr, t0); rows != nil {
		t.Errorf("a Locked run's rows %+v, want none", rows)
	}
	if FenceRows(nil, t0) != nil {
		t.Error("no run has rows")
	}
}

// TestFenceRowsExpiry: an expiry line refuses the entry again with its note, and the row's last change stays the lift
// (its time and who asked), since the time limit, not a person, ended it.
func TestFenceRowsExpiry(t *testing.T) {
	root := t.TempDir()
	t0 := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	const run = "r-aaaa-0003-expire"
	by := "uid:1000 pid:9 dashboard"
	writeRun(t, root, run,
		line(run, "probe", 0, t0, "run_start", adjustableStart),
		fenceGap(run, 1, t0.Add(time.Second), "live-rule-lifted", "lift", "exec", "/usr/bin/psql", by, 1, "2026-10-27T12:30:00Z", ""),
		fenceGap(run, 2, t0.Add(31*time.Minute), "live-lift-expired", "expire", "exec", "/usr/bin/psql", by, 1, "2026-10-27T12:30:00Z", ""))
	r, err := LoadRun(root, run)
	if err != nil {
		t.Fatal(err)
	}
	if rows := FenceRows(r, t0); rows[2].State != FenceRefused || rows[2].Note != FenceNoteExpired || !rows[2].Until.IsZero() ||
		!rows[2].At.Equal(t0.Add(time.Second)) || rows[2].By != by {
		t.Errorf("exec row %+v: want refused, ended by its limit, last changed by the lift at 12:00:01", rows[2])
	}
}

// TestFenceRowsRestoreBy: only the launcher's overlay restore gets the "could not trust the overlay" note; another
// restore of the launcher's own gets its words, and a person's, whatever its by looks like, gets none.
func TestFenceRowsRestoreBy(t *testing.T) {
	root := t.TempDir()
	t0 := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	const run = "r-aaaa-0004-restby"
	by := "uid:1000 pid:9 dashboard"
	writeRun(t, root, run,
		line(run, "probe", 0, t0, "run_start", adjustableStart),
		fenceGap(run, 1, t0.Add(1*time.Second), "live-rule-lifted", "lift", "read", "/srv/exports", by, 1, "", ""),
		fenceGap(run, 2, t0.Add(2*time.Second), "live-rule-restored", "restore", "read", "/srv/exports", "tego: the run is stopping", 1, "", ""),
		fenceGap(run, 3, t0.Add(3*time.Second), "live-rule-lifted", "lift", "net", "api.stripe.com:443", by, 2, "", ""),
		fenceGap(run, 4, t0.Add(4*time.Second), "live-rule-restored", "restore", "net", "api.stripe.com:443", "ops-bot", 3, "", ""))
	r, err := LoadRun(root, run)
	if err != nil {
		t.Fatal(err)
	}
	rows := FenceRows(r, t0.Add(time.Minute))
	if rows[0].State != FenceRefused || rows[0].Note != FenceNoteByTegoPrefix+"the run is stopping." {
		t.Errorf("read row %+v: want refused again in the launcher's words", rows[0])
	}
	if rows[1].State != FenceRefused || rows[1].Note != "" {
		t.Errorf("net row %+v: want refused again by a person, with no note", rows[1])
	}
}
