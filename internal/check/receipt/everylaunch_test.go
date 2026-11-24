// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// baselineStart is the run_start of the applied-baseline fixture: a run with machine baseline evidence whose owner home
// is not any home these tests record.
func baselineStart(t *testing.T) record.RunStartPayload {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "spec", "record", "v1", "fixtures", "baseline", "applied.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	e, err := record.Decode(bytes.Split(data, []byte{'\n'})[0])
	if err != nil {
		t.Fatal(err)
	}
	var p record.RunStartPayload
	if err := e.DecodePayload(&p); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestReceiptFoldsUnderTheRunsRecordedHome (ADR 0157): from record minor 41 run_start names the home the run resolved,
// and the text receipt folds ~ under it for every new run. Where it is, it wins over the baseline evidence's owner home;
// without it the baseline's is used (a ledger at 39 or 40); with neither, every path prints whole and the text says so.
func TestReceiptFoldsUnderTheRunsRecordedHome(t *testing.T) {
	base := baselineStart(t)
	if !base.Baseline.OwnerKnown || !filepath.IsAbs(base.Baseline.Home) {
		t.Fatalf("the fixture records no owner home: %+v", base.Baseline)
	}
	const home = "/home/ada"
	plain := record.RunStartPayload{Tier: "landlock", Capture: "off", Command: []string{"sh"}, Cwd: "/p"}
	at41 := plain
	at41.RecordMinor, at41.Home = record.MinorEveryLaunch, home
	withBoth := base
	withBoth.RecordMinor, withBoth.Home = record.MinorEveryLaunch, home
	baselineOnly := base // revision 39: no run_start.home
	for _, c := range []struct {
		name  string
		start record.RunStartPayload
		under string // a path under this folds to ~, "" when none does
	}{
		{"a run at 41 with no baseline", at41, home},
		{"run_start.home before the baseline's owner home", withBoth, home},
		{"the baseline's owner home, at 39", baselineOnly, base.Baseline.Home},
		{"a record naming none", plain, ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			rc := compute(t, []line{{kind: record.KindRunStart, payload: c.start}, end(1, 0)}, Options{SayNoHome: true})
			var out bytes.Buffer
			if err := rc.Text(&out); err != nil {
				t.Fatal(err)
			}
			for _, h := range []string{home, base.Baseline.Home} {
				want := h + "/.ssh/id_rsa"
				if h == c.under {
					want = "~/.ssh/id_rsa"
				}
				if got := rc.ShortPath(h + "/.ssh/id_rsa"); got != want {
					t.Errorf("under %s: %q, want %q", h, got, want)
				}
			}
			if said := strings.Contains(out.String(), "does not name one"); said != (c.under == "") {
				t.Errorf("says the record names no home: %v, want %v\n%s", said, c.under == "", out.String())
			}
		})
	}
}

// TestReceiptListsANameBlocksAddresses (ADR 0157): a live block by name, or a restored fence entry by name, is listed with
// the addresses its line says it was enforced on, in the text; one whose line names none says the record does not say
// which; a block by address lists nothing. The JSON receipt is unchanged.
func TestReceiptListsANameBlocksAddresses(t *testing.T) {
	at := time.Date(2026, 11, 20, 9, 0, 0, 0, time.UTC)
	gap := func(why, op, rule, kind, value string, addrs []string, more int) line {
		return line{kind: record.KindGap, at: time.Second, payload: record.GapPayload{What: record.GapEnforce, Why: why,
			LiveBlock: &record.LiveBlockChange{Op: op, Kind: kind, Value: value, Rule: rule, By: "uid:1", Serial: 1, At: at, Addrs: addrs, AddrsMore: more}}}
	}
	lines := []line{
		{kind: record.KindRunStart, payload: record.RunStartPayload{Tier: "landlock", Capture: "off", Command: []string{"sh"}, Cwd: "/p", RecordMinor: record.MinorEveryLaunch}},
		gap(record.GapLiveBlockAdded, "add", "live.block[net:example.com:443]", "net", "example.com:443", []string{"2001:db8::1", "93.184.216.34", "fe80::1%2"}[:], 0),
		gap(record.GapLiveBlockAdded, "add", "live.block[net:nolookup.example]", "net", "nolookup.example", nil, 0),
		gap(record.GapLiveBlockAdded, "add", "live.block[net:93.184.216.35:443]", "net", "93.184.216.35:443", nil, 0),
		gap(record.GapLiveRuleRestored, "restore", "live.fence[net:api.example.com:443]", "net", "api.example.com:443", []string{"203.0.113.9"}, 7),
		gap(record.GapLiveBlockAdded, "add", "live.block[exec:/bin/ls]", "exec", "/bin/ls", nil, 0),
		end(2, 0),
	}
	rc := compute(t, lines, Options{})
	got := rc.NameBlocks()
	if len(got) != 3 || got[0].Name != "example.com:443" || strings.Join(got[0].Addrs, ",") != "93.184.216.34,2001:db8::1,fe80::1%2" ||
		got[1].Name != "nolookup.example" || len(got[1].Addrs) != 0 ||
		got[2].Name != "api.example.com:443" || got[2].More != 7 {
		t.Fatalf("name blocks %+v: want the three by name (not the one by address or the exec one), addresses sorted", got)
	}
	var out bytes.Buffer
	if err := rc.Text(&out); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"A live block on example.com:443 was enforced on 93.184.216.34, 2001:db8::1, fe80::1%2.",
		"A live block on nolookup.example refuses the addresses that name resolved to; the record does not say which.",
		"A live block on api.example.com:443 was enforced on 203.0.113.9 and 7 more not listed.",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("the receipt does not say %q:\n%s", want, out.String())
		}
	}
	if strings.Contains(out.String(), "93.184.216.35") {
		t.Errorf("a block by address is listed:\n%s", out.String())
	}
}

// TestReceiptListsALiftsNote (ADR 0125, amended 2026-11-23): a lift or a grant the launcher put in force with a note is
// listed in the text with the note as the terminal and the dashboard show it (record.LiveNoteShown); one with no note
// and a refused lift list nothing; the JSON receipt is unchanged by it.
func TestReceiptListsALiftsNote(t *testing.T) {
	at := time.Date(2026, 11, 23, 9, 0, 0, 0, time.UTC)
	gap := func(why, rule, note string) line {
		return line{kind: record.KindGap, at: time.Second, payload: record.GapPayload{What: record.GapEnforce, Why: why,
			LiveBlock: &record.LiveBlockChange{Op: "lift", Kind: "read", Value: "/srv/x", Rule: rule, By: "uid:1", Serial: 1, At: at, Note: note}}}
	}
	run := record.RunStartPayload{Tier: "landlock", Capture: "off", Command: []string{"sh"}, Cwd: "/p", RecordMinor: record.MinorEveryLaunch}
	with := []line{
		{kind: record.KindRunStart, payload: run},
		gap(record.GapLiveRuleLifted, "live.fence[read:/srv/x]", "ticket 4411\n\x1b[2J"),
		gap(record.GapLiveRuleLifted, "live.fence[read:/srv/y]", ""),
		end(2, 0),
	}
	without := []line{{kind: record.KindRunStart, payload: run}, gap(record.GapLiveRuleLifted, "live.fence[read:/srv/y]", ""), end(2, 0)}
	rc := compute(t, with, Options{})
	got := rc.LiftNotes()
	if len(got) != 1 || got[0].Rule != "live.fence[read:/srv/x]" || got[0].Note != record.LiveNoteShown("ticket 4411\n\x1b[2J") {
		t.Fatalf("lift notes %+v: want the one lift with a note, escaped", got)
	}
	var out bytes.Buffer
	if err := rc.Text(&out); err != nil {
		t.Fatal(err)
	}
	if want := "Lifted live.fence[read:/srv/x] with the note: ticket 4411\\n\\x1b[2J"; !strings.Contains(out.String(), want) {
		t.Errorf("the receipt does not say %q:\n%s", want, out.String())
	}
	if strings.ContainsAny(out.String(), "\x1b") {
		t.Errorf("the receipt carries an escape byte:\n%s", out.String())
	}
	if n := compute(t, without, Options{}).LiftNotes(); len(n) != 0 {
		t.Errorf("a lift with no note is listed: %+v", n)
	}
}
