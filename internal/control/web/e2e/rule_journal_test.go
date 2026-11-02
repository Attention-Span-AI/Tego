// SPDX-License-Identifier: Apache-2.0

//go:build integration

package e2e

import (
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/rulefile"
)

// The rule-change journal across the two real binaries: a real run at tier landlock runs /bin/cat once, and `tego
// rule <run> <line> --block` in a terminal (the tego binary under the world's machine config) turns that line into a
// rule of the contract. Its journal line is read where the dashboard reads it, <ledger_root>/.rule-changes; then
// tego-control serve lists the change in the rules file's History, in words and narrowing, and a person undoes it
// there through the rule service. The file gets its exact old text back, and the journal holds the change and its
// undo, each with its sentence and direction. The journal's other tests write it in process
// (TestRuleBlockWritesAndBacksUp, the rulefile and rules packages) or through the dashboard alone
// (TestRulesChangeJourney, TestDemoNeverAllow).

// journalContract lets the agent run /bin/sh and /bin/cat and write under out/.
const journalContract = `version: 0
name: e2e-journal
command: ["/bin/sh"]
tier: landlock
fs:
  write: ["./out/"]
exec:
  allow: ["/bin/sh", "/bin/cat"]
net: {}
env:
  pass: ["PATH", "HOME"]
limits:
  pids: 64
record: summary
`

// TestRuleJournalFromTheTerminalUndoneOnTheDashboard is the journey in the file comment.
func TestRuleJournalFromTheTerminalUndoneOnTheDashboard(t *testing.T) {
	outsideEveryRun(t)
	if os.Geteuid() == 0 {
		t.Skip("tego-control refuses to run as root (the dashboard runs as the user)")
	}
	w := newWorld(t)
	contract := filepath.Join(w.proj, "journal.yaml")
	write(t, contract, journalContract, 0o600)

	run := exec.Command(w.tego, "run", contract, "--", "/bin/sh", "-c", "/bin/cat journal.yaml > out/copy.txt")
	run.Dir, run.Env = w.proj, w.env
	if out, err := run.CombinedOutput(); err != nil {
		t.Fatalf("tego run: %v\n%s", err, out)
	}
	id := runID(w.ledger)
	seq := 0
	for _, l := range kindsOf(ledgerOf(t, w.ledger, id), "exec") {
		if l.Payload["path"] == "/bin/cat" && l.Verdict == "allow" {
			seq = l.Seq
		}
	}
	if seq == 0 {
		t.Fatalf("run %s records no allowed exec of /bin/cat:\n%s", id, rawOf(ledgerOf(t, w.ledger, id)))
	}

	rule := exec.Command(w.tego, "rule", id, strconv.Itoa(seq), "--block")
	rule.Dir, rule.Env = w.proj, w.env
	if out, err := rule.CombinedOutput(); err != nil || !strings.Contains(string(out), "will refuse to run /bin/cat") {
		t.Fatalf("tego rule %s %d --block: %v\n%s", id, seq, err, out)
	}
	blocked, err := os.ReadFile(contract)
	if err != nil || strings.Contains(string(blocked), "/bin/cat") {
		t.Fatalf("after tego rule the contract is (%v)\n%s", err, blocked)
	}

	// The journal is the ledger root's, this user's alone (a set-group-id bit inherited from the folder above is
	// not compared), and its line says the change as the dashboard's own would.
	journal := filepath.Join(w.ledger, rulefile.JournalDirName)
	for p, mode := range map[string]os.FileMode{
		journal: os.ModeDir | 0o700,
		filepath.Join(journal, rulefile.BlobsDir):    os.ModeDir | 0o700,
		filepath.Join(journal, rulefile.JournalFile): 0o600,
	} {
		if st, err := os.Lstat(p); err != nil || st.Mode()&(os.ModeType|os.ModePerm) != mode {
			t.Errorf("%s: %v (%v), want mode %v", p, st, err, mode)
		}
	}
	es, err := rulefile.ReadJournal(w.ledger)
	if err != nil || len(es) != 1 {
		t.Fatalf("the journal after tego rule: %+v (%v), want its one change", es, err)
	}
	change := es[0]
	said := "May run /bin/cat → Cannot run /bin/cat"
	if change.Op != rulefile.OpChange || change.Via != "cli" || change.UID != os.Geteuid() || change.Contract != contract ||
		change.Run != id || change.Line != uint64(seq) || change.Bak != contract+".bak" ||
		change.OldSHA256 != rulefile.Sum([]byte(journalContract)) || change.NewSHA256 != rulefile.Sum(blocked) ||
		change.Direction != "narrows" || !slices.Equal(change.Sentences, []string{said}) {
		t.Errorf("tego rule's journal line: %+v", change)
	}
	for sum, want := range map[string]string{change.OldSHA256: journalContract, change.NewSHA256: string(blocked)} {
		if b, err := rulefile.Blob(w.ledger, sum); err != nil || string(b) != want {
			t.Errorf("blob %s holds %q (%v), want %q", sum, b, err, want)
		}
	}

	b := serveDashboard(t, w)
	b.signIn()
	_, files := b.get("/rules/change")
	ref := regexp.MustCompile(`href="/rules/change\?c=([0-9a-f]+)"`).FindStringSubmatch(files)
	if ref == nil {
		t.Fatal("Change rules lists no rules file")
	}
	_, page := b.get("/rules/change?c=" + ref[1])
	b.readCSRF(page)
	rows := historyRows(page)
	if len(rows) != 1 || !strings.Contains(rows[0], " · cli</span>") ||
		!strings.Contains(rows[0], `<span class="rc-hwhat">`+said+`</span>`) || !strings.Contains(rows[0], ">Narrows</span>") {
		t.Fatalf("History lists %d rows, want the change tego rule made, via cli, said as %q, Narrows:\n%s", len(rows), said,
			strings.Join(rows, "\n"))
	}
	undo := regexp.MustCompile(`action="/rules/revert">.*name="c" value="([0-9a-f]+)"><input type="hidden" name="id" value="([^"]+)">` +
		`<input type="hidden" name="base" value="([0-9a-f]{64})"><label class="rc-ack-sm"><input type="checkbox" name="ack" value="([0-9a-f]{64})"`).
		FindStringSubmatch(rows[0])
	if undo == nil || undo[1] != ref[1] || undo[2] != change.ID || undo[3] != change.NewSHA256 {
		t.Fatalf("the History row's Undo is %q, want one of %s on the text it wrote, acknowledged (it widens)", undo, change.ID)
	}
	code, undone := b.post("/rules/revert", url.Values{"c": {undo[1]}, "id": {undo[2]}, "base": {undo[3]}, "ack": {undo[4]}})
	if code != http.StatusOK || !strings.Contains(undone, "Undone") {
		t.Fatalf("Undo: %d\n%s", code, undone)
	}

	// The file has its exact old text back, the .bak the text the Undo replaced, and the journal the Undo after the
	// change: by the dashboard, of that change, widening.
	if got, _ := os.ReadFile(contract); string(got) != journalContract {
		t.Errorf("after Undo the contract is\n%s\nwant\n%s", got, journalContract)
	}
	if got, _ := os.ReadFile(contract + ".bak"); string(got) != string(blocked) {
		t.Errorf("after Undo the .bak is\n%s\nwant the text tego rule wrote\n%s", got, blocked)
	}
	es, err = rulefile.ReadJournal(w.ledger)
	if err != nil || len(es) != 2 || es[0].ID != change.ID {
		t.Fatalf("the journal after Undo: %+v (%v), want the change and its undo", es, err)
	}
	if u := es[1]; u.Op != rulefile.OpRevert || u.Via != "dashboard" || u.Reverts != change.ID || u.Contract != contract ||
		u.OldSHA256 != change.NewSHA256 || u.NewSHA256 != change.OldSHA256 || u.Direction != "widens" {
		t.Errorf("the Undo's journal line: %+v", u)
	}
	_, page = b.get("/rules/change?c=" + ref[1])
	if rows = historyRows(page); len(rows) != 2 || !strings.Contains(rows[0], "Undid: Cannot run /bin/cat") ||
		!strings.Contains(rows[0], ">Widens</span>") || !strings.Contains(rows[1], `<span class="soft">Undone</span>`) {
		t.Errorf("History after Undo, want the undo (Undid: Cannot run /bin/cat, Widens) over the change marked Undone:\n%s",
			strings.Join(rows, "\n"))
	}
}

// historyRows is each row of a Change rules page's History, newest first, up to its closing tag.
func historyRows(page string) []string {
	var rows []string
	for _, r := range strings.Split(page, `<li class="rc-hrow">`)[1:] {
		row, _, _ := strings.Cut(r, "</li>")
		rows = append(rows, row)
	}
	return rows
}
