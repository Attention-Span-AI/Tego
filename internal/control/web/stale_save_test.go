// SPDX-License-Identifier: Apache-2.0

package web

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/control/ledgerview"
	"github.com/attention-span-ai/tego/internal/control/rules"
)

var (
	formBase = regexp.MustCompile(`<form class="panel rc-confirm"[^>]*>[\s\S]*?name="base" value="([0-9a-f]*)"`)
	formAck  = regexp.MustCompile(`<form class="panel rc-confirm"[\s\S]*?name="ack" value="([0-9a-f]*)"`)
)

func fileSum(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// TestStaleSaveRecovers: a Save refused because the rules file changed since the preview goes back to the
// preview without the refused base, which plans on the file as it is now: its form carries the file's sha256 now, and
// saving from it lands. A second POST of the same form (a double click) is not another refusal: the file already has
// the change, the page says so, and nothing more is written. The Save button posts as a plain form, so a browser with
// JavaScript gets the re-planned page too.
func TestStaleSaveRecovers(t *testing.T) {
	f := newChangeFix(t)
	ref := f.ref(t, f.source)
	edit := url.Values{"c": {ref.Ref}, "op": {"remove"}, "key": {"exec.allow"}, "v": {"git"}}
	q := url.Values{"base": {ref.Base}}
	for k, v := range edit {
		q[k] = v
	}
	code, preview := f.get(t, "/rules/change/preview?"+q.Encode())
	if code != http.StatusOK || !strings.Contains(preview, `type="submit" data-page>`) {
		t.Fatalf("preview %d, or its Save does not post as a plain form:\n%s", code, preview)
	}
	m := formBase.FindStringSubmatch(preview)
	if m == nil || m[1] != ref.Base {
		t.Fatalf("the preview's form base %v, want %s", m, ref.Base)
	}

	// The file changes on disk after the preview.
	if err := os.WriteFile(f.source, append([]byte(readText(t, f.source)), "# changed by hand\n"...), 0o600); err != nil {
		t.Fatal(err)
	}
	now := fileSum(t, f.source)
	save := url.Values{"base": {m[1]}}
	for k, v := range edit {
		save[k] = v
	}
	save.Set("csrf", f.s.csrf)
	w := post(f.s, "/rules/change", save, own, "", f.c)
	loc := w.Header().Get("Location")
	if w.Code != http.StatusSeeOther || !strings.HasPrefix(loc, "/rules/change/preview?") || strings.Contains(loc, "base=") {
		t.Fatalf("a stale Save answered %d %q, want a 303 to the preview without base=", w.Code, loc)
	}
	again := follow(t, f.s, f.c, w)
	if !strings.Contains(again, "changed since you looked") {
		t.Error("the re-planned preview does not say why nothing was written")
	}
	if strings.Contains(again, "The rules file changed since you opened the form") {
		t.Error("the re-planned preview says it twice (the flash and the stale banner)")
	}
	m = formBase.FindStringSubmatch(again)
	if m == nil || m[1] != now {
		t.Fatalf("the re-planned form's base %v, want the file's sha256 now %s", m, now)
	}

	save.Set("base", m[1])
	w = post(f.s, "/rules/change", save, own, "", f.c)
	if loc := w.Header().Get("Location"); w.Code != http.StatusSeeOther || !strings.HasPrefix(loc, "/rules/change/saved?") {
		t.Fatalf("the Save from the re-planned preview answered %d %q", w.Code, loc)
	}
	after := readText(t, f.source)
	if strings.Contains(after, "git]") || strings.Contains(after, "git,") || !strings.Contains(after, "# changed by hand") || journalLen(t, f.root) != 1 {
		t.Fatalf("the change did not land on the file as it was:\n%s", after)
	}

	// The same form posted again: the file already has the change.
	w = post(f.s, "/rules/change", save, own, "", f.c)
	loc = w.Header().Get("Location")
	if w.Code != http.StatusSeeOther || !strings.HasPrefix(loc, "/rules/change/preview?") || strings.Contains(loc, "base=") {
		t.Fatalf("the second POST answered %d %q", w.Code, loc)
	}
	body := follow(t, f.s, f.c, w)
	if !strings.Contains(body, "Already in the contract") || strings.Contains(body, "changed since you looked") {
		t.Errorf("the second POST's page does not say the file already has the change:\n%s", body)
	}
	if readText(t, f.source) != after || journalLen(t, f.root) != 1 {
		t.Error("the second POST wrote again")
	}
}

// TestStaleWideningGetsTheNewAck: a widening refused as stale comes back with the acknowledgement of the
// change planned on the file now (the old one is bound to the old text), and saving with it lands.
func TestStaleWideningGetsTheNewAck(t *testing.T) {
	f := newChangeFix(t)
	ref := f.ref(t, f.source)
	q := url.Values{"c": {ref.Ref}, "base": {ref.Base}, "op": {"add"}, "key": {"fs.write"}, "v": {"./more/"}}
	_, preview := f.get(t, "/rules/change/preview?"+q.Encode())
	old := formAck.FindStringSubmatch(preview)
	if old == nil {
		t.Fatalf("the widening's preview has no ack:\n%s", preview)
	}
	if err := os.WriteFile(f.source, append([]byte(readText(t, f.source)), "# changed by hand\n"...), 0o600); err != nil {
		t.Fatal(err)
	}
	q.Set("ack", old[1])
	q.Set("csrf", f.s.csrf)
	again := follow(t, f.s, f.c, post(f.s, "/rules/change", q, own, "", f.c))
	ack, base := formAck.FindStringSubmatch(again), formBase.FindStringSubmatch(again)
	if ack == nil || base == nil || ack[1] == old[1] || base[1] != fileSum(t, f.source) {
		t.Fatalf("the re-planned widening's ack %v base %v (old ack %s)", ack, base, old[1])
	}
	p, err := f.svc.PlanChange(context.Background(), rules.ChangeReq{Ref: ref.Ref, Edits: []rules.Edit{{Op: "add", Key: "fs.write", Entry: "./more/"}}})
	if err != nil || p.Ack != ack[1] {
		t.Fatalf("the form's ack is not the re-planned preview's: %v %v", p, err)
	}
	q.Set("ack", ack[1])
	q.Set("base", base[1])
	if loc := post(f.s, "/rules/change", q, own, "", f.c).Header().Get("Location"); !strings.HasPrefix(loc, "/rules/change/saved?") {
		t.Fatalf("the Save with the new ack went to %q", loc)
	}
	if !strings.Contains(readText(t, f.source), "./more/") {
		t.Error("the widening did not land")
	}
}

// TestUndoPostsAsAPlainForm: a refused Undo answers with the page it came from, read again (its base now), so every
// Undo button posts as a plain form, as Save does.
func TestUndoPostsAsAPlainForm(t *testing.T) {
	for _, name := range []string{"rules-parts.tmpl", "rules-saved.tmpl"} {
		b, err := assets.ReadFile("templates/" + name)
		if err != nil {
			t.Fatal(err)
		}
		for _, form := range regexp.MustCompile(`(?s)<form[^>]*action="/rules/revert".*?</form>`).FindAllString(string(b), -1) {
			if !regexp.MustCompile(`<button[^>]*type="submit" data-page>`).MatchString(form) {
				t.Errorf("%s: an Undo form whose button posts in the background:\n%s", name, form)
			}
		}
	}
}

// TestSavedPageSaysLiveNow: the Saved page says each "Also apply now" outcome's state on its run now, from
// the run's own record (the launcher's confirming gap line), with no reload: the page is its live region. The
// headline says "live now on <run> and from the next run" only once every placed block is in force there; an option
// with no live block, or a run whose box was not ticked, says "Next run" and why.
func TestSavedPageSaysLiveNow(t *testing.T) {
	for _, c := range []struct {
		name            string
		tier            string
		confirmed       uint64
		serial          uint64
		state, headline string
		chip            string
	}{
		{"before the launcher's line", "landlock", 0, 1, ledgerview.LiveWaiting, "Saved · from the next run; putting it in force on r-…askedx now", "Putting it in force"},
		{"confirmed", "landlock", 1, 1, ledgerview.LiveInForce, "Saved · live now on r-…askedx and from the next run", "Live now"},
		{"a watched run", "observe", 1, 1, ledgerview.LiveRecordedOnly, "Saved · applies from the next run", "Recorded only"},
	} {
		t.Run(c.name, func(t *testing.T) {
			s, _ := liveFixture(t, c.tier, c.confirmed)
			plan := &rules.ChangePlan{Ref: "00112233aabbccdd", Contract: "/p/agent.yaml", Agent: "demo", Direction: "narrows",
				Sentences: []rules.Sentence{{Before: "Asks you before it reads ./vault/", After: "Can never read ./vault/", Direction: "narrows"}},
				Now: []rules.NowOption{{Run: actRun, Kind: "read", Value: "/p/vault", Block: "read:/p/vault", OK: true, Cwd: "/p"},
					{Run: actRun, Change: "exec.allow -= git push", Why: "a command entry"},
					{Run: "r-other-run-0002", Kind: "read", Value: "/p/vault", Block: "read:/p/vault", OK: true, Cwd: "/p"}}}
			d := savedData{Ref: plan.Ref, Applied: &rules.Applied{Plan: plan, ID: "rc-1",
				Live: []rules.LiveResult{{Run: actRun, Block: "read:/p/vault", OK: true, Serial: c.serial}}}}
			s.settleSaved(&d)
			if d.Headline != c.headline {
				t.Errorf("headline %q, want %q", d.Headline, c.headline)
			}
			if len(d.Live) != 1 || d.Live[0].State != c.state || d.Live[0].Chip != c.chip || d.Live[0].Words != "Reads of ./vault" {
				t.Errorf("live %+v, want %s %q", d.Live, c.state, c.chip)
			}
			if c.state == ledgerview.LiveInForce && d.Live[0].After != " since line #1" {
				t.Errorf("in force: %q, want since line #1", d.Live[0].After)
			}
			if len(d.Next) != 2 || d.Next[0].Why != "a command entry" || !strings.Contains(d.Next[1].Why, "not ticked") {
				t.Errorf("next %+v", d.Next)
			}
		})
	}
	// Nothing applied now: the next run only.
	s, _ := liveFixture(t, "landlock", 0)
	d := savedData{Applied: &rules.Applied{Plan: &rules.ChangePlan{}}}
	s.settleSaved(&d)
	if d.Headline != "Saved · applies from the next run" || d.Live != nil || d.Next != nil {
		t.Errorf("nothing applied now: %+v", d)
	}
}

// TestSavedPageTurnsLiveNowInPlace: the Saved page a Save opens says "Putting it in force" until the
// launcher's line, and its live region, fetched again once the line is in the ledger, says "Live now … since line #N"
// and the headline with it.
func TestSavedPageTurnsLiveNowInPlace(t *testing.T) {
	s0, _ := liveFixture(t, "landlock", 0)
	root := s0.cfg.Ledger
	plan := &rules.ChangePlan{Ref: "00112233aabbccdd", Contract: "/p/agent.yaml", Agent: "demo", Base: "b2", Direction: "narrows",
		Summary: "fs.deny_read += ./vault/", Sentences: []rules.Sentence{{Before: "May read ./vault/", After: "Can never read ./vault/", Direction: "narrows"}},
		Now: []rules.NowOption{{Run: actRun, Kind: "read", Value: "/p/vault", Block: "read:/p/vault", OK: true, Cwd: "/p"}}}
	fc := &fakeChange{plan: plan, applied: &rules.Applied{Plan: plan, ID: "rc-1",
		Live: []rules.LiveResult{{Run: actRun, Block: "read:/p/vault", OK: true, Serial: 1}}}}
	s, err := New(Config{Ledger: root, Port: port, Token: "tok123", Rules: fc})
	if err != nil {
		t.Fatal(err)
	}
	trustPeer(s)
	c := login(t, s)
	w := post(s, "/rules/change", url.Values{"csrf": {s.csrf}, "c": {plan.Ref}, "base": {"b2"}, "op": {"add"}, "key": {"fs.deny_read"},
		"v": {"./vault/"}, "now": {actRun}}, own, "", c)
	loc, _, _ := strings.Cut(w.Header().Get("Location"), "&flash=")
	if !strings.HasPrefix(loc, "/rules/change/saved?") {
		t.Fatalf("Save went to %q", loc)
	}
	body := do(s, "GET", loc, "127.0.0.1:8484", c).Body.String()
	mustContain(t, "the Saved page before the launcher's line", body, "Saved · from the next run; putting it in force on", `data-state="waiting"`,
		"Putting it in force</span>", "Running now")
	// The launcher's confirming line arrives: the run is recorded again with it.
	s1, _ := liveFixture(t, "landlock", 1)
	b := readFile(t, s1.cfg.Ledger+"/"+actRun+"/events.jsonl")
	writeRaw(t, root+"/"+actRun+"/events.jsonl", b)
	region := doRegions(s, loc, "127.0.0.1:8484", c, "content:x").Body.String()
	mustContain(t, "the Saved page's live region after the line", region, "Saved · live now on", "and from the next run", `data-state="in_force"`,
		"Live now</span>", " since line #1")
}

// TestStaleUndoSaysSo (the Undo path): an Undo posted from a page read before the file changed by hand
// undoes nothing, goes back to Change rules read again (no stale base: the page has none in its address), and says
// so in Undo's words, not Save's.
func TestStaleUndoSaysSo(t *testing.T) {
	f := newChangeFix(t)
	ref := f.ref(t, f.source)
	_, saved := f.save(t, "/rules/change", url.Values{"c": {ref.Ref}, "base": {ref.Base}, "op": {"remove"}, "key": {"exec.allow"}, "v": {"git"}})
	id := regexp.MustCompile(`name="id" value="([^"]+)"`).FindStringSubmatch(saved)
	base := formUndoBase.FindStringSubmatch(saved)
	if id == nil || base == nil {
		t.Fatal("no Undo on the Saved page")
	}
	if err := os.WriteFile(f.source, append([]byte(readText(t, f.source)), "# changed by hand\n"...), 0o600); err != nil {
		t.Fatal(err)
	}
	before := readText(t, f.source)
	w := post(f.s, "/rules/revert", url.Values{"csrf": {f.s.csrf}, "c": {ref.Ref}, "id": {id[1]}, "base": {base[1]}, "ack": {ackIn(t, saved)}}, own, "", f.c)
	if loc := w.Header().Get("Location"); !strings.HasPrefix(loc, "/rules/change?c="+ref.Ref) || strings.Contains(loc, "base=") {
		t.Fatalf("a stale Undo went to %q", loc)
	}
	body := follow(t, f.s, f.c, w)
	if !strings.Contains(body, "Not undone") || strings.Contains(body, "save again") {
		t.Errorf("the stale Undo's line is not Undo's:\n%s", body)
	}
	if readText(t, f.source) != before {
		t.Error("a stale Undo wrote the file")
	}
}

var formUndoBase = regexp.MustCompile(`action="/rules/revert"[^>]*>(?:<[^>]+>)*?<input type="hidden" name="base" value="([0-9a-f]+)"`)
