// SPDX-License-Identifier: Apache-2.0

package web

import (
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/control/ledgerview"
	"golang.org/x/net/html"
)

// Waiting identities are accumulated by runState.take, not reconstructed from Events
// or the capped answer history. Exercise an ask older than each of those bounds.
func TestWaitingSurvivesHistoryAndWindowBounds(t *testing.T) {
	for _, mode := range []string{"window", "eviction", "history cap", "reader error"} {
		t.Run(mode, func(t *testing.T) {
			oldLines, oldBytes := ledgerview.MaxLines, ledgerview.MaxResidentBytes
			t.Cleanup(func() { ledgerview.MaxLines, ledgerview.MaxResidentBytes = oldLines, oldBytes })
			if mode == "window" {
				ledgerview.MaxLines = 16
			}
			if mode == "eviction" {
				ledgerview.MaxResidentBytes = 1
			}
			root := lockedMCPFixture(t)
			seq := 8
			for i := 0; i < historyAnswers+1; i++ {
				appendLine(t, root, harmRun, line(harmRun, "agent", seq, time.Now(), "ask", fmt.Sprintf(`"ask_id":"answered-%d","hold":"net"`, i)))
				seq++
				appendLine(t, root, harmRun, line(harmRun, "agent", seq, time.Now(), "answer", fmt.Sprintf(`"ask_id":"answered-%d","approved":true`, i)))
				seq++
			}
			if mode == "reader error" {
				makeUnreadableCandidate(t, root)
			}
			snap, err := ledgerview.Load(root)
			if err != nil {
				t.Fatal(err)
			}
			r := snap.Find(harmRun)
			if r == nil || len(r.Pending) != 1 || r.Pending[0].AskID != "ask-7" {
				t.Fatalf("old waiting identity lost: %+v", r)
			}
			if mode == "window" || mode == "eviction" {
				for _, ev := range r.Events {
					if ev.AskID == "ask-7" {
						t.Fatal("ask is still in the event window")
					}
				}
			}
			s := newServer(t, root)
			c := login(t, s)
			body := get(t, s, c, "/approvals")
			if strings.Contains(body, "Nothing waiting") {
				t.Fatal("a waiting request older than history was hidden")
			}
			if mode == "reader error" && !strings.Contains(body, "at least 1 waiting") {
				t.Fatal("unreadable waiting source lost lower bound")
			}
			appendLine(t, root, harmRun, line(harmRun, "agent", seq, time.Now(), "answer", `"ask_id":"ask-7","approved":true`))
			body = get(t, s, c, "/approvals")
			if mode == "reader error" {
				if strings.Contains(body, "Nothing waiting") || !strings.Contains(body, "could not tell whether a request is waiting") {
					t.Fatal("reader failure became an all-clear")
				}
			} else if !strings.Contains(body, "Nothing waiting") {
				t.Fatal("history/window completeness incorrectly qualifies the waiting headline")
			}
		})
	}
}

func TestApprovalsHeadlineUsesOnlyWaitingSources(t *testing.T) {
	source := attentionSourceOf(&ledgerview.Snapshot{Runs: []*ledgerview.Run{{Ended: true, ReadError: "the ended run could not be reread"}}})
	got := (approvalsData{AttentionSource: source}).Attention()
	if len(got.Items) != 0 {
		t.Fatalf("ended-record history failure qualified the waiting headline: %+v", got)
	}
}

func TestWaitingReaderFailureCanHideRequest(t *testing.T) {
	root := lockedMCPFixture(t)
	// The unreadable file really contains an unanswered ask, before this server
	// has read any prefix of it. A cold dashboard has no known count to display.
	path := filepath.Join(root, harmRun, "events.jsonl")
	if err := os.Rename(path, path+".unreadable"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	s := newServer(t, root)
	c := login(t, s)
	body := getRaw(t, s, c, "/approvals")
	if strings.Contains(body, "Nothing waiting") || !strings.Contains(body, "could not tell whether a request is waiting") {
		t.Fatal("an unreadable waiting source became an all-clear")
	}
}

func TestApprovalsEndedMissingRecordCannotHideWaiting(t *testing.T) {
	root := numberLedger(t)
	if err := os.RemoveAll(filepath.Join(root, harmRun)); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(root, ".live", harmRun)); err != nil {
		t.Fatal(err)
	}
	s := newServer(t, root)
	c := login(t, s)
	getRaw(t, s, c, "/approvals") // publish the ended run and its state first
	if err := os.Remove(filepath.Join(root, numRichRun, "events.jsonl")); err != nil {
		t.Fatal(err)
	}
	body := getRaw(t, s, c, "/approvals")
	if !strings.Contains(body, "Nothing waiting") || strings.Contains(body, "could not tell whether a request is waiting") {
		t.Fatal("an ended run's missing record qualified the actionable queue")
	}
	overview := getRaw(t, s, c, "/")
	if !strings.Contains(overview, "Could not read the full record") || !strings.Contains(overview, "its record file is missing") {
		t.Fatal("waiting certainty hid the record failure")
	}
}

func TestUnknownCandidateAfterListedFailureCannotClearQueue(t *testing.T) {
	root := numberLedger(t)
	if err := os.RemoveAll(filepath.Join(root, harmRun)); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(root, ".live", harmRun)); err != nil {
		t.Fatal(err)
	}
	s := newServer(t, root)
	c := login(t, s)
	getRaw(t, s, c, "/approvals")
	if err := os.Remove(filepath.Join(root, numRichRun, "events.jsonl")); err != nil {
		t.Fatal(err)
	}
	makeUnreadableCandidate(t, root) // sorts after the known failed run
	body := getRaw(t, s, c, "/approvals")
	if strings.Contains(body, "Nothing waiting") || !strings.Contains(body, "could not tell whether a request is waiting") {
		t.Fatal("the first listed error hid a later unlisted waiting source")
	}
}

func TestMissingLiveRecordKeepsKnownWaitingCount(t *testing.T) {
	for _, removeDirectory := range []bool{false, true} {
		t.Run(map[bool]string{false: "file", true: "directory"}[removeDirectory], func(t *testing.T) {
			root := twoRequestFixture(t)
			appendLine(t, root, harmRun, line(harmRun, "Agent", 8, time.Now(), "ask", `"ask_id":"third","hold":"net","target":"example.org:443"`))
			s := newServer(t, root)
			c := login(t, s)
			getRaw(t, s, c, "/approvals")
			if removeDirectory {
				if err := os.RemoveAll(filepath.Join(root, harmRun)); err != nil {
					t.Fatal(err)
				}
			} else if err := os.Remove(filepath.Join(root, harmRun, "events.jsonl")); err != nil {
				t.Fatal(err)
			}
			if removeDirectory { // Read beyond the lock-probe cache; the old directory/lock is now unreachable.
				time.Sleep(2100 * time.Millisecond)
			}
			body := getRaw(t, s, c, "/approvals")
			title, badge, spoken, sentence := "", "", "", ""
			walk(parseHTML(t, "Approvals", body), func(n *html.Node) {
				if n.Data == "title" {
					title = text(n)
				}
				if marker, _ := attr(n, "data-number"); n.Data == "p" && marker == "approvals.waiting" {
					sentence = text(n)
				}
				if class, _ := attr(n, "class"); n.Data == "span" && class == "count" {
					spoken, _ = attr(n, "aria-label")
					for child := n.FirstChild; child != nil; child = child.NextSibling {
						if child.Type == html.TextNode {
							badge += child.Data
						}
					}
				}
			})
			if badge != "3+" || !strings.HasPrefix(title, "(3+)") || spoken != sentence || !strings.HasPrefix(sentence, "at least 3 waiting: ") || !strings.Contains(sentence, "its record file is missing") {
				t.Fatalf("known waiting representations disagree: badge=%q title=%q spoken=%q page=%q", badge, title, spoken, sentence)
			}
		})
	}
}

func TestRunDetailWaitingUsesActionableScope(t *testing.T) {
	root := twoRequestFixture(t)
	appendLine(t, root, harmRun, line(harmRun, "Agent", 8, time.Now(), "ask", `"ask_id":"third","hold":"net","target":"example.org:443"`))
	s := newServer(t, root)
	c := login(t, s)
	getRaw(t, s, c, "/approvals")
	if err := os.Remove(filepath.Join(root, harmRun, "events.jsonl")); err != nil {
		t.Fatal(err)
	}
	body := getRaw(t, s, c, "/runs/"+harmRun+"?details=1")
	asks := ""
	walk(parseHTML(t, "Run details", body), func(n *html.Node) {
		if n.Data == "dt" && text(n) == "Asks" && n.NextSibling != nil {
			asks = text(n.NextSibling)
		}
	})
	if !strings.Contains(asks, "at least 2") || !strings.Contains(asks, "waiting") {
		t.Fatalf("run details hide known actionable requests: %q", asks)
	}
}

func TestUnreadableLiveIndexCannotClearWaiting(t *testing.T) {
	for _, warm := range []bool{false, true} {
		t.Run(fmt.Sprint(warm), func(t *testing.T) {
			root := twoRequestFixture(t)
			s := newServer(t, root)
			c := login(t, s)
			if warm {
				getRaw(t, s, c, "/approvals")
			}
			if err := os.RemoveAll(filepath.Join(root, ".live")); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, ".live"), []byte("unreadable index"), 0600); err != nil {
				t.Fatal(err)
			}
			body := getRaw(t, s, c, "/approvals")
			if strings.Contains(body, "Nothing waiting") || !strings.Contains(body, "could not read the live index") {
				t.Fatal("unreadable live index became an all-clear")
			}
			if warm && !strings.Contains(body, "at least 2 waiting") {
				t.Fatal("known waiting requests disappeared with their index")
			}
			if !strings.Contains(body, "Could not read running state") {
				t.Fatal("top bar ignored global live-source scope")
			}
		})
	}
}

func TestVanishedIndexedRunCannotClearColdQueue(t *testing.T) {
	root := twoRequestFixture(t)
	if err := os.RemoveAll(filepath.Join(root, harmRun)); err != nil {
		t.Fatal(err)
	}
	s := newServer(t, root)
	body := getRaw(t, s, login(t, s), "/approvals")
	if strings.Contains(body, "Nothing waiting") || !strings.Contains(body, "its record file is missing") {
		t.Fatal("an indexed run with missing records became an all-clear")
	}
}

func TestMissingLedgerRootKeepsKnownWaiting(t *testing.T) {
	root := twoRequestFixture(t)
	s := newServer(t, root)
	c := login(t, s)
	getRaw(t, s, c, "/approvals")
	if err := os.RemoveAll(root); err != nil {
		t.Fatal(err)
	}
	body := getRaw(t, s, c, "/approvals")
	if !strings.Contains(body, "at least 2 waiting") || strings.Contains(body, "Nothing waiting") {
		t.Fatal("removing the root erased known waiting requests")
	}
}

// The recorder's locks and asks survive a missing index across dashboard restart.
func TestMissingLiveIndexAfterRestartCannotClearWaiting(t *testing.T) {
	root := twoRequestFixture(t)
	if err := os.RemoveAll(filepath.Join(root, ".live")); err != nil {
		t.Fatal(err)
	}
	s := newServer(t, root)
	body := getRaw(t, s, login(t, s), "/approvals")
	if strings.Contains(body, "Nothing waiting") || !strings.Contains(body, "live index") {
		t.Fatal("cold missing live index became an all-clear despite held locks and unanswered asks")
	}
	before, err := ledgerview.Load(root)
	if err != nil {
		t.Fatal(err)
	}
	numbers := snapshotNumbers(before)
	if numbers.Live.Error == "" || numbers.Queue.Error == "" || numbers.Runs.incomplete() || numbers.Aggregate.incomplete() || numbers.Window.incomplete() || numbers.History.incomplete() {
		t.Fatal("a live-index failure qualified readable record sources or lost its actionable scope")
	}
	for _, run := range before.Runs {
		if !run.Ended && run.State() != "unknown" {
			t.Fatal("unknown liveness was called lost or running")
		}
	}
	run, err := ledgerview.LoadRun(root, harmRun)
	if err != nil || run.LiveError == "" || run.State() != "unknown" {
		t.Fatal("direct run lookup forgot the missing live index")
	}
	runPage := getRaw(t, s, login(t, s), "/runs/"+harmRun)
	if strings.Contains(runPage, "This run was lost") || !strings.Contains(runPage, "could not tell whether a request is waiting") {
		t.Fatal("unknown live source became a local run all-clear or a lost-run claim")
	}
	form := s.newForm(httptest.NewRequest("GET", "/rules/new?mode=run", nil), before, "", "", nil, "", "", "", "", "run")
	for _, option := range form.Runs {
		if option.ID == harmRun || option.ID == secondRequestRun {
			t.Fatal("unknown run offered as a finished run")
		}
	}
	absence, err := quantityZero("editor.finished-runs-zero", "No finished run", numbers)
	if err != nil || !strings.Contains(absence.Text, "could not be read") {
		t.Fatal("finished-run absence ignored unknown status")
	}
	const unknown = "could not read"
	for _, filter := range []string{"", "running", "ended", "lost"} {
		body := getRaw(t, s, login(t, s), "/runs?state="+filter)
		m := numberMarkers(t, body)
		wantUnknown := filter != "" && filter != "ended"
		if got := strings.Contains(strings.Join(m["runs.matches"], " "), unknown); got != wantUnknown {
			t.Fatalf("filter %q matching count affected=%v want %v", filter, got, wantUnknown)
		}
	}
	again, err := ledgerview.Load(root)
	if err != nil {
		t.Fatal(err)
	}
	if before.Rev != again.Rev {
		t.Fatal("unchanged missing-index coverage moved the revision")
	}
	if err := os.MkdirAll(filepath.Join(root, ".live"), 0700); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{harmRun, secondRequestRun} {
		if err := os.WriteFile(filepath.Join(root, ".live", id), nil, 0600); err != nil {
			t.Fatal(err)
		}
	}
	after, err := ledgerview.Load(root)
	if err != nil {
		t.Fatal(err)
	}
	if after.ReadError != "" || after.LiveError != "" || after.Rev <= before.Rev || len(after.Pending()) != 2 {
		t.Fatal("restored index did not recover the known queue and its revision")
	}
	body = getRaw(t, s, login(t, s), "/approvals")
	if !strings.Contains(body, "2 waiting") || strings.Contains(body, "could not tell whether a request is waiting") {
		t.Fatal("restored index kept an unknown waiting headline")
	}
}

func TestMissingKnownLedgerRootCannotClearQueue(t *testing.T) {
	for _, ended := range []bool{false, true} {
		t.Run(fmt.Sprint(ended), func(t *testing.T) {
			root := t.TempDir()
			if ended {
				fix3EndedOnly(t, root)
			}
			s := newServer(t, root)
			c := login(t, s)
			if !strings.Contains(getRaw(t, s, c, "/approvals"), "Nothing waiting") {
				t.Fatal("complete startup source has no waiting request")
			}
			if err := os.RemoveAll(root); err != nil {
				t.Fatal(err)
			}
			body := getRaw(t, s, c, "/approvals")
			if strings.Contains(body, "Nothing waiting") || !strings.Contains(body, "could not tell whether a request is waiting") {
				t.Fatal("missing known ledger root became an all-clear")
			}
		})
	}
}

func TestMissingLiveIndexDoesNotQualifyEndedHistory(t *testing.T) {
	for _, recorded := range []bool{false, true} {
		t.Run(fmt.Sprint(recorded), func(t *testing.T) {
			root := t.TempDir()
			if recorded {
				fix3EndedOnly(t, root)
			}
			s := newServer(t, root)
			body := getRaw(t, s, login(t, s), "/approvals")
			if !strings.Contains(body, "Nothing waiting") || strings.Contains(body, "could not tell whether a request is waiting") {
				t.Fatal("an absent startup index or complete ended history qualified the waiting headline")
			}
		})
	}
}

func fix3EndedOnly(t *testing.T, root string) {
	t.Helper()
	dir := filepath.Join(root, cleanRun)
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	record := line(cleanRun, "Ended", 1, now, "run_start", `"tier":"observe"`) + line(cleanRun, "Ended", 2, now, "run_end", `"exit_code":0`)
	if err := os.WriteFile(filepath.Join(dir, "events.jsonl"), []byte(record), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestLiveSourceRecoveryMovesRowRevisions(t *testing.T) {
	root := twoRequestFixture(t)
	for _, id := range []string{harmRun, secondRequestRun} {
		letGo(filepath.Join(root, id))
	}
	if err := os.RemoveAll(filepath.Join(root, ".live")); err != nil {
		t.Fatal(err)
	}
	before, err := ledgerview.Load(root)
	if err != nil {
		t.Fatal(err)
	}
	if before.Find(harmRun).State() != "unknown" {
		t.Fatal("missing source was called lost")
	}
	if err := os.Mkdir(filepath.Join(root, ".live"), 0700); err != nil {
		t.Fatal(err)
	}
	after, err := ledgerview.Load(root)
	if err != nil {
		t.Fatal(err)
	}
	if after.Find(harmRun).State() != "lost" || after.Rev <= before.Rev {
		t.Fatal("source recovery did not establish the stopped run")
	}
	seen := map[string]bool{}
	for _, run := range after.Changed(before.Rev) {
		seen[run.ID] = true
	}
	if !seen[harmRun] || !seen[secondRequestRun] {
		t.Fatal("metadata-only source recovery did not invalidate run rows")
	}
}
