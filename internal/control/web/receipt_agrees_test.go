// SPDX-License-Identifier: Apache-2.0

package web

import (
	"context"
	"fmt"
	"html"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/control/ledgerview"
)

// receiptAndTab writes one run of lines under a fresh root and returns the Receipt tab's page and `tego receipt`'s text
// for it: the tab renders the same receipt with its own template, so each pair of words is checked on both.
func receiptAndTab(t *testing.T, run string, lines ...string) (page, text string) {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, run), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, run, "events.jsonl"), []byte(strings.Join(lines, "")), 0o644); err != nil {
		t.Fatal(err)
	}
	rc, err := ledgerview.LoadReceipt(context.Background(), root, run)
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	if err := rc.Text(&b); err != nil {
		t.Fatal(err)
	}
	s := newServer(t, root)
	return get(t, s, login(t, s), "/runs/"+run+"/receipt"), b.String()
}

// TestReceiptTabCountsRoutineSockets: tego receipt counts an AF_UNSPEC reset and the netlink socket apart, as routine
// socket calls that name no place, and the Receipt tab showed only its places and system lookups: a run with nothing
// else said "None recorded." there and "None, besides 1 routine socket call ..." in the terminal (review 1 S1).
func TestReceiptTabCountsRoutineSockets(t *testing.T) {
	const run = "r-aaaaaaaa-0000000000061-rtsock"
	t0 := time.Date(2026, 11, 11, 9, 0, 0, 0, time.UTC)
	at := func(i int) time.Time { return t0.Add(time.Duration(i) * time.Millisecond) }
	page, text := receiptAndTab(t, run,
		line(run, "py", 0, at(0), "run_start", `"tier":"observe","command":["python3","fetch.py"],"cwd":"/w"`),
		line(run, "py", 1, at(1), "net", `"rule":"net.unspec","verdict":"observed","dst":"unspec","proto":"udp"`),
		line(run, "py", 2, at(2), "net", `"rule":"route-query","verdict":"allow","dst":"family(16)","proto":"raw"`),
		line(run, "py", 3, at(3), "run_end", `"reason":"exit","exit_code":0`))
	if want := "None, besides 2 routine socket calls that name no place"; !strings.Contains(text, want) {
		t.Fatalf("tego receipt lacks %q:\n%s", want, text)
	}
	// The tab says tego receipt's sentence, from the receipt (NoConnectionWords), not its own shorter one.
	for _, want := range []string{"None, besides 2 routine socket calls that name no place (disconnects with AF_UNSPEC, the kernel's netlink socket)."} {
		if !strings.Contains(page, html.EscapeString(want)) {
			t.Errorf("the Receipt tab lacks %q", want)
		}
	}

	const run2 = "r-aaaaaaaa-0000000000062-rtsock"
	page, text = receiptAndTab(t, run2,
		line(run2, "py", 0, at(0), "run_start", `"tier":"observe","command":["python3","fetch.py"],"cwd":"/w"`),
		line(run2, "py", 1, at(1), "net", `"rule":"net.unspec","verdict":"observed","dst":"unspec","proto":"udp"`),
		line(run2, "py", 2, at(2), "net", `"rule":"unmatched","verdict":"observed","dst":"151.101.0.223:443","proto":"tcp"`),
		line(run2, "py", 3, at(3), "run_end", `"reason":"exit","exit_code":0`))
	const also = "Also 1 routine socket call that names no place (disconnects with AF_UNSPEC, the kernel"
	if !strings.Contains(text, also) {
		t.Fatalf("tego receipt lacks %q:\n%s", also, text)
	}
	if !strings.Contains(page, html.EscapeString(also+"'s netlink socket), not counted above.")) {
		t.Errorf("the Receipt tab lacks %q", also)
	}
}

// TestReceiptTabNamesTheKernelTLSRefusalBuiltIn: tego receipt and tego run's summary name tego's built-in refusal of
// setsockopt(TCP_ULP, "tls") apart from the default deny, and the Receipt tab's bars and refused list still called it
// by the rule the record files it under, "Not in policy" (review 1 S1). The tab now names it "built in: kernel TLS" in
// both places, gives it a bar of its own, and keeps the default deny's words for a real connect.
func TestReceiptTabNamesTheKernelTLSRefusalBuiltIn(t *testing.T) {
	const run = "r-aaaaaaaa-0000000000063-ktlsxx"
	t0 := time.Date(2026, 11, 11, 9, 0, 0, 0, time.UTC)
	at := func(i int) time.Time { return t0.Add(time.Duration(i) * time.Millisecond) }
	page, text := receiptAndTab(t, run,
		line(run, "py", 0, at(0), "run_start", `"tier":"landlock","command":["python3","fetch.py"],"cwd":"/w"`),
		line(run, "py", 1, at(1), "refused", `"rule":"unmatched","reason":"net-not-allowed","op":"setsockopt","target":"TCP_ULP \"tls\""`),
		line(run, "py", 2, at(2), "refused", `"rule":"unmatched","reason":"net-not-allowed","op":"setsockopt","target":"TCP_ULP \"tls\""`),
		line(run, "py", 3, at(3), "refused", `"rule":"unmatched","reason":"net-not-allowed","op":"net","target":"203.0.113.9:443"`),
		line(run, "py", 4, at(4), "run_end", `"reason":"exit","exit_code":0`))
	for _, want := range []string{"       2  built in, no rule allows it: kernel TLS", "       1  not allowed by any rule (net-not-allowed)"} {
		if !strings.Contains(text, want) {
			t.Fatalf("tego receipt lacks %q:\n%s", want, text)
		}
	}
	bars := regexp.MustCompile(`<span class="mono rc-rule" title="unmatched">([^<]*)</span><span class="rc-n">(\d+)</span>`).
		FindAllStringSubmatch(page, -1)
	var got []string
	for _, m := range bars {
		got = append(got, m[1]+" "+m[2])
	}
	if want := []string{"built in: kernel TLS 2", ruleName("unmatched") + " 1"}; strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("the Receipt tab's bars are %q, want %q", got, want)
	}
	listed := regexp.MustCompile(`<span class="soft rc-rr" title="unmatched">([^<]*)</span>`).FindAllStringSubmatch(page, -1)
	got = got[:0]
	for _, m := range listed {
		got = append(got, m[1])
	}
	if want := []string{"built in: kernel TLS", "built in: kernel TLS", ruleName("unmatched")}; strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("the Receipt tab's refused list names %q, want %q", got, want)
	}
}

// TestReceiptTabSaysWhatARunDoesNotRecord: a tier-landlock run with reason.reads off leaves no line for a read its
// deny_read refuses, and tego receipt says so where it counts refusals; the Receipt tab still said "Nothing was
// refused." for the same record (review 1 S1). It now says what tego receipt says, with and without a refusal, and a
// run that records its refused reads keeps "Nothing was refused.".
func TestReceiptTabSaysWhatARunDoesNotRecord(t *testing.T) {
	t0 := time.Date(2026, 11, 11, 9, 0, 0, 0, time.UTC)
	at := func(i int) time.Time { return t0.Add(time.Duration(i) * time.Millisecond) }
	const (
		nothing    = "Nothing was refused."
		unrecorded = "No recorded action was refused; this run does not record refused reads (see Sensitive files read)."
		alsoNot    = "This run does not record refused reads, so a read it refused is not counted (see Sensitive files read)."
	)
	for i, c := range []struct {
		notified, refuse bool
		want, notWant    string
	}{
		{false, false, unrecorded, nothing},
		{false, true, alsoNot, nothing},
		{true, false, nothing, "does not record refused reads"},
	} {
		run := fmt.Sprintf("r-aaaaaaaa-000000000007%d-rdsoff", i)
		why := "reason-off"
		if c.notified {
			why = "reason"
		}
		ls := []string{line(run, "sh", 0, at(0), "run_start", fmt.Sprintf(`"tier":"landlock","command":["cat","secret.txt"],"cwd":"/w",`+
			`"reads_notified":{"notified":%t,"why":%q}`, c.notified, why))}
		if c.refuse {
			ls = append(ls, line(run, "sh", 1, at(1), "refused", `"rule":"unmatched","reason":"net-not-allowed","op":"net","target":"203.0.113.9:443"`))
		}
		page, text := receiptAndTab(t, run, append(ls, line(run, "sh", 2, at(2), "run_end", `"reason":"exit","exit_code":1`))...)
		if !strings.Contains(text, c.want) || strings.Contains(text, c.notWant) {
			t.Fatalf("case %d: tego receipt does not say %q, or says %q:\n%s", i, c.want, c.notWant, text)
		}
		if !strings.Contains(page, c.want) || strings.Contains(page, c.notWant) {
			t.Errorf("case %d: the Receipt tab does not say %q, or says %q", i, c.want, c.notWant)
		}
	}
}
