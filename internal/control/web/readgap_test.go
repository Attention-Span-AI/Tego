// SPDX-License-Identifier: Apache-2.0

package web

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/control/rules"
)

const (
	gapWatch   = "r-aaaaaaaa-0000000000061-gapwat"
	gapNoRoot  = "r-aaaaaaaa-0000000000062-gapnor"
	gapFull    = "r-aaaaaaaa-0000000000063-gapful"
	gapOldLine = "r-aaaaaaaa-0000000000064-gapold"
)

// gapFixture is the measured session of Nov 10: a watched run (tego watch keeps every read) read ~/.ssh/id_ed25519,
// then the same agent ran at tier landlock under record: summary, where Landlock refused that read without a line
// (run_start: record.reads_mmap_chmod false, reads_notified reason-off), and only a connection refusal is recorded.
// gapFull is a tier 1 run that kept its reads, gapOldLine one whose run_start predates the capability line.
func gapFixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	t0 := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	at := func(s int) time.Time { return t0.Add(time.Duration(s) * time.Second) }
	key := `"op":"open","path":"/w/home/.ssh/id_ed25519","flags":0`
	finishRun(t, root, gapWatch,
		line(gapWatch, "worker", 0, at(0), "run_start", `"tier":"observe","command":["python3","worker.py"],"cwd":"/w/proj","capabilities":{"record.reads_mmap_chmod":true},"reads_notified":{"notified":true,"why":"record-full"}`),
		line(gapWatch, "worker", 1, at(1), "fs", `"verdict":"observed","rule":"unmatched",`+key),
		line(gapWatch, "worker", 2, at(9), "run_end", `"reason":"exit","exit_code":0`))
	finishRun(t, root, gapNoRoot,
		line(gapNoRoot, "worker", 0, at(20), "run_start", `"tier":"landlock","command":["python3","worker.py"],"cwd":"/w/proj","capabilities":{"record.reads_mmap_chmod":false},"reads_notified":{"notified":false,"why":"reason-off"}`),
		line(gapNoRoot, "worker", 1, at(21), "refused", `"rule":"unmatched","reason":"net-not-allowed","op":"connect","target":"172.66.147.243:443"`),
		line(gapNoRoot, "worker", 2, at(29), "run_end", `"reason":"exit","exit_code":0`))
	finishRun(t, root, gapFull,
		line(gapFull, "worker", 0, at(40), "run_start", `"tier":"landlock","command":["python3","worker.py"],"cwd":"/w/proj","capabilities":{"record.reads_mmap_chmod":true},"reads_notified":{"notified":true,"why":"record-full"}`),
		line(gapFull, "worker", 1, at(49), "run_end", `"reason":"exit","exit_code":0`))
	finishRun(t, root, gapOldLine,
		line(gapOldLine, "worker", 0, at(60), "run_start", `"tier":"landlock","command":["python3","worker.py"],"cwd":"/w/proj"`),
		line(gapOldLine, "worker", 1, at(69), "run_end", `"reason":"exit","exit_code":0`))
	return root
}

// TestNoRootRunWithoutReadsSaysSo: a tier landlock run that kept no file read never says no secret was touched or
// tried. Its banner, Highlights, Receipt, Compare and the Overview say reads were not recorded, that a refused read
// is not listed, and name record: full; the runs that kept their reads, or whose ledger does not say, keep their words.
func TestNoRootRunWithoutReadsSaysSo(t *testing.T) {
	const (
		gap = "File reads were not recorded, refused ones included, so a secret the agent tried to read is not listed."
		fix = "To record every read, add <code>record: full</code> to the contract; each file open then costs about 60 µs more."
	)
	s := newServer(t, gapFixture(t))
	c := login(t, s)

	run := get(t, s, c, "/runs/"+gapNoRoot)
	for _, want := range []string{`<p class="vt">No attack seen in the record</p>`, `<p class="vs">File reads not recorded</p>`, gap, fix} {
		if !strings.Contains(run, want) {
			t.Errorf("the run page lacks %q", want)
		}
	}
	for _, old := range []string{`<p class="vt">No attack seen</p>`, "No secrets touched"} {
		if strings.Contains(run, old) {
			t.Errorf("the run page still says %q", old)
		}
	}

	rc := get(t, s, c, "/runs/"+gapNoRoot+"/receipt")
	if !strings.Contains(rc, gap) || !strings.Contains(rc, fix) || strings.Contains(rc, "Not known: this run did not record every read") {
		t.Errorf("the receipt does not say what the run did not record:\n%s", rc)
	}

	cmp := get(t, s, c, "/compare?a="+gapWatch+"&b="+gapNoRoot)
	for _, want := range []string{`<span class="cmp-stat-d">file reads not recorded</span>`, "Run B: " + gap + " " + fix,
		`<span class="muted" title="` + gap + `">not recorded</span>`} {
		if !strings.Contains(cmp, want) {
			t.Errorf("Compare lacks %q", want)
		}
	}
	if strings.Contains(cmp, "no attempt on a secret seen") || strings.Contains(cmp, `<span class="muted">not seen</span>`) {
		t.Errorf("Compare still says the enforced run saw no attempt on the key:\n%s", cmp)
	}

	if ov := get(t, s, c, "/"); !strings.Contains(ov, "1 run did not record every file read, so a secret read there may be missing from these counts. "+fix) {
		t.Errorf("the Overview's secret counts do not say a run kept no read:\n%s", ov)
	}

	for _, id := range []string{gapFull, gapOldLine} {
		body := get(t, s, c, "/runs/"+id)
		if !strings.Contains(body, `<p class="vt">No attack seen</p>`) || !strings.Contains(body, "No secrets touched") || strings.Contains(body, "record: full</code>") {
			t.Errorf("run %s, whose run_start does not say reads went unrecorded, lost its words", id)
		}
	}
}

// TestReadGapWords: a run that told the supervisor of its read opens lists the refused ones, so its words say only
// that allowed reads went unrecorded; a run that kept its reads, or does not say, has no gap.
func TestReadGapWords(t *testing.T) {
	root := gapFixture(t)
	s := newServer(t, root)
	c := login(t, s)
	t0 := time.Date(2026, 10, 25, 13, 0, 0, 0, time.UTC)
	const notified = "r-aaaaaaaa-0000000000065-gapntf"
	finishRun(t, root, notified,
		line(notified, "worker", 0, t0, "run_start", `"tier":"landlock","command":["python3","worker.py"],"capabilities":{"record.reads_mmap_chmod":false},"reads_notified":{"notified":true,"why":"reason"}`),
		line(notified, "worker", 1, t0.Add(time.Second), "run_end", `"reason":"exit","exit_code":0`))
	body := get(t, s, c, "/runs/"+notified)
	if !strings.Contains(body, "Allowed file reads were not recorded, so a secret the agent read is not listed.") || strings.Contains(body, "refused ones included") {
		t.Errorf("a run that records refused reads is told it does not:\n%s", body)
	}
}

// TestSecretReadThroughIsNotNeverRead: Highlights put the never-read rule's label beside a read that went through as
// "Never read" next to "Observed 1", while the Receipt said "Read, not refused 1". A read that went through now names
// the rule as not enforced; a refused one keeps "Never read".
func TestSecretReadThroughIsNotNeverRead(t *testing.T) {
	s := newServer(t, pw3Fixture(t))
	c := login(t, s)
	hl := func(run string) string {
		body := get(t, s, c, "/runs/"+run)
		return body[strings.Index(body, `id="h-hl-s"`):strings.Index(body, `id="h-hl-o"`)]
	}
	if w := hl(pw3Watch); strings.Contains(w, `/.ssh/]">Never read</span>`) || !strings.Contains(w, `/.ssh/]">Never-read rule, not enforced</span>`) {
		t.Errorf("the watched run's key read reads as never read:\n%s", w)
	}
	if e := hl(pw3Enf); !strings.Contains(e, `/.ssh/]">Never read</span>`) {
		t.Errorf("the enforced run's refused key read lost its rule:\n%s", e)
	}
}

// TestMachineKernelDecidesAtTierOne: at tier landlock the kernel refuses files and programs (Landlock); "Nothing"
// read as no kernel protection at all.
func TestMachineKernelDecidesAtTierOne(t *testing.T) {
	s := newServer(t, fixture(t))
	body := get(t, s, login(t, s), "/machine")
	if strings.Contains(body, `title="Basic and watched runs decide no file or program in a kernel plane">Nothing</span>`) ||
		!strings.Contains(body, ">Files and programs (Landlock)</span>") {
		t.Errorf("This machine says the kernel decides nothing for a tier landlock run:\n%s", body)
	}
}

// TestEmptyPagesGiveANextStep: each page a new user opens before any run says what to do next, in one short true
// line, and none names tego init's starter or a file the installer does not install.
func TestEmptyPagesGiveANextStep(t *testing.T) {
	root := t.TempDir()
	s := newServer(t, root)
	svc := &rules.Service{Ledger: root, Home: t.TempDir(), Now: s.cfg.Now,
		Compile: func(context.Context, rules.CheckContext, []byte) error { return nil }}
	s.cfg.Setup, s.cfg.Rules = svc, svc
	c := login(t, s)
	for path, want := range map[string]string{
		"/detections":         "What Tego refuses a run under a contract (<span class=\"mono\">tego run</span>) shows here.",
		"/approvals":          "A contract can ask you before a file change or a connection; those requests wait here for your answer.",
		"/logs":               "Every line a run records shows here; <span class=\"mono\">tego watch -- &lt;command&gt;</span> starts one.",
		"/rules":              "Make one from presets or from a finished run with New contract.",
		"/rules/change":       `Make one with <a class="link" href="/rules/new">New contract</a>; once it is written, its rules can be changed here.`,
		"/rules/new?mode=run": "Record one first: <span class=\"mono\">tego watch -- &lt;the command that starts your agent&gt;</span>",
	} {
		body := get(t, s, c, path)
		if !strings.Contains(body, want) {
			t.Errorf("%s lacks its next step %q", path, want)
		}
		if strings.Contains(body, "tego init &amp;&amp; tego run") || strings.Contains(body, "examples/agents/") {
			t.Errorf("%s still points at tego init's starter or an example file", path)
		}
	}
}

// TestReadGapWhenTheRecordCannotTell: a tier landlock run whose run_start says it kept no file read but has no
// reads_notified (a ledger written before 2026-10-25) cannot say whether Landlock refused a read without a line, so
// its words say a refused read may be missing too, as tego receipt's do. A root tier's run that says why=kernel keeps
// its refused reads in the kernel record, so only the allowed ones are missing. The Overview's note then speaks of
// every file read, not of refused ones alone: at a root tier the refused reads are in the counts and the allowed are not.
func TestReadGapWhenTheRecordCannotTell(t *testing.T) {
	const (
		mayMiss  = "Allowed file reads were not recorded, so a secret the agent read is not listed; a refused read may be missing too."
		allowed  = "Allowed file reads were not recorded, so a secret the agent read is not listed."
		unseen   = "refused ones included"
		older    = "r-aaaaaaaa-0000000000066-gapnrn"
		kernel   = "r-aaaaaaaa-0000000000067-gapker"
		overview = "3 runs did not record every file read, so a secret read there may be missing from these counts."
	)
	root := gapFixture(t)
	t0 := time.Date(2026, 10, 25, 14, 0, 0, 0, time.UTC)
	finishRun(t, root, older,
		line(older, "worker", 0, t0, "run_start", `"tier":"landlock","command":["python3","worker.py"],"capabilities":{"record.reads_mmap_chmod":false}`),
		line(older, "worker", 1, t0.Add(time.Second), "run_end", `"reason":"exit","exit_code":0`))
	finishRun(t, root, kernel,
		line(kernel, "worker", 0, t0.Add(2*time.Second), "run_start", `"tier":"cgroup","command":["python3","worker.py"],"capabilities":{"record.reads_mmap_chmod":false},"reads_notified":{"notified":false,"why":"kernel"}`),
		line(kernel, "worker", 1, t0.Add(3*time.Second), "run_end", `"reason":"exit","exit_code":0`))
	s := newServer(t, root)
	c := login(t, s)
	for _, page := range []string{"/runs/" + older, "/runs/" + older + "/receipt"} {
		if body := get(t, s, c, page); !strings.Contains(body, mayMiss) || strings.Contains(body, unseen) {
			t.Errorf("%s: a run whose record does not say what Landlock refused does not say a refused read may be missing:\n%s", page, body)
		}
	}
	for _, page := range []string{"/runs/" + kernel, "/runs/" + kernel + "/receipt"} {
		if body := get(t, s, c, page); !strings.Contains(body, allowed) || strings.Contains(body, mayMiss) || strings.Contains(body, unseen) {
			t.Errorf("%s: a root tier's run, whose kernel record holds its refused reads, is told they may be missing:\n%s", page, body)
		}
	}
	if ov := get(t, s, c, "/"); !strings.Contains(ov, overview) || strings.Contains(ov, "a secret read refused there") {
		t.Errorf("the Overview's note does not speak of every file read:\n%s", ov)
	}
}
