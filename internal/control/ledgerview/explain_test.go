// SPDX-License-Identifier: Apache-2.0

package ledgerview

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// flatKeys is every leaf key of the JSON object line, nested non-empty objects as dotted paths, the envelope left
// out: what Explain's Fields must hold, worked out here independently of its walker.
func flatKeys(t *testing.T, line string) []string {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(line), &m); err != nil {
		t.Fatalf("%v: %s", err, line)
	}
	var out []string
	var walk func(prefix string, v any)
	walk = func(prefix string, v any) {
		if o, ok := v.(map[string]any); ok && len(o) > 0 {
			for k, vv := range o {
				walk(prefix+"."+k, vv)
			}
			return
		}
		out = append(out, prefix[1:])
	}
	for k, v := range m {
		if envelopeKeys[k] {
			continue
		}
		walk("."+k, v)
	}
	sort.Strings(out)
	return out
}

// checkFields fails unless lv's Fields hold exactly the line's keys, with Unknown on the keys of unknown alone.
func checkFields(t *testing.T, where string, lv *LineView, unknown map[string]bool) {
	t.Helper()
	want := flatKeys(t, lv.Raw)
	var got []string
	for _, f := range lv.Fields {
		got = append(got, f.Key)
		if f.Unknown != unknown[f.Key] {
			t.Errorf("%s #%d: key %q unknown=%v (label %q)", where, lv.Seq, f.Key, f.Unknown, f.Label)
		}
		if f.Label == "" {
			t.Errorf("%s #%d: key %q has no label", where, lv.Seq, f.Key)
		}
	}
	sort.Strings(got)
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("%s #%d: fields\n got %v\nwant %v", where, lv.Seq, got, want)
	}
}

// TestExplainEveryKeyOfTheRecordFixtures: every key of every line of the record's v1 fixtures, and of a demo-shaped
// run that carries the keys writers add beyond the typed payloads, is in Fields with a label; only the key the test
// injects is unknown.
func TestExplainEveryKeyOfTheRecordFixtures(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("..", "..", "..", "spec", "record", "v1", "fixtures", "*.jsonl"))
	if err != nil || len(files) < 10 {
		t.Fatalf("fixtures: %v (%d)", err, len(files))
	}
	root := t.TempDir()
	lines := 0
	for fi, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		// One run directory per run a fixture file holds, in file order.
		byRun := map[string][]string{}
		var order []string
		sc := bufio.NewScanner(bytes.NewReader(b))
		sc.Buffer(make([]byte, 64<<10), maxLineBytes)
		for sc.Scan() {
			var head struct {
				Run string `json:"run"`
			}
			if json.Unmarshal(sc.Bytes(), &head) != nil {
				continue
			}
			if _, ok := byRun[head.Run]; !ok {
				order = append(order, head.Run)
			}
			byRun[head.Run] = append(byRun[head.Run], sc.Text()+"\n")
		}
		for ri, run := range order {
			id := fmt.Sprintf("r-fixture-%02d-%02d", fi, ri)
			writeRun(t, root, id, byRun[run]...)
			r, err := LoadRun(root, id)
			if err != nil {
				t.Fatal(err)
			}
			for _, e := range r.AllEvents() {
				lv, err := Explain(root, r, e.Seq)
				if err != nil {
					t.Fatalf("%s #%d: %v", filepath.Base(f), e.Seq, err)
				}
				checkFields(t, filepath.Base(f), lv, nil)
				if lv.Sentence == "" {
					t.Errorf("%s #%d: no sentence", filepath.Base(f), e.Seq)
				}
				lines++
			}
		}
	}
	if lines < 50 {
		t.Fatalf("explained %d fixture lines, want the fixtures' lines", lines)
	}

	x, _ := codexShaped(t)
	x.add(400, `"kind":"exec","source":"seccomp","rule":"exec[curl]","verdict":"allow","authority":"rule","argv":["curl"],"argv_truncated":true,"path_search":true,"fileless":false,"exec_id":"r/400/8","parent_exec_id":"r/300/7","path":"/usr/bin/curl","score":42,"gate_rule":"gate.exec","gate_outcome":"allow","gate_facts":{"model":"none"}`)
	x.add(400, `"kind":"fs","source":"supervisor","rule":"fs.ask[./held/]","verdict":"allow","authority":"human","op":"open","flags":577,"path":"/p/held/plan.md","operation_completed":true,"fd_delivered":true,"syscall_ret":3,"alternate_for":"/p/held/plan.md"`)
	x.add(400, `"kind":"net","source":"supervisor","rule":"net.ask[x]","verdict":"allow","authority":"human","dst":"10.0.0.1:443","proto":"tcp","relay_dst":"127.0.0.1:9","upstream_connected":true,"result_unknown":false,"best_effort":true`)
	x.add(100, `"kind":"gap","source":"supervisor","what":"enforce","why":"live-block-added","live_block":{"op":"add","kind":"exec","value":"curl","rule":"live.block[exec:curl]","by":"uid:1000 pid:5 dashboard","serial":1,"at":"2026-10-26T03:40:00Z"}`)
	x.add(100, `"kind":"gap","source":"supervisor","what":"record","why":"ringbuf-full","dropped":12,"count":12`)
	x.add(100, `"kind":"answer","source":"supervisor","ask_id":"q-9","by":"uid:1000 pid:5","after_s":2,"approved":false,"op":"open","target":"/p/a","ask_rule":"fs.ask[./]","alternate":"/p/b","alternate_dev":1,"alternate_ino":2`)
	x.add(400, `"kind":"fs","source":"seccomp","rule":"unmatched","verdict":"allow","authority":"rule","op":"open","flags":0,"path":"/etc/hosts","zz_injected":"a key no writer has"`)
	x.add(100, `"kind":"run_end","source":"supervisor","reason":"exit","exit_code":0,"resources":{"memory_peak":1024,"pids_peak":3,"cpu_usage_usec":10,"memory_events":{"oom":0,"oom_kill":0}},"supervisor":{"notifications":5,"held_ms":3,"anomalies":0,"exec_missing":1}`)
	r := x.write(t)
	for _, e := range r.AllEvents() {
		lv, err := Explain(x.root, r, e.Seq)
		if err != nil {
			t.Fatal(err)
		}
		checkFields(t, "demo-shaped", lv, map[string]bool{"zz_injected": true})
	}
}

// askRun is a run with an approved question and a denied one, each with an unrelated line slipped in between.
func askRun(t *testing.T) (*xrun, map[string]uint64) {
	x, seqs := codexShaped(t)
	seqs["cat"] = x.exec(410, 11, "300/7", false, "cat", "confidential/plan.md")
	seqs["ask"] = x.add(410, `"kind":"ask","source":"supervisor","ask_id":"q-1","ask_rule":"fs.ask_read[./confidential/]","hold":"open","op":"read","target":"/home/u/proj/confidential/plan.md"`)
	x.add(400, `"kind":"fs","source":"seccomp","rule":"unmatched","verdict":"allow","authority":"rule","op":"open","flags":0,"path":"/etc/hosts"`)
	seqs["answer"] = x.add(410, `"kind":"answer","source":"supervisor","after_s":41.7,"approved":true,"ask_id":"q-1","ask_rule":"fs.ask_read[./confidential/]","by":"uid:1000 pid:77 dashboard","op":"read","target":"/home/u/proj/confidential/plan.md"`)
	x.add(400, `"kind":"fs","source":"seccomp","rule":"unmatched","verdict":"allow","authority":"rule","op":"open","flags":0,"path":"/etc/resolv.conf"`)
	seqs["then"] = x.add(410, `"kind":"fs","source":"supervisor","rule":"fs.ask_read[./confidential/]","verdict":"allow","authority":"human","op":"open","flags":524288,"path":"/home/u/proj/confidential/plan.md","operation_completed":true,"fd_delivered":true,"syscall_ret":3`)

	seqs["ask2"] = x.add(410, `"kind":"ask","source":"supervisor","ask_id":"q-2","ask_rule":"fs.ask_read[./confidential/]","hold":"open","op":"read","target":"/home/u/proj/confidential/keys.md"`)
	seqs["answer2"] = x.add(410, `"kind":"answer","source":"supervisor","after_s":3,"approved":false,"answer_reason":"ask-denied","ask_id":"q-2","ask_rule":"fs.ask_read[./confidential/]","by":"uid:1000 pid:77","op":"read","target":"/home/u/proj/confidential/keys.md"`)
	seqs["then2"] = x.add(410, `"kind":"fs","source":"supervisor","rule":"fs.ask_read[./confidential/]","verdict":"refused","authority":"human","reason":"ask-denied","op":"open","flags":0,"path":"/home/u/proj/confidential/keys.md","errno":13`)
	seqs["mirror2"] = x.add(410, `"kind":"refused","source":"supervisor","rule":"fs.ask_read[./confidential/]","reason":"ask-denied","op":"read","target":"/home/u/proj/confidential/keys.md"`)
	return x, seqs
}

// TestAskLinksTheQuestionItsAnswerAndWhatFollowed: the ask line, its answer and the line the answer let through all
// return the same Ask block, naming the person; a denial's refusal and its mirror do too, and the refusal's sentence
// says a person refused it and what the agent got.
func TestAskLinksTheQuestionItsAnswerAndWhatFollowed(t *testing.T) {
	x, seqs := askRun(t)
	r := x.write(t)
	explain := func(name string) *LineView {
		t.Helper()
		lv, err := Explain(x.root, r, seqs[name])
		if err != nil {
			t.Fatal(err)
		}
		return lv
	}
	var first *AskFacts
	for _, name := range []string{"ask", "answer", "then"} {
		a := explain(name).Ask
		if a == nil {
			t.Fatalf("%s: no ask block", name)
		}
		if a.AskID != "q-1" || a.AskSeq != seqs["ask"] || a.AnswerSeq != seqs["answer"] || !a.HasAsk || !a.Answered {
			t.Errorf("%s: ask %+v", name, a)
		}
		if a.ByWords != "alice, from the dashboard" || a.After != "41.7 s" || a.Approved == nil || !*a.Approved {
			t.Errorf("%s: by %q after %q approved %v", name, a.ByWords, a.After, a.Approved)
		}
		if len(a.ConsequenceSeqs) != 1 || a.ConsequenceSeqs[0] != seqs["then"] {
			t.Errorf("%s: consequences %v, want [%d]", name, a.ConsequenceSeqs, seqs["then"])
		}
		if first == nil {
			first = a
		} else if a.Sentence != first.Sentence {
			t.Errorf("%s: sentence %q differs from the ask's %q", name, a.Sentence, first.Sentence)
		}
	}
	if want := "asked to read /home/u/proj/confidential/plan.md · allowed once by alice, from the dashboard after 41.7 s"; first.Sentence != want {
		t.Errorf("ask sentence %q, want %q", first.Sentence, want)
	}
	if s := explain("ask").Sentence; !strings.HasPrefix(s, "cat (pid 410, child of bash) asked to read") {
		t.Errorf("ask line sentence %q", s)
	}
	if s := explain("then").Sentence; !strings.HasSuffix(s, "; a person allowed it") {
		t.Errorf("approved open sentence %q", s)
	}

	for _, name := range []string{"ask2", "answer2", "then2", "mirror2"} {
		a := explain(name).Ask
		if a == nil || a.AskID != "q-2" {
			t.Fatalf("%s: ask %+v, want q-2", name, a)
		}
		if got := fmt.Sprint(a.ConsequenceSeqs); got != fmt.Sprint([]uint64{seqs["then2"], seqs["mirror2"]}) {
			t.Errorf("%s: consequences %s", name, got)
		}
		if a.ByWords != "alice" || !strings.Contains(a.Sentence, "denied by alice after 3.0 s") {
			t.Errorf("%s: by %q sentence %q", name, a.ByWords, a.Sentence)
		}
	}
	then2 := explain("then2")
	if then2.MirroredBy == nil || *then2.MirroredBy != seqs["mirror2"] {
		t.Errorf("then2 mirrored by %v, want %d", then2.MirroredBy, seqs["mirror2"])
	}
	if !strings.Contains(then2.Sentence, "a person refused it: a person said no, and the agent got EACCES") {
		t.Errorf("denied open sentence %q", then2.Sentence)
	}
	if m := explain("mirror2"); m.MirrorOf == nil || *m.MirrorOf != seqs["then2"] || !strings.HasPrefix(m.Sentence, "Tego's record of the refusal on line #") {
		t.Errorf("mirror: of %v sentence %q", m.MirrorOf, m.Sentence)
	}
	if explain("curl").Ask != nil {
		t.Error("a line outside any question has an ask block")
	}
}

// TestBlobsAreCheckedAndSplicesNamed: an argv blob reads back whole and checked, masked; a blob whose content does not
// hash to its name is not verified and shows nothing; a body blob under "blob" reads back; a request's splice hashes
// are named, never read.
func TestBlobsAreCheckedAndSplicesNamed(t *testing.T) {
	x := newXRun(t, "r-3f9c2a1b-0dmeggtrb9ncn-blob01")
	dir := filepath.Join(x.root, x.run)
	good := putBlob(t, dir, []byte(`["/bin/bash","-c","curl -H 'Authorization: Bearer abcdef0123456789' https://example.com"]`))
	forged := sha256.Sum256([]byte(`["what the chain vouches for"]`))
	bad := hex.EncodeToString(forged[:])
	if err := os.WriteFile(filepath.Join(dir, "blobs", bad), []byte(`["something else"]`), 0o644); err != nil {
		t.Fatal(err)
	}
	body := putBlob(t, dir, []byte(`{"content":"hello"}`))
	x.add(100, `"kind":"run_start","source":"supervisor","command":["codex"],"cwd":"/p","launcher_pid":100,"launcher_start_ns":5`)
	gs := x.add(200, `"kind":"exec","source":"seccomp","rule":"exec[bash]","verdict":"allow","authority":"rule","argv_blob":"`+good+`","argv_truncated":true,"exec_id":"r/200/6","parent_exec_id":"r/100/5","path":"/bin/bash"`)
	bs := x.add(200, `"kind":"exec","source":"seccomp","rule":"exec[bash]","verdict":"allow","authority":"rule","argv_blob":"`+bad+`","argv_truncated":true,"exec_id":"r/200/6","parent_exec_id":"r/100/5","path":"/bin/bash"`)
	ss := x.add(100, `"kind":"ssl_response","source":"forwarder","status":200,"latency_ms":3,"parser_version":"anthropic/1","blob":"`+body+`"`)
	rs := x.add(100, `"kind":"ssl_request","source":"forwarder","endpoint":"anthropic","method":"POST","body_sha256":"`+body+`","frame":"`+body+`","messages":"`+body+`"`)
	r := x.write(t)
	field := func(seq uint64, key string) Field {
		t.Helper()
		lv, err := Explain(x.root, r, seq)
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range lv.Fields {
			if f.Key == key {
				return f
			}
		}
		t.Fatalf("#%d has no %s", seq, key)
		return Field{}
	}
	g := field(gs, "argv_blob")
	if g.Blob == nil || !g.Blob.Verified || !strings.HasPrefix(g.Blob.Inline, "/bin/bash -c curl") || strings.Contains(g.Blob.Inline, "abcdef0123456789") {
		t.Errorf("good blob %+v", g.Blob)
	}
	if !strings.Contains(g.Value, "checked against its hash") || g.Blob.Size == 0 {
		t.Errorf("good blob words %q size %d", g.Value, g.Blob.Size)
	}
	b := field(bs, "argv_blob")
	if b.Blob == nil || b.Blob.Verified || b.Blob.Inline != "" || !strings.Contains(b.Value, "does not match its hash") {
		t.Errorf("forged blob %+v (%q)", b.Blob, b.Value)
	}
	if s := field(ss, "blob"); s.Blob == nil || !s.Blob.Verified || s.Blob.Inline != `{"content":"hello"}` {
		t.Errorf("body blob %+v", s.Blob)
	}
	for _, k := range []string{"body_sha256", "frame", "messages"} {
		if f := field(rs, k); !f.Splice || f.Blob != nil || f.Value != "stored as a splice; not shown here" {
			t.Errorf("%s: %+v", k, f)
		}
	}
}

// TestIntegrityNamesThePlaceInTheChain: position, the line before, and a prev that does not name it.
func TestIntegrityNamesThePlaceInTheChain(t *testing.T) {
	x, seqs := codexShaped(t)
	// Break line bash's link: its prev names a hash no line has.
	i := seqs["bash"]
	x.lines[i] = strings.Replace(x.lines[i], `"prev":"`+x.ids[i-1]+`"`, `"prev":"`+strings.Repeat("0", 64)+`"`, 1)
	r := x.write(t)
	for name, wantOK := range map[string]bool{"start": true, "codex": true, "bash": false, "curl": true} {
		lv, err := Explain(x.root, r, seqs[name])
		if err != nil {
			t.Fatal(err)
		}
		env := lv.Envelope
		if env.PrevOK != wantOK {
			t.Errorf("%s: prev ok %v, want %v", name, env.PrevOK, wantOK)
		}
		if env.Position != int(seqs[name])+1 || env.Total != len(x.lines) || env.ID != x.ids[seqs[name]] {
			t.Errorf("%s: position %d of %d id %s", name, env.Position, env.Total, env.ID)
		}
		if seqs[name] > 0 && env.PrevSeq != seqs[name]-1 {
			t.Errorf("%s: prev seq %d", name, env.PrevSeq)
		}
	}
	if w := ChainWords(Chain{State: ChainBroken, AtLine: true, Line: 2, Reason: "prev mismatch"}); !strings.Contains(w, "breaks at line #2") {
		t.Errorf("chain words %q", w)
	}
	if w := ChainWords(Chain{State: ChainVerified, Lines: 9, Anchored: true}); !strings.Contains(w, "all 9 lines") {
		t.Errorf("chain words %q", w)
	}
}

// TestAskDecisionNamesThePersonAndTheRule: a read a person refused reads "Refused: a person said no", decided by that
// person and the rule that asked, on the refusal and its mirror; a question nobody answered reads "Refused: nobody
// answered in time"; an allowed line, a rule's own refusal and the answer line have no such words.
func TestAskDecisionNamesThePersonAndTheRule(t *testing.T) {
	x, seqs := askRun(t)
	seqs["ask3"] = x.add(410, `"kind":"ask","source":"supervisor","ask_id":"q-3","ask_rule":"fs.ask_read[./confidential/]","hold":"open","op":"read","target":"/home/u/proj/confidential/late.md"`)
	seqs["answer3"] = x.add(410, `"kind":"answer","source":"supervisor","after_s":60,"approved":false,"answer_reason":"ask-timeout","ask_id":"q-3","ask_rule":"fs.ask_read[./confidential/]","op":"read","target":"/home/u/proj/confidential/late.md"`)
	seqs["then3"] = x.add(410, `"kind":"fs","source":"supervisor","rule":"fs.ask_read[./confidential/]","verdict":"refused","authority":"rule","reason":"ask-timeout","op":"open","flags":0,"path":"/home/u/proj/confidential/late.md","errno":13`)
	seqs["denied"] = x.add(410, `"kind":"fs","source":"seccomp","rule":"fs.deny_read[~/.ssh/]","verdict":"refused","authority":"rule","reason":"read-denied","op":"open","flags":0,"path":"/home/u/.ssh/id_rsa","errno":13`)
	r := x.write(t)
	for _, tc := range []struct{ name, decision, by string }{
		{"then2", "Refused: a person said no", "alice, asked by fs.ask_read[./confidential/]"},
		{"mirror2", "Refused: a person said no", "alice, asked by fs.ask_read[./confidential/]"},
		{"then3", "Refused: nobody answered in time", "the time limit, asked by fs.ask_read[./confidential/]"},
		{"then", "", ""},
		{"denied", "", ""},
		{"answer2", "", ""},
	} {
		lv, err := Explain(x.root, r, seqs[tc.name])
		if err != nil {
			t.Fatal(err)
		}
		if lv.Decision != tc.decision || lv.DecidedBy != tc.by {
			t.Errorf("%s: decision %q by %q, want %q by %q", tc.name, lv.Decision, lv.DecidedBy, tc.decision, tc.by)
		}
	}
}

// BenchmarkExplain explains a line of a 12,000-line resident run, warm (the index built): the line page's cost.
func BenchmarkExplain(b *testing.B) {
	x := newXRun(b, "r-3f9c2a1b-0dmeggtrb9ncn-bench1")
	x.add(100, `"kind":"run_start","source":"supervisor","command":["codex"],"cwd":"/p","launcher_pid":100,"launcher_start_ns":5,"launcher_uid":1000,"launcher_user":"alice"`)
	x.exec(200, 6, "100/5", false, "codex")
	for len(x.lines) < 12_000 {
		pid := 1000 + len(x.lines)/20
		if len(x.lines)%20 == 0 {
			x.exec(pid, 7, "200/6", false, "/bin/bash", "-c", "ls")
			continue
		}
		x.add(pid, `"kind":"fs","source":"seccomp","rule":"unmatched","verdict":"allow","authority":"rule","op":"open","flags":0,"path":"/p/src/file.go","operation_completed":true,"fd_delivered":true,"syscall_ret":3`)
	}
	r := x.write(b)
	seq := uint64(len(x.lines) - 7)
	if _, err := Explain(x.root, r, seq); err != nil { // build the index once, as the first page view does
		b.Fatal(err)
	}
	b.ResetTimer()
	for b.Loop() {
		if _, err := Explain(x.root, r, seq); err != nil {
			b.Fatal(err)
		}
	}
}
