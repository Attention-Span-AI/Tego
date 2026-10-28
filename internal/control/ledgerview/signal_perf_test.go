// SPDX-License-Identifier: Apache-2.0

package ledgerview

import (
	"fmt"
	"math/rand/v2"
	"testing"
	"time"
)

// agentLines is a generated agent's lines, seq from..from+n-1, the way a long Codex run reads in the ledger: reads of
// its project's files (vocab names), its own config, a secret now and then, sends to its API and to an attacker,
// route probes, retries, name lookups, programs run and refused, asks and their answers, and live blocks. step is the
// most time between two lines; a small step puts sends within NearSecretWindow of the secret reads.
func agentLines(id string, from, n, vocab int, step time.Duration, rng *rand.Rand) []string {
	t0 := time.Date(2026, 10, 27, 9, 0, 0, 0, time.UTC)
	ts := t0.Add(time.Duration(from) * step / 2)
	var ls []string
	add := func(seq int, kind, extra string) {
		ls = append(ls, line(id, "codex", seq, ts, kind, extra))
	}
	asks := from
	for seq := from; seq < from+n; seq++ {
		ts = ts.Add(time.Duration(rng.Int64N(int64(step) + 1)))
		if seq == 0 {
			add(seq, "run_start", `"tier":"landlock","command":["codex","exec","the task"],"cwd":"/home/u/proj"`)
			continue
		}
		f := rng.IntN(vocab)
		switch k := rng.IntN(100); {
		case k < 40:
			add(seq, "fs", fmt.Sprintf(`"rule":"fs.read[./]","verdict":"allow","op":"open","path":"/home/u/proj/src/f%d.go"`, f))
		case k < 46:
			add(seq, "fs", fmt.Sprintf(`"rule":"unmatched","verdict":"observed","op":"open","path":"/home/u/.codex/cache/c%d.json"`, f%50))
		case k < 48:
			add(seq, "fs", `"rule":"fs.deny_read[/home/u/.ssh/]","verdict":"refused","reason":"read-denied","op":"open","path":"/home/u/.ssh/id_rsa"`)
			add(seq, "refused", `"rule":"fs.deny_read[/home/u/.ssh/]","reason":"read-denied","op":"open","target":"/home/u/.ssh/id_rsa"`)
		case k < 49:
			add(seq, "fs", `"rule":"fs.read[./]","verdict":"allow","op":"open","path":"/home/u/proj/.env"`)
		case k < 50:
			add(seq, "fs", fmt.Sprintf(`"rule":"fs.write[./]","verdict":"allow","op":"rename","path":"/home/u/proj/a%d.tmp","path2":"/home/u/proj/confidential/p%d.md"`, f%7, f%7))
		case k < 58:
			add(seq, "net", `"rule":"net[tcp://chatgpt.com:443]","verdict":"allow","dst":"104.18.32.47:443","host":"chatgpt.com","proto":"tcp"`)
		case k < 63:
			add(seq, "net", `"rule":"unmatched","verdict":"refused","reason":"net-not-allowed","proto":"udp","dst":"104.18.32.47:65535"`)
			add(seq, "refused", `"rule":"unmatched","reason":"net-not-allowed","op":"net","target":"104.18.32.47:65535"`)
		case k < 65:
			add(seq, "refused", fmt.Sprintf(`"rule":"unmatched","reason":"net-not-allowed","op":"net","target":"172.64.144.%d:443"`, f%4))
		case k < 66:
			add(seq, "refused", `"rule":"unmatched","reason":"net-not-allowed","op":"net","target":"127.0.0.1:8802"`)
		case k < 67:
			add(seq, "net", `"rule":"unmatched","verdict":"observed","dst":"203.0.113.7:8443","proto":"tcp"`)
		case k < 70:
			add(seq, "net", `"rule":"net.resolver","verdict":"allow","dst":"127.0.0.53:53","proto":"udp"`)
		case k < 72:
			add(seq, "refused", `"rule":"unmatched","reason":"net-not-allowed","op":"connect","target":"unix:/var/run/nscd/socket"`)
		case k < 73:
			add(seq, "refused", fmt.Sprintf(`"rule":"unmatched","reason":"net-not-allowed","op":"net","target":"10.0.0.%d:53"`, f%3))
		case k < 80:
			add(seq, "exec", fmt.Sprintf(`"rule":"exec[git]","verdict":"allow","path":"/usr/bin/git","argv":["git","status","-%d"]`, f%5))
		case k < 82:
			add(seq, "refused", `"rule":"unmatched","reason":"exec-not-allowed","op":"exec","target":"/usr/bin/lsb_release"`)
		case k < 83:
			add(seq, "refused", `"rule":"live.block[exec:curl]","reason":"exec-not-allowed","op":"exec","target":"/usr/bin/curl"`)
		case k < 85:
			add(seq, "refused", `"rule":"held-unsupported","reason":"fs-gate","op":"open","target":"/dev/tty"`)
		case k < 87:
			asks++
			add(seq, "ask", fmt.Sprintf(`"ask_id":"q-%d","ask_rule":"fs.ask_read[./confidential/]","hold":"open","op":"read","target":"/home/u/proj/confidential/plan%d.md"`, asks, f%3))
		case k < 89:
			a := from + rng.IntN(asks-from+1)
			add(seq, "answer", fmt.Sprintf(`"ask_id":"q-%d","approved":%v,"by":"uid:1000","after_s":%d.5`, a, rng.IntN(2) == 0, f%60))
		case k < 90:
			add(seq, "ask", fmt.Sprintf(`"ask_id":"q-%d","hold":"exec"`, from+rng.IntN(asks-from+1)))
		default:
			add(seq, "fs", fmt.Sprintf(`"rule":"unmatched","verdict":"observed","op":"stat","path":"/usr/lib/x86_64-linux-gnu/l%d.so"`, f%300))
		}
	}
	return ls
}

// liveBig is a live run of n generated lines read by a Store, as the dashboard holds a 24/7 agent's run.
func liveBig(tb testing.TB, n int) (s *Store, root, id string, rng *rand.Rand) {
	tb.Helper()
	root, id = tb.TempDir(), "r-aaaa-0009-bigliv"
	rng = rand.New(rand.NewPCG(9, 9))
	writeRun(tb, root, id, agentLines(id, 0, n, 5000, 40*time.Millisecond, rng)...)
	markLive(tb, root, id, true)
	return Open(root), root, id, rng
}

var benchSens = Sensitive{Entries: []string{"/home/u/.ssh/", "./confidential/"}, Cwd: "/home/u/proj"}

// BenchmarkSignalLiveAppend is a live update of a 24/7 agent's run page: a 100k-line live run gains 10 lines, and its
// Signal is read on the new version (PF-1's acceptance: under 15 ms; the full pass took about 150 ms).
func BenchmarkSignalLiveAppend(b *testing.B) {
	s, root, id, rng := liveBig(b, 100_000)
	r, err := s.Run(id)
	if err != nil {
		b.Fatal(err)
	}
	Signal(r, benchSens)
	seq := 100_000
	b.ResetTimer()
	for range b.N {
		b.StopTimer()
		ls := agentLines(id, seq, 10, 5000, 40*time.Millisecond, rng)
		appendLines(b, root, id, ls...)
		seq += 10
		want := r.Lines + len(ls)
		if r, err = s.Run(id); err != nil || r.Lines != want {
			b.Fatalf("run: %v, %d lines, want %d", err, r.Lines, want)
		}
		b.StartTimer()
		Signal(r, benchSens)
	}
}

// BenchmarkSignalFull is the whole pass over the same 100k-line run, as a cold page or another contract computes it.
func BenchmarkSignalFull(b *testing.B) {
	s, _, id, _ := liveBig(b, 100_000)
	r, err := s.Run(id)
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for range b.N {
		computeSignal(r, benchSens)
	}
}

// BenchmarkCompareWarm is Compare of a 5k-line watched run against the 100k-line run with both Signals cached, as a
// second look at /compare reads it (PF-1's acceptance: under 40 ms; 196-309 ms before).
func BenchmarkCompareWarm(b *testing.B) {
	s, root, id, rng := liveBig(b, 100_000)
	w := "r-aaaa-0008-watchx"
	ls := agentLines(w, 0, 5000, 300, 40*time.Millisecond, rng)
	ls[0] = line(w, "codex", 0, time.Date(2026, 10, 27, 8, 0, 0, 0, time.UTC), "run_start", `"tier":"observe","command":["codex","exec","the task"],"cwd":"/home/u/proj"`)
	writeRun(b, root, w, ls...)
	a, err := s.Run(w)
	if err != nil {
		b.Fatal(err)
	}
	big, err := s.Run(id)
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for range b.N {
		CompareSignals(a, big, Signal(a, Sensitive{Cwd: a.Cwd}), Signal(big, benchSens), false)
	}
}
