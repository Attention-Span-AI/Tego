// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/watch/adopt"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

type baselineCompatClock struct{}

func (baselineCompatClock) Now() time.Time { return time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC) }
func (baselineCompatClock) Mono() uint64   { return 123456789 }

// TestBaselineLegacyWriterStreams compares every emitted line of these two writer
// seams. The fixtures come from 2910acb2b, before baseline implementation. This
// proves run_start and run_end only; action producers and real launches need their
// own evidence. See testdata/prebaseline/README.md for provenance and exact masks.
func TestBaselineLegacyWriterStreams(t *testing.T) {
	for _, mode := range []string{"launch", "adoption"} {
		t.Run(mode, func(t *testing.T) {
			const id = "r-00000000-000000000000a-compat"
			dir := filepath.Join(t.TempDir(), id)
			w, err := ledger.Open(dir, record.RunRef{ID: id, Agent: "retriever"}, ledger.WithClock(baselineCompatClock{}), ledger.WithAnchor(nopAnchor{}))
			if err != nil {
				t.Fatal(err)
			}
			defer w.Abandon()
			r := newTestRunner(Deps{Enforce: tierBackend{tier: backend.TierLandlock}, Cwd: "/srv/proj", Build: Build{Version: "0.1.0-test", Commit: "c0ffee0", Kernel: "6.17.0-test"}, Labels: map[string]string{}, Environ: []string{}})
			r.writer, r.cmd, r.launcherStart = w, []string{"/bin/true"}, 1234
			r.rt = &agent.RuleTable{ContractPath: "/srv/agent.yaml", Contract: &agent.Contract{Name: "retriever"}}
			if mode == "adoption" {
				procRoot := t.TempDir()
				task := filepath.Join(procRoot, "4242")
				if err := os.Mkdir(task, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("/srv/proj", filepath.Join(task, "cwd")); err != nil {
					t.Fatal(err)
				}
				a := &adoption{r: r, spec: AdoptSpec{Root: adopt.Process{PID: 4242, Argv: []string{"/bin/true"}}}, env: adopt.Env{Proc: adopt.NewFS(procRoot)}}
				err = a.writeRunStart()
			} else {
				err = r.writeRunStart()
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(filepath.Join(dir, ledger.EventsFile))
			if err != nil {
				t.Fatal(err)
			}
			// All other fields, including fixed clocks, launcher start and adopted cwd,
			// remain byte-compared. IDs and prev depend on the masked host fields.
			got := string(data)
			for _, key := range []string{"id", "prev", "pid", "tid", "launcher_pid", "launcher_uid"} {
				got = regexp.MustCompile(`"`+key+`":("[^"]*"|[0-9]+)`).ReplaceAllString(got, `"`+key+`":"<`+key+`>"`)
			}
			for _, key := range []string{"launcher_user", "host", "sudo_uid", "sudo_user"} {
				got = regexp.MustCompile(`,"`+key+`":("[^"]*"|[0-9]+)`).ReplaceAllString(got, "")
			}
			if strings.Count(got, "\n") != 2 || !strings.Contains(got, `"kind":"run_start"`) || !strings.Contains(got, `"kind":"run_end"`) {
				t.Fatalf("unexpected writer kinds: %s", got)
			}
			path := filepath.Join("testdata", "prebaseline", mode+".jsonl")
			if os.Getenv("TEGO_WRITE_COMPAT") == "1" {
				if err := os.WriteFile(path, []byte(got), 0644); err != nil {
					t.Fatal(err)
				}
				return
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if got != string(want) {
				t.Fatalf("%s writer bytes changed:\ngot %s\nwant %s", mode, got, want)
			}
		})
	}
}
