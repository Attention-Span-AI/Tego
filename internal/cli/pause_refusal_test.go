// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/liveblock"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

func TestControlPollingReportsRefusal(t *testing.T) {
	at := time.Now().UTC()
	dir, _ := controlLedger(t, []record.GapPayload{{What: record.GapEnforce, Why: record.GapRunPaused, LiveControl: &record.LiveControlChange{Op: "pause", By: "uid:1000 pid:9 cli", Serial: 1, At: at}}})
	path := filepath.Join(dir, ledger.EventsFile)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var confirm []byte
	for l := range bytes.Lines(data) {
		if bytes.Contains(l, []byte(`"live_control"`)) {
			confirm = bytes.Clone(l)
		}
	}
	for _, validAfter := range []bool{false, true} {
		t.Run(map[bool]string{false: "damaged-confirmation", true: "valid-after-damage"}[validAfter], func(t *testing.T) {
			bad := bytes.Replace(confirm, []byte(`"v":1`), []byte(`"v":0`), 1)
			if validAfter {
				bad = []byte("{broken baseline\n")
			}
			body := append(bytes.Clone(data), bad...)
			if validAfter {
				body = append(body, confirm...)
			}
			if err := os.WriteFile(path, body, 0600); err != nil {
				t.Fatal(err)
			}
			sc := controlScan{path: path, serial: 1, off: int64(len(data))}
			why, _ := sc.next()
			if validAfter && why != record.GapRunPaused {
				t.Fatalf("lost valid confirmation: %q", why)
			}
			if !validAfter && why != "" {
				t.Fatalf("damaged confirmation accepted: %q", why)
			}
			diagnostic := fmt.Sprintf("%+v", readPause(dir, "fixture"))
			if !strings.Contains(diagnostic, "byte offset") || !strings.Contains(diagnostic, map[bool]string{true: "malformed", false: "version"}[validAfter]) {
				t.Fatalf("status reread lost refusal: %s", diagnostic)
			}
		})
	}
}

func TestPauseCommandsReportDamageAndConfirmation(t *testing.T) {
	data, err := os.ReadFile("../../spec/record/v1/fixtures/baseline/applied.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	badBaseline := bytes.Replace(bytes.Split(data, []byte{'\n'})[0], []byte(`"plane":""`), []byte(`"plane":null`), 1)

	for _, name := range []string{"pause", "resume"} {
		for _, valid := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/%t", name, valid), func(t *testing.T) {
				dir, id, _ := liveRun(t)
				if err := liveblock.MarkControl(dir); err != nil {
					t.Fatal(err)
				}
				serial := uint64(1)
				why := record.GapRunPaused
				if name == "resume" {
					if _, err := liveblock.Update(context.Background(), dir, id, func(o *liveblock.Overlay) (bool, error) { o.Pause("cli", time.Now()); return true, nil }); err != nil {
						t.Fatal(err)
					}
					serial = 2
					why = record.GapRunResumed
				}
				e := record.Event{V: record.Version, Seq: 99, Prev: strings.Repeat("a", 64), Run: id, Agent: "tester", TS: time.Now(), Kind: record.KindGap, Source: record.SourceSupervisor}
				if err := e.SetPayload(record.GapPayload{What: record.GapEnforce, Why: why, LiveControl: &record.LiveControlChange{Op: name, By: "uid:1000 pid:9 cli", Serial: serial, At: time.Now()}}); err != nil {
					t.Fatal(err)
				}
				confirm, err := e.MarshalLine()
				if err != nil {
					t.Fatal(err)
				}
				ready := make(chan error, 1)
				go func() {
					for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(time.Millisecond) {
						o, err := liveblock.Read(dir, id)
						if err != nil || o.Serial < serial {
							continue
						}
						b := append(bytes.Clone(badBaseline), '\n')
						if valid {
							b = append(b, append(confirm, '\n')...)
						} else {
							b = append(bytes.Replace(confirm, []byte(`"v":1`), []byte(`"v":0`), 1), '\n')
						}
						f, err := os.OpenFile(filepath.Join(dir, ledger.EventsFile), os.O_WRONLY|os.O_APPEND, 0)
						if err != nil {
							ready <- err
							return
						}
						_, err = f.Write(b)
						closeErr := f.Close()
						if err == nil {
							err = closeErr
						}
						ready <- err
						return
					}
					ready <- fmt.Errorf("request never written")
				}()
				code, out, errs := run(t, name, id)
				if err := <-ready; err != nil {
					t.Fatal(err)
				}
				if code != identity.ExitError || !strings.Contains(errs, "byte offset") || !strings.Contains(errs, map[bool]string{true: "plane", false: "version"}[valid]) || strings.Contains(out, "has not confirmed") {
					t.Fatalf("lost damage: code=%d out=%q errs=%q", code, out, errs)
				}
				if valid && !strings.Contains(out, map[string]string{"pause": "paused (line #99)", "resume": "resumed (line #99)"}[name]) {
					t.Fatalf("lost confirmation: %q", out)
				}
			})
		}
	}
}
