// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

func TestReceiptRefusesCompleteBadTimestamp(t *testing.T) {
	for _, stamp := range []string{"2026-09-22T09:00:00,002Z", "2026-09-22T9:00:00Z", "2026-09-22T09:00:00+24:00", "2026-09-22T09:00:00+00:60"} {
		for _, terminated := range []bool{true, false} {
			t.Run(stamp+map[bool]string{true: "/terminated", false: "/unterminated"}[terminated], func(t *testing.T) {
				r := ledgerOf(t, boundRun())
				path := filepath.Join(r.Dir(), ledger.EventsFile)
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				lines := bytes.Split(bytes.TrimSuffix(data, []byte{'\n'}), []byte{'\n'})
				last := string(lines[len(lines)-1])
				begin := strings.Index(last, `"ts":"`) + 6
				end := begin + strings.IndexByte(last[begin:], '"')
				lines[len(lines)-1] = []byte(last[:begin] + stamp + last[end:])
				data = bytes.Join(lines, []byte{'\n'})
				if terminated {
					data = append(data, '\n')
				}
				if err := os.WriteFile(path, data, 0600); err != nil {
					t.Fatal(err)
				}
				rc, err := Compute(context.Background(), r, Options{Bind: &testBy})
				if rc != nil || !errors.Is(err, record.ErrMalformedLine) {
					t.Fatalf("receipt=%+v err=%v", rc, err)
				}
			})
		}
	}
}

// The original bound receipt must report the complete altered record as malformed at its final
// line. Treating it as a torn tail hides the timestamp failure behind an anchor mismatch.
func TestReceiptCheckRefusesCompleteBadTimestamp(t *testing.T) {
	for _, stamp := range []string{"2026-09-22T09:00:00,002Z", "2026-09-22T9:00:00Z", "2026-09-22T09:00:00+24:00", "2026-09-22T09:00:00+00:60"} {
		for _, terminated := range []bool{true, false} {
			t.Run(stamp+map[bool]string{true: "/terminated", false: "/unterminated"}[terminated], func(t *testing.T) {
				p := boundPair(t, boundRun())
				path := filepath.Join(p.dir, ledger.EventsFile)
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				lines := bytes.Split(bytes.TrimSuffix(data, []byte{'\n'}), []byte{'\n'})
				last := string(lines[len(lines)-1])
				begin := strings.Index(last, `"ts":"`) + len(`"ts":"`)
				end := begin + strings.IndexByte(last[begin:], '"')
				lines[len(lines)-1] = []byte(last[:begin] + stamp + last[end:])
				data = bytes.Join(lines, []byte{'\n'})
				if terminated {
					data = append(data, '\n')
				}
				if err := os.WriteFile(path, data, 0o600); err != nil {
					t.Fatal(err)
				}
				res := checked(t, p, testBy)
				if res.Result != CheckMismatch {
					t.Fatalf("result = %s, want mismatch", res.Result)
				}
				if got := step(res, "chain"); got.Result != StepFail || !strings.Contains(got.Why, "ts:") {
					t.Fatalf("chain = %+v, want malformed timestamp", got)
				}
				if got := step(res, "head"); got.Result != StepNotChecked {
					t.Fatalf("head = %+v, want not checked after malformed line", got)
				}
			})
		}
	}
}
