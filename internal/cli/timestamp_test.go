// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

func TestEventsVerifyRefusesCompleteBadTimestamp(t *testing.T) {
	for _, stamp := range []string{"2026-09-22T09:00:00,002Z", "2026-09-22T9:00:00Z", "2026-09-22T09:00:00+24:00", "2026-09-22T09:00:00+00:60"} {
		for _, terminated := range []bool{true, false} {
			t.Run(stamp+map[bool]string{true: "/terminated", false: "/unterminated"}[terminated], func(t *testing.T) {
				dir := fixtureRun(t)
				path := filepath.Join(dir, ledger.EventsFile)
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
				code, _, errs := run(t, "events", dir, "--verify")
				if code != identity.ExitFinding || !strings.Contains(errs, "ts:") {
					t.Fatalf("exit=%d stderr=%s", code, errs)
				}
			})
		}
	}
}
