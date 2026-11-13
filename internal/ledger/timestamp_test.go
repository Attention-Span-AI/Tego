// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

func TestReadersRefuseCompleteBadTimestamp(t *testing.T) {
	for _, stamp := range []string{"2026-09-22T09:00:00,002Z", "2026-09-22T9:00:00Z", "2026-09-22T09:00:00+24:00", "2026-09-22T09:00:00+00:60"} {
		for _, terminated := range []bool{true, false} {
			t.Run(stamp+map[bool]string{true: "/terminated", false: "/unterminated"}[terminated], func(t *testing.T) {
				dir, _ := closedRun(t, 1)
				path := filepath.Join(dir, EventsFile)
				lines := bytes.Split(bytes.TrimSuffix(readFile(t, path), []byte{'\n'}), []byte{'\n'})
				last := string(lines[len(lines)-1])
				begin := strings.Index(last, `"ts":"`) + 6
				end := begin + strings.IndexByte(last[begin:], '"')
				lines[len(lines)-1] = []byte(last[:begin] + stamp + last[end:])
				data := bytes.Join(lines, []byte{'\n'})
				if terminated {
					data = append(data, '\n')
				}
				if err := os.WriteFile(path, data, 0600); err != nil {
					t.Fatal(err)
				}
				r, err := OpenReader(dir)
				if err != nil {
					t.Fatal(err)
				}
				defer r.Close()
				r.SkipNewerVersions() // refused v1 timestamps must never become skippable newer records
				binder := r.Bind()
				n := 0
				for _, err := range r.Lines() {
					if err != nil {
						t.Fatal(err)
					}
					n++
				}
				if n != len(lines) {
					t.Fatalf("Lines hid complete record: %d", n)
				}
				if bound := binder.Bound(); !errors.Is(bound.Err, record.ErrMalformedLine) || bound.Head != "" {
					t.Fatalf("binding: %+v", bound)
				}
				if state, err := r.State(); !errors.Is(err, ErrCorruptLedger) {
					t.Fatalf("State %s %v", state, err)
				}
				fl, err := Follow(dir, Cursor{})
				if err != nil {
					t.Fatal(err)
				}
				defer fl.Close()
				if got := followAll(t, fl, time.Second); !errors.Is(got.err, record.ErrMalformedLine) {
					t.Fatalf("Follower: %v", got.err)
				}
				for _, backward := range []bool{false, true} {
					seq := r.Entries()
					if backward {
						seq = r.Backward()
					}
					var got error
					for _, err := range seq {
						if err != nil {
							got = err
							break
						}
					}
					if !errors.Is(got, ErrCorruptLedger) || !errors.Is(got, record.ErrMalformedLine) {
						t.Fatalf("backward=%v: %v", backward, got)
					}
				}
				if _, err := r.Verify(context.Background(), &memAnchor{}); !errors.Is(err, record.ErrMalformedLine) {
					t.Fatalf("Verify: %v", err)
				}
				off := int64(len(lines[0]) + 1)
				n = 0
				for _, err := range r.LinesFrom(off) {
					if err != nil {
						t.Fatal(err)
					}
					n++
				}
				want := len(lines) - 1
				if !terminated {
					want--
				} // This live append poller holds every unterminated tail.
				if n != want {
					t.Fatalf("LinesFrom: %d, want %d", n, want)
				}
				w, err := Open(dir, testRef, WithAnchor(&memAnchor{}))
				if w != nil {
					_ = w.Close(record.RunEndPayload{Reason: record.RunEndExit})
				}
				if !errors.Is(err, record.ErrMalformedLine) {
					t.Fatalf("resume: %v", err)
				}
				if got := readFile(t, path); !bytes.Equal(got, data) {
					t.Fatal("resume changed a complete malformed record")
				}
			})
		}
	}
}
