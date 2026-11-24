// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// TestVerifyAlongIsVerify: the chain check that rides the one pass a view makes over the record (Reader.VerifyAlong) gives
// what Verify gives, report and error, over a run as written and over each way a record can be damaged: so tego run's end
// summary reads the ledger once for its receipt and its "chain verified", not twice.
func TestVerifyAlongIsVerify(t *testing.T) {
	type mutate func(t *testing.T, dir string)
	edit := func(f func(b []byte) []byte) mutate {
		return func(t *testing.T, dir string) {
			t.Helper()
			path := filepath.Join(dir, EventsFile)
			b, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, f(b), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	dropLines := func(n int) mutate {
		return edit(func(b []byte) []byte {
			lines := bytes.SplitAfter(b, []byte("\n"))
			return bytes.Join(lines[:len(lines)-1-n], nil)
		})
	}
	for _, c := range []struct {
		name   string
		mutate mutate
		noAnch bool // verify without an anchor
		empty  bool // an anchor with no line for the run
	}{
		{name: "as written"},
		{name: "as written, no anchor", noAnch: true},
		{name: "no anchor line", empty: true},
		{name: "last line dropped", mutate: dropLines(1)},
		{name: "three lines dropped", mutate: dropLines(3)},
		{name: "a line altered", mutate: edit(func(b []byte) []byte {
			i := bytes.Index(b, []byte(`"why":"e1"`))
			b[i+len(`"why":"e`)] = '9'
			return b
		})},
		{name: "bytes after run_end", mutate: edit(func(b []byte) []byte { return append(b, `{"v":1,"seq":9`...) })},
		{name: "garbage after run_end", mutate: edit(func(b []byte) []byte { return append(b, "garbage\n"...) })},
		{name: "NUL tail", mutate: edit(func(b []byte) []byte { return append(b, make([]byte, 64)...) })},
		{name: "torn last line", mutate: edit(func(b []byte) []byte { return b[:len(b)-10] }), noAnch: true},
		{name: "a line twice", mutate: edit(func(b []byte) []byte {
			lines := bytes.SplitAfter(b, []byte("\n"))
			return bytes.Join(append(lines[:3:3], lines[2:]...), nil)
		})},
		{name: "empty record", mutate: edit(func([]byte) []byte { return nil })},
	} {
		t.Run(c.name, func(t *testing.T) {
			dir, anchor := closedRun(t, 3)
			if c.mutate != nil {
				c.mutate(t, dir)
			}
			var a ChainAnchor = anchor
			switch {
			case c.noAnch:
				a = nil
			case c.empty:
				a = &memAnchor{}
			}
			want, wantErr := verifyErr(t, dir, a)

			r, err := OpenReader(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = r.Close() }()
			r.SkipNewerVersions()
			v := r.VerifyAlong()
			for range r.Iter() { // a view that reads the whole record, as the receipt does
			}
			got, gotErr := v.Finish(context.Background(), a)
			if !reflect.DeepEqual(got, want) {
				t.Errorf("report\n along  %+v\n verify %+v", got, want)
			}
			if (gotErr == nil) != (wantErr == nil) || (gotErr != nil && gotErr.Error() != wantErr.Error()) {
				t.Errorf("error\n along  %v\n verify %v", gotErr, wantErr)
			}
		})
	}
}

// TestVerifyAlongReadsAgainWhenThePassStoppedShort: a view that stops before the end of the record leaves the walk short,
// and Finish then answers as Verify does, from a read of its own.
func TestVerifyAlongReadsAgainWhenThePassStoppedShort(t *testing.T) {
	dir, anchor := closedRun(t, 3)
	want, wantErr := verifyErr(t, dir, anchor)
	r, err := OpenReader(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	v := r.VerifyAlong()
	n := 0
	for range r.Lines() {
		if n++; n == 2 {
			break
		}
	}
	got, gotErr := v.Finish(context.Background(), anchor)
	if gotErr != nil || wantErr != nil || !reflect.DeepEqual(got, want) {
		t.Errorf("a short pass: %+v %v, Verify %+v %v", got, gotErr, want, wantErr)
	}
}
