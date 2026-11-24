// SPDX-License-Identifier: Apache-2.0

package rulesview

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/attention-span-ai/tego/internal/control/pathcheck"
	"github.com/attention-span-ai/tego/internal/testutil"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// A file that answers regular-file metadata but fails every read with EIO. This exercises the real helper read rather
// than a metadata failure. It is not /proc/self/mem, which the undumpable helper cannot open (testutil.EIOFile).
func TestInForceKeepsSourceReadAvailability(t *testing.T) {
	unreadable := testutil.EIOFile(t)
	st, err := os.Lstat(unreadable)
	if err != nil || !st.Mode().IsRegular() {
		t.Fatalf("metadata control: stat=%v err=%v", st, err)
	}
	if _, _, err := readNoFollow(unreadable); !errors.Is(err, syscall.EIO) {
		t.Fatalf("read control: %v, want EIO", err)
	}
	f := newFixture(t, "r-aaaaaaaa-0000000000017-srcerr")
	lines := strings.ReplaceAll(f.lines.String(), f.source, unreadable)
	if err := os.WriteFile(filepath.Join(f.dir, "events.jsonl"), []byte(lines), 0o600); err != nil {
		t.Fatal(err)
	}
	v := InForce(context.Background(), f.root, f.run, Options{Machine: f.m})
	if v.Err != "" || v.Contract.Text == "" || v.Positions != PositionsCopy || !strings.Contains(v.PositionsWhy, pathcheck.Unavailable) {
		t.Fatalf("source-read failure lost the recorded copy: err=%q positions=%q why=%q copy=%q", v.Err, v.Positions, v.PositionsWhy, v.Contract.Text)
	}
	assertSourceUnavailable(t, v)
}

type unavailableProfile struct{ cause error }

func (p unavailableProfile) Resolve(string) (string, []byte, error) {
	return "", nil, &os.PathError{Op: "read", Path: "/profiles/base.yaml", Err: p.cause}
}

func TestInForceKeepsProfileReadAvailability(t *testing.T) {
	for _, cause := range []error{syscall.EIO, syscall.ENOTCONN, context.DeadlineExceeded} {
		t.Run(cause.Error(), func(t *testing.T) {
			f := newFixture(t, "r-aaaaaaaa-0000000000018-prferr")
			text := strings.Replace(sourceText, "capture: off\n", "capture: off\nextends: base\n", 1)
			f.startFrom(t, text, profileMap{"base": "env:\n  pass: [HOME]\n"})
			v := f.inForceWith(t, Options{Machine: f.m, Profiles: unavailableProfile{cause}})
			if v.Positions != PositionsCopy || v.Contract.Text == "" || !strings.Contains(v.PositionsWhy, pathcheck.Unavailable) {
				t.Fatalf("profile read failure lost its copy or reason: positions=%q why=%q copy=%q", v.Positions, v.PositionsWhy, v.Contract.Text)
			}
			assertSourceUnavailable(t, v)
		})
	}
}

func assertSourceUnavailable(t *testing.T, v *InForceView) {
	t.Helper()
	encoded, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var projection struct {
		SourceUnavailable string `json:"source_unavailable"`
	}
	if err := json.Unmarshal(encoded, &projection); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(projection.SourceUnavailable, pathcheck.Unavailable) {
		t.Fatalf("view lost source availability: source=%q err=%q positions=%q why=%q", v.Source, v.Err, v.Positions, v.PositionsWhy)
	}
}

// The loader returns the first error separately, but every diagnostic matters.
type mixedProfiles struct{}

func (mixedProfiles) Resolve(name string) (string, []byte, error) {
	if name == "missing" {
		return "", nil, os.ErrNotExist
	}
	return unavailableProfile{syscall.ENOTCONN}.Resolve(name)
}
func TestInForceChecksEveryProfileDiagnostic(t *testing.T) {
	for _, order := range []string{"missing, offline", "offline, missing"} {
		t.Run(order, func(t *testing.T) {
			f := newFixture(t, "r-aaaaaaaa-0000000000019-mixedx")
			text := sourceText + "\nextends: [" + order + "]\n"
			f.startFrom(t, text, profileMap{"missing": "{}", "offline": "{}"})
			_, ds, err := agent.LoadBytes(f.source, []byte(text), mixedProfiles{})
			if err == nil || len(ds) != 2 {
				t.Fatalf("diagnostic control: %v %v", ds, err)
			}
			before := ds[0].Error() + ds[1].Error()
			v := f.inForceWith(t, Options{Machine: f.m, Profiles: mixedProfiles{}})
			assertSourceUnavailable(t, v)
			if v.Contract.Text == "" || v.Positions != PositionsCopy {
				t.Fatal("lost copy")
			}
			_, after, _ := agent.LoadBytes(f.source, []byte(text), mixedProfiles{})
			if before != after[0].Error()+after[1].Error() {
				t.Fatal("diagnostic text changed")
			}
		})
	}
}
