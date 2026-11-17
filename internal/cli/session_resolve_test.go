// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

func TestSessionNameRejectsLinkedAndMisboundRuns(t *testing.T) {
	const realID = identity.RunID("r-519c2703-0dmw7w54wuixg-naw97n")
	const planted = "r-519c2703-0dmw7w54wuixg-naabcd"
	for _, kind := range []string{"symlink", "symlink-matching-id", "misbound", "events-link"} {
		t.Run(kind, func(t *testing.T) {
			root := gcRoot(t)
			outside := t.TempDir()
			id := endedRunNamed(t, outside, realID, "helper")
			source := filepath.Join(outside, id)
			before, err := os.ReadFile(filepath.Join(source, ledger.EventsFile))
			if err != nil {
				t.Fatal(err)
			}
			snapshot := sessionTreeSnapshot(t, source)
			entry, ref := planted, "helper-abcd"
			if kind == "symlink-matching-id" {
				entry, ref = id, sessionName("helper", id)
			}
			target := filepath.Join(root, entry)
			switch kind {
			case "symlink", "symlink-matching-id":
				err = os.Symlink(source, target)
			case "misbound":
				err = os.Mkdir(target, 0700)
				if err == nil {
					err = os.WriteFile(filepath.Join(target, ledger.EventsFile), before, 0600)
				}
			case "events-link":
				err = os.Mkdir(target, 0700)
				if err == nil {
					err = os.Symlink(filepath.Join(source, ledger.EventsFile), filepath.Join(target, ledger.EventsFile))
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			if got, ok := sessionRun(ref, root); ok {
				t.Errorf("accepted %s as %s", kind, got)
			}
			for _, verb := range []string{"show", "stop", "pause", "resume"} {
				code, out, errs := run(t, "session", verb, ref)
				if code != identity.ExitUsage || out != "" || !strings.Contains(errs, "[usage]") {
					t.Errorf("%s accepted %s: exit %d out %q err %q", verb, kind, code, out, errs)
				}
			}
			after, err := os.ReadFile(filepath.Join(source, ledger.EventsFile))
			if err != nil || string(after) != string(before) {
				t.Fatalf("outside record changed: %v", err)
			}
			if after := sessionTreeSnapshot(t, source); !reflect.DeepEqual(after, snapshot) {
				t.Fatal("outside run tree changed")
			}

		})
	}
}

func TestSessionNameStillRefusesTwoMatches(t *testing.T) {
	root := gcRoot(t)
	const a = identity.RunID("r-519c2703-0dmw7w54wuixg-naabcd")
	const b = identity.RunID("r-519c2703-0dmw7w54wuixh-naabcd")
	endedRunNamed(t, root, a, "helper")
	if got, ok := sessionRun("helper-abcd", root); !ok || got != string(a) {
		t.Fatalf("valid session = %q %v", got, ok)
	}
	endedRunNamed(t, root, b, "helper")
	if got, ok := sessionRun("helper-abcd", root); ok {
		t.Fatalf("two matches resolved as %s", got)
	}
}

func sessionTreeSnapshot(t *testing.T, root string) map[string]string {
	t.Helper()
	found := map[string]string{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		found[path] = info.Mode().String()
		if !d.IsDir() {
			b, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			found[path] += string(b)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return found
}
