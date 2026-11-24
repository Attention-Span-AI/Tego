// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/contracts"
	"github.com/attention-span-ai/tego/internal/control/web"
	"github.com/attention-span-ai/tego/internal/guide/guidetest"
)

type helperStarts struct{ Launcher, Worker int }

func guideHelperCount(t *testing.T) func() helperStarts {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	marker := executable + ".count"
	if err := os.Mkdir(marker, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(marker); err != nil {
			t.Error(err)
		}
	})
	return func() helperStarts {
		entries, err := os.ReadDir(marker)
		if err != nil {
			t.Fatal(err)
		}
		var starts helperStarts
		for _, entry := range entries {
			switch {
			case strings.HasPrefix(entry.Name(), "launcher-"):
				starts.Launcher++
			case strings.HasPrefix(entry.Name(), "worker-"):
				starts.Worker++
			default:
				t.Fatalf("unknown helper process role %q", entry.Name())
			}
		}
		return starts
	}
}

func TestOverviewBootstrapSharesRequestHelper(t *testing.T) {
	f := guidetest.Make(t, guidetest.Fresh)
	t.Setenv("PATH", filepath.Join(f.Root, "absent-bin"))
	original := selfExecutable
	selfExecutable = func() (string, error) { return filepath.Join(f.Root, "absent-self"), nil }
	defer func() { selfExecutable = original }()
	count := guideHelperCount(t)
	ctx, closeHelpers := contracts.WithHelperSession(context.Background())
	defer closeHelpers()
	s, err := web.New(web.Config{Ledger: f.Ledger, Guide: guideInputs(f.Machine(t), f.Ledger, f.Anchor)})
	if err != nil {
		t.Fatal(err)
	}
	s.Prewarm(ctx)
	t.Logf("overview including binary bootstrap processes: %+v", count())
	if count() != (helperStarts{Launcher: 1, Worker: 1}) {
		t.Errorf("overview bootstrap processes: %+v; want one launcher and one worker", count())
	}
}

func TestCancelledOverviewBootstrapStartsNoHelper(t *testing.T) {
	f := guidetest.Make(t, guidetest.Fresh)
	count := guideHelperCount(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	in := guideInputs(f.Machine(t), f.Ledger, f.Anchor)(ctx)
	if in.Exe != "" {
		t.Error("cancelled bootstrap returned a checked binary")
	}
	if count() != (helperStarts{}) {
		t.Errorf("cancelled bootstrap processes: %+v", count())
	}
}
