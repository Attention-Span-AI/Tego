// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/attention-span-ai/tego/internal/runtime/enforce"
	"github.com/attention-span-ai/tego/internal/runtime/enforce/api"
	"github.com/attention-span-ai/tego/internal/runtime/launch"
	"github.com/attention-span-ai/tego/internal/runtime/source"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// preparedTable is a backend that keeps the table Prepare was given and then fails, so the run unwinds before any
// child exists.
type preparedTable struct {
	fakeBackend
	got *agent.RuleTable
}

var errStopAtPrepare = errors.New("stop at prepare")

func (b *preparedTable) Prepare(_ context.Context, rt *agent.RuleTable, _ enforce.RunRef) (api.Handle, error) {
	b.got = rt
	return nil, errStopAtPrepare
}

// TestTheCodexHomeGrantReachesPrepare is R10a's ordering: the run's CODEX_HOME exists and its grant is in the table
// before Prepare, so the backend builds its Landlock ruleset (which pins a path that exists) or its maps with it.
// It was made after Prepare, where no grant could reach the kernel's rules. A run that unwinds removes it.
func TestTheCodexHomeGrantReachesPrepare(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("a root launcher writes no CODEX_HOME")
	}
	xdg := privateTempDir(t)
	t.Setenv("XDG_RUNTIME_DIR", xdg)
	m, rt, root := startupFixture(t)
	b := &preparedTable{}
	_, err := Run(context.Background(), rt, []string{"/bin/true"}, Deps{
		Config: m, Cgroups: &fakeCgroups{root: t.TempDir()}, Enforce: b, Cwd: root,
		Launcher: &launch.Launcher{Exe: filepath.Join(root, "must-never-start")},
		Capture:  []source.Source{&fakeLoopback{name: "forwarder", vars: map[string]string{envOpenAIBaseURL: "http://127.0.0.1:41001/v1"}}},
		Environ:  []string{"HOME=/nonexistent"},
	})
	if !errors.Is(err, errStopAtPrepare) {
		t.Fatalf("Run = %v, want the backend's own error", err)
	}
	if b.got == nil {
		t.Fatal("Prepare never ran")
	}
	var home string
	for _, f := range b.got.FS {
		if f.Runtime == agent.CodexHomeGrant {
			home = f.Path
		}
	}
	if home == "" || filepath.Base(home) != codexHomeName || filepath.Dir(filepath.Dir(home)) != filepath.Join(xdg, "tego") {
		t.Fatalf("the table Prepare built with holds no codex home grant under %s/tego: %+v", xdg, b.got.FS)
	}
	if _, err := os.Stat(filepath.Dir(home)); !os.IsNotExist(err) {
		t.Fatalf("the unwound run left its runtime directory: %v", err)
	}
}
