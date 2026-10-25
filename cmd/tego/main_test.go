// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/adapters/claudecode"
	"github.com/attention-span-ai/tego/internal/testutil"
	"github.com/attention-span-ai/tego/pkg/spec/reason"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// mainEnv makes the test binary run main() over its own arguments, so a test drives the dispatch as tego's.
const mainEnv = "TEGO_CMD_TEST_RUN_MAIN"

func TestMain(m *testing.M) {
	if os.Getenv(mainEnv) == "1" {
		main()
		return
	}
	os.Exit(testutil.GuardedMain(m))
}

// tego runs main() in a new process with args and env, stdin empty or the given bytes.
func tego(t *testing.T, env []string, stdin string, args ...string) (stdout, stderr string, code int) {
	t.Helper()
	cmd := exec.Command(os.Args[0], args...) //nolint:gosec // the test binary itself, as tego
	cmd.Env = append(env, mainEnv+"=1")
	cmd.Stdin = strings.NewReader(stdin)
	var o, e bytes.Buffer
	cmd.Stdout, cmd.Stderr = &o, &e
	err := cmd.Run()
	if ee, ok := err.(*exec.ExitError); ok {
		return o.String(), e.String(), ee.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	return o.String(), e.String(), 0
}

// TestHookIsDispatchedBeforeTheCLI: `tego hook claude-code` is answered by the hook before the command line, which
// knows no verb hook (it answered "unknown command" with exit 2 before the arm). The hook needs no machine config and
// no home: with a machine config that does not parse and a HOME it cannot read, outside any run it is a silent exit
// 0, and inside one it reports the run's refusal. That it reads neither, which an error here would not show, is
// internal/adapters/claudecode's TestHookMakesOnlyItsDocumentedSyscalls and TestHookUnderTegoRunIsRefusedNothing.
func TestHookIsDispatchedBeforeTheCLI(t *testing.T) {
	dir := t.TempDir()
	home := filepath.Join(dir, "home")
	if err := os.Mkdir(home, 0); err != nil {
		t.Fatal(err)
	}
	bad := filepath.Join(dir, "machine.yaml")
	if err := os.WriteFile(bad, []byte("version: 0\nledger_root: [\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// testutil.TegoEnv keeps a tego that did reach the command line away from the real ~/.tego; HOME and TEGO_REASON
	// are overridden after it (the last value of a key wins).
	env := testutil.TegoEnv(t, dir, "PATH=/usr/bin:/bin", "HOME="+home, "TEGO_CONFIG="+bad, "TEGO_REASON=")
	stop := `{"session_id":"abc123","transcript_path":"/t.jsonl","cwd":"/work","permission_mode":"default","hook_event_name":"Stop","stop_hook_active":false}`
	if o, e, code := tego(t, env, stop, "hook", "claude-code"); code != 0 || o != "" || e != "" {
		t.Errorf("outside a run: exit %d, stdout %q, stderr %q; want a silent exit 0", code, o, e)
	}

	const run = "r-3f9c2a1b-0dllq06ts7400-k7m2pq"
	rundir := filepath.Join(dir, "xdg", "tego", run)
	if err := os.MkdirAll(filepath.Join(rundir, claudecode.StateDirName), 0o700); err != nil {
		t.Fatal(err)
	}
	b, err := reason.Encode(run, 1, []reason.Refusal{{Seq: 7, TS: time.Unix(0, 0), PID: 42, Payload: record.RefusedPayload{
		Op: "write", Target: "/etc/hosts", Reason: record.ReasonWriteOutsideContract, Rule: "fs.write"}}})
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(rundir, reason.FileName)
	if err := os.WriteFile(file, b, 0o600); err != nil {
		t.Fatal(err)
	}
	env = append(env, "XDG_RUNTIME_DIR="+filepath.Join(dir, "xdg"), "TEGO_REASON="+file)
	o, e, code := tego(t, env, stop, "hook", "claude-code")
	if code != 0 || e != "" || !strings.Contains(o, `"hookEventName":"Stop"`) || !strings.Contains(o, `\"/etc/hosts\"`) {
		t.Errorf("inside a run: exit %d, stdout %q, stderr %q; want the refusal as Stop's context", code, o, e)
	}
}

// TestHelpDoesNotListHook: the hook is a harness-facing verb, not a user's.
func TestHelpDoesNotListHook(t *testing.T) {
	o, e, _ := tego(t, testutil.TegoEnv(t, t.TempDir()), "", "-h")
	verbs := map[string]bool{}
	for _, line := range strings.Split(o+e, "\n") {
		if f := strings.Fields(line); len(f) > 0 {
			verbs[f[0]] = true
		}
	}
	if !verbs["run"] || !verbs["compile"] {
		t.Fatalf("tego -h lists no verbs to compare with:\n%s%s", o, e)
	}
	if verbs[claudecode.Verb] {
		t.Errorf("tego -h lists the hook:\n%s%s", o, e)
	}
}
