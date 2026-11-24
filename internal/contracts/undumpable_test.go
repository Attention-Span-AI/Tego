// SPDX-License-Identifier: Apache-2.0

package contracts

import (
	"errors"
	"os"
	"os/exec"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// helperProbeEnv makes TestMain's helper branch run HelperMain over an argument it does not know and say what the process's
// dumpable flag is when it returns.
const helperProbeEnv = "TEGO_TEST_CONTRACTS_HELPER_PROBE"

// TestContractsHelperIsUndumpable: a launcher or worker re-executes the program image, so it is dumpable again whatever its
// caller was, and it is handed the contract text, the machine's snapshot and the recorded path. The real HelperMain, in a
// real child, leaves the dumpable flag at 0 (it reaches its argument check only after the hold).
func TestContractsHelperIsUndumpable(t *testing.T) {
	cmd := exec.Command(os.Args[0], HelperCommand, "probe")
	cmd.Env = append(os.Environ(), helperProbeEnv+"=1")
	out, err := cmd.Output()
	if err == nil {
		t.Fatalf("the helper given an argument it does not know ended well: %q", out)
	}
	if got, want := string(out), "dumpable=false err=<nil> code=125\n"; got != want {
		t.Fatalf("the helper said %q, want %q", got, want)
	}
}

// TestContractsHelperDoesNothingWhenItCannotBeMadeUndumpable: a helper that cannot be made undumpable starts no worker and
// serves no request, for either mode.
func TestContractsHelperDoesNothingWhenItCannotBeMadeUndumpable(t *testing.T) {
	old := makeUndumpable
	t.Cleanup(func() { makeUndumpable = old })
	holds := 0
	makeUndumpable = func() error { holds++; return errors.New("prctl: not permitted") }
	for _, mode := range []string{"launcher", "idle-launcher", "worker", "idle-worker"} {
		if code := HelperMain([]string{mode}); code != identity.ExitError {
			t.Errorf("HelperMain(%s) with a failing hold = %d, want %d", mode, code, identity.ExitError)
		}
	}
	if holds != 4 {
		t.Errorf("the hold was tried %d times for four modes", holds)
	}
	if code := HelperMain(nil); code != identity.ExitError || holds != 4 {
		t.Errorf("HelperMain with no mode = %d after %d holds; want %d and no further hold", code, holds, identity.ExitError)
	}
}
