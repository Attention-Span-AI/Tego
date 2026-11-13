// SPDX-License-Identifier: Apache-2.0

package execmatchdiff_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/attention-span-ai/tego/pkg/policy/execmatch"
	old "github.com/attention-span-ai/tego/test/execmatchdiff/internal/baseline"
	oldrows "github.com/attention-span-ai/tego/test/execmatchdiff/internal/baseline/rows"
)

// A skipped generated pattern must be invalid in both grammars. Otherwise a
// compile regression would silently remove its entire invocation corpus.
func generatedCompileRegression(entry string, list execmatch.List, currentErr error) error {
	if currentErr == nil {
		return nil
	}
	if _, err := old.Parse(entry, old.List(list), oldrows.Builtin()); err != nil {
		return nil
	}
	return fmt.Errorf("generated %s entry %q compiled in the release but is now rejected: %w", list, entry, currentErr)
}

func TestGeneratedPatternCompilerRegressionIsNotSkipped(t *testing.T) {
	for _, list := range []execmatch.List{execmatch.ListAllow, execmatch.ListDeny, execmatch.ListAsk} {
		if err := generatedCompileRegression("go run", list, errors.New("injected compiler rejection")); err == nil {
			t.Errorf("%s silently skipped a released-valid entry", list)
		}
		if err := generatedCompileRegression("", list, errors.New("empty pattern")); err != nil {
			t.Errorf("%s rejected an entry invalid in both grammars: %v", list, err)
		}
		if err := generatedCompileRegression("go run", list, nil); err != nil {
			t.Errorf("%s rejected an admitted generated entry: %v", list, err)
		}
	}
}
