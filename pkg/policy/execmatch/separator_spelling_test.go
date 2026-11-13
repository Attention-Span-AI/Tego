// SPDX-License-Identifier: Apache-2.0

package execmatch_test

import (
	"errors"
	"github.com/attention-span-ai/tego/pkg/policy/execmatch"
	"github.com/attention-span-ai/tego/pkg/policy/execmatch/rows"
	"testing"
)

func TestSeparatorKeepsContractOptionSpelling(t *testing.T) {
	for _, entry := range []string{"npm --tag --g -- install", "npm --tag --g ---global -- install"} {
		_, err := execmatch.Parse(entry, execmatch.ListAllow, rows.Builtin())
		if err == nil {
			t.Errorf("invocation shorthand lookup widened literal contract spelling %q", entry)
		}
		if entry == "npm --tag --g ---global -- install" {
			var syntax *execmatch.SyntaxError
			if !errors.As(err, &syntax) || len(syntax.Warnings) == 0 {
				t.Errorf("spelling warning lost: %v", err)
			}
		}
	}
}

func TestSeparatorKeepsLiteralOptionLookingValue(t *testing.T) {
	p, err := execmatch.Parse("npm --tag ---g -- install", execmatch.ListAllow, rows.Builtin())
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, o := range p.Opts {
		if o.Opt != nil && o.Opt.Name == "tag" && o.HasValue && o.Value == "---g" {
			found = true
		}
	}
	if !found || len(p.Warnings) != 0 {
		t.Errorf("a literal option value became an option spelling: %+v warnings=%v", p.Opts, p.Warnings)
	}
}
