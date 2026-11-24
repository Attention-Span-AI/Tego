// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"context"
	"strconv"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/control/rulesview"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// TestCheckNeverShowsAnEnvValue: in the dashboard's editor, the error of a text that does not compile never shows an
// env value, whatever its length: neither a value of env.set the service put back, nor a value typed where a
// variable's name belongs (A40; rule (a) of pkg/spec/identity envtext.go). The compiler prints no value, so the
// message is whole: nothing in it had to be cut out.
func TestCheckNeverShowsAnEnvValue(t *testing.T) {
	for _, v := range []string{"@", "@&", "@&;", "@&;-a-long-secret-value"} {
		t.Run(strconv.Itoa(len(v))+" bytes", func(t *testing.T) { // the value is kept out of the test's own paths
			f := newFixture(t)
			// The real compiler, as the dashboard runs it (no test hook), with the machine's built-in settings.
			f.s.Compile = nil
			m := config.Builtin()
			m.Home = f.s.Home
			f.s.Machine, f.s.PATH = m, "/usr/bin:/bin"
			writeFile(t, f.contract, strings.Replace(baseText, "exec:\n", "env:\n  set:\n    TOKEN: \""+v+"\"\nexec:\n", 1))
			ref := f.ref(t, f.contract)
			// The editor's text: the set value reads (value hidden), and the edit puts the value where a name belongs.
			raw := strings.Replace(f.text(t), "TOKEN: \""+v+"\"", "TOKEN: "+rulesview.Hidden, 1)
			raw = strings.Replace(raw, "env:\n", "env:\n  pass: [PATH, \""+v+"\"]\n", 1)
			p, err := f.s.PlanRaw(context.Background(), RawReq{Ref: ref.Ref, Base: ref.Base, Text: []byte(raw)})
			if err != nil || p.EnvRefused {
				t.Fatalf("PlanRaw: %v %+v", err, p)
			}
			if !strings.Contains(p.Err, "does not compile") || !strings.Contains(p.Err, "env.pass.1: this entry is not an environment variable name") {
				t.Fatalf("the editor's error does not call the entry by its position:\n%s", p.Err)
			}
			if strings.Contains(p.Err, "@") || strings.Contains(p.Err, rulesview.Hidden) {
				t.Fatalf("the editor's error shows, or had to cut out, the env value %q:\n%s", v, p.Err)
			}
		})
	}
}
