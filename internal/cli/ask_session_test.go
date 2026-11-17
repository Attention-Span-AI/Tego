// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

func TestAskCommandsAcceptSessionNames(t *testing.T) {
	for _, agentName := range []string{"helper", "q"} {
		t.Run(agentName, func(t *testing.T) {
			root := gcRoot(t)
			const id = identity.RunID("r-519c2703-0dmw7w54wuixg-naw97n")
			endedRunNamed(t, root, id, agentName)
			const askID = "q-0123456789abcdef0123456789abcdef"
			for _, tc := range []struct {
				noun string
				tail []string
			}{
				{"ask", nil}, {"ask", []string{askID}},
				{"approve", []string{askID}}, {"deny", []string{askID}},
				{"alternate", []string{askID, "--file", "/a/file"}},
			} {
				args := append([]string{tc.noun, string(id)}, tc.tail...)
				wantCode, wantOut, wantErr := run(t, args...)
				args[1] = sessionName(agentName, string(id))
				code, out, errs := run(t, args...)
				if code != wantCode || out != wantOut || errs != wantErr {
					t.Errorf("%v: got (%d,%q,%q), want run-id result (%d,%q,%q)", args, code, out, errs, wantCode, wantOut, wantErr)
				}
			}
		})
	}
}
