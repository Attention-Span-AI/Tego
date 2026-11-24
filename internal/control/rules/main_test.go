// SPDX-License-Identifier: Apache-2.0
package rules

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/contracts"
	"github.com/attention-span-ai/tego/internal/control/draftcompile"
)

// slowChildMark in a draft's text makes its compiler child start slowly, as on a busy machine: it takes longer than the
// helper's whole location budget before it reads its draft.
const slowChildMark = "# slow-compile-child"

func TestMain(m *testing.M) {
	if len(os.Args) == 2 && os.Args[1] == draftcompile.Argument {
		b, _ := io.ReadAll(os.Stdin)
		var r struct{ Text []byte }
		if json.Unmarshal(b, &r) == nil && bytes.Contains(r.Text, []byte(slowChildMark)) {
			time.Sleep(contracts.CheckTimeout + time.Second)
		}
		if handled, code := draftcompile.Helper(os.Args, bytes.NewReader(b), os.Stdout); handled {
			os.Exit(code)
		}
	}
	os.Exit(m.Run())
}
