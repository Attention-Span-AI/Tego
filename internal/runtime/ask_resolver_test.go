// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/platform/dns"
	"github.com/attention-span-ai/tego/internal/runtime/supervisor"
	"github.com/attention-span-ai/tego/internal/testutil/contracttest"
)

// An absent optional DNS set must stay a nil interface when passed through the
// actual supervisor option type. A typed nil *dns.Set caused every ordinary
// unmatched connect to panic inside Match and lose its refusal action line.
func TestAskDNSAbsentRemainsNilSupervisorResolver(t *testing.T) {
	f := contracttest.Build(t, "version: 0\nname: no-ask-dns\ncommand: [fixture]\nnet: {allow: []}\n", contracttest.Tree{})
	r := &runner{rt: f.Rules}
	opts := supervisor.Options{AskResolver: r.startAskDNS(context.Background(), dns.Options{}, time.Second)}
	if opts.AskResolver != nil {
		t.Fatalf("absent NetAsk produced a non-nil resolver interface: %T", opts.AskResolver)
	}
}
