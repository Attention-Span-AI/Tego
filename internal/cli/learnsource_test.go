// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

func TestLearnHistoryReachesRunSource(t *testing.T) {
	c, _, err := agent.LoadBytes("/agent.yaml", []byte("version: 0\nname: a\ncommand: [python]\nlearn:\n  run: r-12345678-0aaaaaaaaaaaa-abcdef\n  withheld: [tcp://203.0.113.9:443]\n"), nil)
	if err != nil {
		t.Fatal(err)
	}
	src := (contractRef{arg: "/agent.yaml"}).source(&agent.RuleTable{Contract: c, ContractPath: "/agent.yaml"})
	b, err := json.Marshal(src)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"learn"`) || !strings.Contains(string(b), "tcp://203.0.113.9:443") {
		t.Fatalf("run_start loses learned history: %s", b)
	}
	if got := (contractRef{arg: stdinContract}).source(&agent.RuleTable{Contract: c, ContractPath: "/agent.yaml"}); got != nil {
		t.Fatalf("stdin contract acquired a recorded source: %+v", got)
	}
}
