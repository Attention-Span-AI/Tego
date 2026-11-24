// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/platform/hostaddr"
)

// TestDoctorRoutingLine: doctor names the routing tables whose local, broadcast or anycast routes the run's reading of
// this host leaves out (Cilium's table 2004 behind a mark), says so when the policy rules cannot be read, and says
// nothing when every such table is read. Text and --json agree.
func TestDoctorRoutingLine(t *testing.T) {
	read := func(t hostaddr.LocalTable, err error) func() (hostaddr.LocalTable, error) {
		return func() (hostaddr.LocalTable, error) { return t, err }
	}
	if c := checkRouting(read(hostaddr.LocalTable{}, nil)); c != nil {
		t.Fatalf("a line where every table is read: %+v", c)
	}
	var none bytes.Buffer
	if err := writeRoutingCheck(&none, nil); err != nil || none.Len() != 0 {
		t.Errorf("a nil check wrote %q, %v", none.String(), err)
	}
	b, _ := json.Marshal(doctorReport{})
	if strings.Contains(string(b), `"routing"`) {
		t.Errorf("--json has a routing key with no check: %s", b)
	}

	c := checkRouting(read(hostaddr.LocalTable{Unread: []uint32{100, 2004}}, nil))
	if c == nil || len(c.Unread) != 2 {
		t.Fatalf("no line for tables 100 and 2004: %+v", c)
	}
	var text bytes.Buffer
	if err := writeRoutingCheck(&text, c); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"\nnote routing: routing table 100, 2004 holds", "no policy rule that the run's own traffic can match"} {
		if !strings.Contains(text.String(), want) {
			t.Errorf("text %q lacks %q", text.String(), want)
		}
	}
	b, _ = json.Marshal(doctorReport{Routing: c})
	if !strings.Contains(string(b), `"routing":{"unread_tables":[100,2004],"words":"routing table 100, 2004 holds`) {
		t.Errorf("--json: %s", b)
	}

	c = checkRouting(read(hostaddr.LocalTable{}, errors.New("netlink: operation not permitted")))
	if c == nil || len(c.Unread) != 0 || !strings.Contains(c.Words, "could not be read") || !strings.Contains(c.Words, "operation not permitted") {
		t.Errorf("an unreadable rule dump: %+v", c)
	}
}
