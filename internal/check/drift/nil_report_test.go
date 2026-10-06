// SPDX-License-Identifier: Apache-2.0

package drift

import (
	"strings"
	"testing"
)

func TestAggregateRejectsANilReportAtEveryPosition(t *testing.T) {
	valid := &Report{Agent: "test", Runs: 1}
	for _, tt := range []struct {
		name    string
		reports []*Report
		want    string
	}{
		{"first", []*Report{nil, valid}, "report 0 is nil"},
		{"last", []*Report{valid, nil}, "report 1 is nil"},
		{"only", []*Report{nil}, "report 0 is nil"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			rep, err := Aggregate(tt.reports)
			if rep != nil || err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Aggregate = %v, %v; want nil, %q", rep, err, tt.want)
			}
		})
	}
}
