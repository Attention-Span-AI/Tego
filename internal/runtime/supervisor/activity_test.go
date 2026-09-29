// SPDX-License-Identifier: Apache-2.0

package supervisor

import (
	"sync/atomic"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// TestRecordOffReportsEveryAnsweredNotificationAsActivity: under record: off the producers keep only refusals,
// so Options.Activity is the only feed of the budget watcher's Touch (docs/p0/limits-check-doctor-cli.md
// LCD-R4). Every answered notification must reach it once, allowed or refused, whether or not it left a line.
func TestRecordOffReportsEveryAnsweredNotificationAsActivity(t *testing.T) {
	const pathAddr = 0x1000
	fs := []agent.FSRule{{Path: "/work", Kind: agent.FSWrite}}
	for _, tc := range []struct {
		name  string
		path  string
		lines int // lines the loop keeps under record: off
	}{
		{name: "an allowed write keeps no line", path: "/work/x", lines: 0},
		{name: "a refused write keeps its line", path: "/etc/x", lines: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake()
			f.put(pathAddr, cstr(tc.path))
			pol := testPolicy(nil, fs, nil)
			pol.Record = agent.RecordOff
			var touched atomic.Int64
			sink := &testSink{}
			l, err := New(testListener(), pol, sink, Options{kernel: f, Workers: 1, Activity: func() { touched.Add(1) }})
			if err != nil {
				t.Fatal(err)
			}
			nr := nrFor(t, "openat")
			const count = 5
			for i := 0; i < count; i++ {
				n := notifFor(nr, 42, argCWD, pathAddr, 0x241)
				n.id = uint64(i + 1)
				l.handle(n)
			}
			if f.respCount() != count {
				t.Fatalf("%d responses, want %d", f.respCount(), count)
			}
			if got := touched.Load(); got != count {
				t.Errorf("Activity told of %d notifications, want %d: one per answered notification (LCD-R4)", got, count)
			}
			if got := len(sink.all()); got != tc.lines*count {
				t.Errorf("%d lines under record: off, want %d", got, tc.lines*count)
			}
		})
	}
}
