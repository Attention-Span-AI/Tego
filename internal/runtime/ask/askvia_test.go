// SPDX-License-Identifier: Apache-2.0

package ask_test

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/attention-span-ai/tego/internal/askclient"
	"github.com/attention-span-ai/tego/pkg/spec/askproto"
)

// An answer the dashboard sends says where the person gave it: the run records "uid:N pid:P dashboard" (and "dashboard
// relay" from a browser that reached the dashboard through its relay), so a receipt reads it as the signed-in person's
// answer and not as the dashboard process deciding. Without the word the by is as it was.
func TestAnswerRecordsWhereThePersonAnswered(t *testing.T) {
	ctx := context.Background()
	pid := os.Getpid()
	w := newWireBroker(t, nil)
	for _, c := range []struct {
		name   string
		via    string
		always bool
		suffix string
	}{
		{"terminal", "", false, ""},
		{"dashboard", askproto.ViaDashboard, false, " dashboard"},
		{"dashboard relay", askproto.ViaDashboardRelay, false, " dashboard relay"},
		{"dashboard always", askproto.ViaDashboard, true, " dashboard always"},
	} {
		t.Run(c.name, func(t *testing.T) {
			id, done := w.hold(t, connectReq(fmt.Sprintf("10.9.9.%d:443", len(c.name))))
			d, err := askclient.Answer(askclient.WithVia(ctx, c.via), w.dir, pid, id, true, c.always)
			if err != nil || !d.Approved {
				t.Fatalf("answer = %+v, %v", d, err)
			}
			settle(t, done)
			if want := fmt.Sprintf("uid:%d pid:%d", os.Getuid(), pid) + c.suffix; d.By != want {
				t.Errorf("by %q, want %q", d.By, want)
			}
		})
	}
}
