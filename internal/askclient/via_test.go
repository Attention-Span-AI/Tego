// SPDX-License-Identifier: Apache-2.0

package askclient_test

import (
	"context"
	"net"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/attention-span-ai/tego/internal/askclient"
	"github.com/attention-span-ai/tego/pkg/spec/askproto"
)

// A run started by a tego from before Command.Via refuses the key as a protocol error and acts on nothing: the dashboard
// asks again without it, so the person's answer still reaches that run (recorded without the word).
func TestAnswerWithViaFallsBackForAnOlderBroker(t *testing.T) {
	dir := t.TempDir()
	f, path, err := askclient.OpenSocketDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	ln, err := net.ListenUnix("unixpacket", &net.UnixAddr{Name: path, Net: "unixpacket"})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	var mu sync.Mutex
	var packets []string
	go func() {
		for {
			c, err := ln.AcceptUnix()
			if err != nil {
				return
			}
			func() {
				defer func() { _ = c.Close() }()
				_, _ = c.Write([]byte(`{"ready":"` + strings.Repeat("a", askproto.NonceLen) + `"}`))
				buf := make([]byte, askproto.MaxPacket)
				n, _, _, _, err := c.ReadMsgUnix(buf, nil)
				if err != nil {
					return
				}
				mu.Lock()
				packets = append(packets, string(buf[:n]))
				mu.Unlock()
				// This broker predates via: any key it does not know is a protocol error.
				if strings.Contains(string(buf[:n]), `"via"`) {
					_, _ = c.Write([]byte(`{"error":"ask: invalid protocol","code":"protocol"}`))
					return
				}
				_, _ = c.Write([]byte(`{"decision":{"ask_id":"q-` + strings.Repeat("0", 32) + `","approved":true,"by":"uid:1 pid:2"}}`))
			}()
		}
	}()
	id := "q-" + strings.Repeat("0", 32)
	d, err := askclient.Answer(askclient.WithVia(context.Background(), askproto.ViaDashboard), dir, os.Getpid(), id, true, false)
	if err != nil || !d.Approved {
		t.Fatalf("answer = %+v, %v", d, err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(packets) != 2 || !strings.Contains(packets[0], `"via":"dashboard"`) || strings.Contains(packets[1], `"via"`) {
		t.Errorf("packets %q: want one with via, then the same answer without it", packets)
	}
	// An invalid word is never sent.
	if got := askclient.WithVia(context.Background(), "forged"); got != context.Background() {
		t.Error("an unknown via was carried")
	}
}
