// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/netip"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// panicLogStack returns the stack the own log recorded on its "supervisor: handler panic" line.
func panicLogStack(t *testing.T, buf *bytes.Buffer) string {
	t.Helper()
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("log line %q: %v", line, err)
		}
		if rec["msg"] == "supervisor: handler panic" {
			s, _ := rec["stack"].(string)
			return s
		}
	}
	t.Fatalf("no handler panic line in the own log:\n%s", buf.String())
	return ""
}

// stackTestHandlerPanics is the handler whose name the recovered stack must carry.
func stackTestHandlerPanics(*Loop, *notif) { panic("a bounds bug in a reader") }

// TestHandlerPanicLogsItsStack is R25 and the failure table's "Handler panics mid-decision": the recovered
// stack goes to the own log, so a panic can be located after the fact, not only its message.
func TestHandlerPanicLogsItsStack(t *testing.T) {
	var buf bytes.Buffer
	f := newFake()
	l, err := New(testListener(), testPolicy(nil, nil, nil), &testSink{}, Options{kernel: f, Workers: 1,
		Log: slog.New(slog.NewJSONHandler(&buf, nil))})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	const nr = 4242
	l.dispatch[dispatchKey{arch: nativeAuditArch(), nr: nr}] = entry{name: "boom",
		fn: stackTestHandlerPanics}
	l.handle(notifFor(nr, 42))
	if st := panicLogStack(t, &buf); !strings.Contains(st, "stackTestHandlerPanics") {
		t.Errorf("own log's stack does not name the panicking handler:\n%s", st)
	}
}

// TestRelayPanicLogsTheRelayStack: a panic in a relay goroutine is re-raised on the worker, and the stack
// the own log records is the goroutine's, where the panic happened, not the worker's that re-raised it.
func TestRelayPanicLogsTheRelayStack(t *testing.T) {
	const addr = 0x40000
	var buf bytes.Buffer
	f := newFake()
	f.put(addr, sockaddrIn4("10.0.0.5", 8080))
	pol := testPolicy([]agent.NetRule{netRule("10.0.0.5:8080", "", 8080, "10.0.0.5")}, nil, []netip.AddrPort{})
	l, err := New(testListener(), pol, &testSink{}, Options{kernel: &panickingKernel{fakeKernel: f}, Workers: 1,
		Log: slog.New(slog.NewJSONHandler(&buf, nil))})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	l.handle(notifFor(connectNR(), 4242, 5, addr, 16))
	if st := panicLogStack(t, &buf); !strings.Contains(st, "panickingKernel).ConnectRaw") {
		t.Errorf("own log's stack is not the relay goroutine's:\n%s", st)
	}
}
