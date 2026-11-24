// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bufio"
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/ledger"
	tegoruntime "github.com/attention-span-ai/tego/internal/runtime"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// bytesRead is the bytes this process has read through read(2) and pread(2) (rchar in /proc/self/io), or false where the
// kernel keeps no such count.
func bytesRead(t *testing.T) (uint64, bool) {
	t.Helper()
	f, err := os.Open("/proc/self/io")
	if err != nil {
		return 0, false
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if v, ok := strings.CutPrefix(sc.Text(), "rchar: "); ok {
			n, err := strconv.ParseUint(strings.TrimSpace(v), 10, 64)
			return n, err == nil
		}
	}
	return 0, false
}

// TestEndSummaryReadsTheLedgerOnce: tego run's summary has the receipt of the run and says "chain verified", from one read
// of the record, not a read for the receipt and another for the chain check. Over a 10,000-line run the bytes read for
// the summary are about the file's size, never twice it.
func TestEndSummaryReadsTheLedgerOnce(t *testing.T) {
	root := t.TempDir()
	anchor := filepath.Join(t.TempDir(), "chain.log")
	var host [32]byte
	id, err := identity.NewRunID(host, time.Now(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	w, err := ledger.Open(filepath.Join(root, string(id)), record.RunRef{ID: string(id), Agent: "once"},
		ledger.WithAnchor(ledger.NewFileChainAnchor(anchor)))
	if err != nil {
		t.Fatal(err)
	}
	if err := w.WriteRunStart(record.RunStartPayload{Command: []string{"agent"}, Cwd: "/w", Tier: "landlock"}); err != nil {
		t.Fatal(err)
	}
	for i := range 9998 {
		e := &record.Event{Kind: record.KindFS, Source: record.SourceSupervisor, PID: 1, TID: 1, Verdict: record.VerdictAllow,
			Rule: "fs.read[/]", Attr: record.Unattributed(), Authority: record.AuthorityRule}
		if err := e.SetPayload(record.FSPayload{Op: record.FSOpen, Path: fmt.Sprintf("/w/src/file%d.go", i%500)}); err != nil {
			t.Fatal(err)
		}
		if err := w.Append(e); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
		t.Fatal(err)
	}
	prev := ledgerRootOf
	t.Cleanup(func() { ledgerRootOf = prev })
	ledgerRootOf = func(*config.Machine) (string, error) { return root, nil }
	st, err := os.Stat(filepath.Join(root, string(id), ledger.EventsFile))
	if err != nil {
		t.Fatal(err)
	}
	res := tegoruntime.Result{RunID: string(id), Reason: record.RunEndExit}

	before, ok := bytesRead(t)
	if !ok {
		t.Skip("this kernel keeps no per-process read count")
	}
	s := summarizeRun(t.Context(), &config.Machine{}, anchor, res, agent.RecordSummary)
	after, _ := bytesRead(t)
	if s == nil || s.rc == nil || s.chain != "chain verified" {
		t.Fatalf("summary %+v", s)
	}
	if read := after - before; read > uint64(st.Size())*3/2 {
		t.Errorf("the summary read %d bytes of a %d byte record: it read the ledger more than once", read, st.Size())
	}
}
