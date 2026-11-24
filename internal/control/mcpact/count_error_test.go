// SPDX-License-Identifier: Apache-2.0

package mcpact

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStateCountsDiscloseReaderFailure(t *testing.T) {
	for _, failure := range []string{"open", "corrupt", "newer-version", "payload", "ask-payload"} {
		t.Run(failure, func(t *testing.T) {
			s, dir := fixture(t, true)
			path := filepath.Join(dir, "events.jsonl")
			f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
			if err != nil {
				t.Fatal(err)
			}
			prefix := fmt.Sprintf(`{"v":1,"seq":1,"id":%q,"prev":%q,"ts":"2026-10-27T12:00:01Z","mono_ns":2,"run":%q,"agent":"t","pid":1,"tid":1,"cgroup":1,"kind":"mcp","source":"proxy","verdict":"allow","name":"files","tool":"read_file"}`, zeros, zeros, run) + "\n"
			if _, err := f.WriteString(prefix); err != nil {
				t.Fatal(err)
			}
			bad := "{damaged ledger line}\n"
			switch failure {
			case "newer-version":
				bad = strings.Replace(prefix, `"v":1`, `"v":999`, 1)
			case "payload":
				bad = strings.Replace(prefix, `"tool":"read_file"`, `"tool":{}`, 1)
			case "ask-payload":
				bad = strings.Replace(prefix, `"kind":"mcp"`, `"kind":"ask"`, 1)
				bad = strings.Replace(bad, `"tool":"read_file"`, `"op":{},"target":"files read_file"`, 1)
			}
			if _, err := f.WriteString(bad); err != nil {
				t.Fatal(err)
			}
			if err := f.Close(); err != nil {
				t.Fatal(err)
			}
			if failure == "open" {
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			}
			st, err := s.State(run)
			if err != nil {
				t.Fatalf("contract decisions should remain available: %v", err)
			}
			if st.CountError == "" {
				t.Fatal("reader failure exposed the prefix as complete tool counts")
			}
			facts := readFacts(dir)
			if facts.err == nil || st.CountError != facts.err.Error() {
				t.Fatalf("count error lost its reason: state=%q, reader=%v", st.CountError, facts.err)
			}
			if failure != "open" && facts.calls[[2]string{"files", "read_file"}] != 1 {
				t.Fatal("fixture must fail after a valid counted prefix")
			}
		})
	}
}
