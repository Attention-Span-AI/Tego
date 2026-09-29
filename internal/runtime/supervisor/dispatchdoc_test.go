// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"os"
	"strings"
	"testing"
)

// TestR1NamesEveryDispatchedSyscall holds docs/p0/supervisor.md R1, the dispatch scope, to the table: every
// syscall buildDispatchFor dispatches on either architecture is named there in backticks, and the System V
// IPC entries by their family. R1 once said the table covered "only" the path and network sets and that
// sendmsg was notified only with msg_name set, while the table had grown the keyring, IPC, namespace,
// signal, truncate and chmod entries and the filter notified every sendmsg.
func TestR1NamesEveryDispatchedSyscall(t *testing.T) {
	b, err := os.ReadFile("../../../docs/p0/supervisor.md")
	if err != nil {
		t.Fatal(err)
	}
	doc := string(b)
	start := strings.Index(doc, "**R1 — dispatch scope.**")
	end := strings.Index(doc, "**R2 — ")
	if start < 0 || end < start {
		t.Fatal("R1 not found in docs/p0/supervisor.md")
	}
	r1 := doc[start:end]
	sysv := map[string]bool{"msgget": true, "msgsnd": true, "msgrcv": true, "msgctl": true, "semget": true,
		"semop": true, "semtimedop": true, "semctl": true, "shmget": true, "shmat": true, "shmctl": true}
	for _, arch := range []uint32{auditArchX86, auditArchARM} {
		for _, e := range buildDispatchFor(arch) {
			if sysv[e.name] {
				if !strings.Contains(r1, "System V IPC") {
					t.Errorf("R1 does not name the System V IPC entries (%s)", e.name)
				}
				continue
			}
			if !strings.Contains(r1, "`"+e.name+"`") {
				t.Errorf("R1 does not name the dispatched syscall %q", e.name)
			}
		}
	}
	if strings.Contains(r1, "`msg_name` set, known datagram fd") {
		t.Error("R1 still says sendmsg is notified only with msg_name set; the filter notifies every call")
	}
}

// TestR15NamesTheFallbackMutationRefusal holds docs/p0/supervisor.md R15 and the list of who owns a line to
// fallbackMutation (fs.go): at tier cgroup with no plane mode (Options.PlaneAttrs unset) this loop refuses, with
// R10's errno, every mutation the root walk refuses beneath a deny_read nested in a write entry (ADR 0021 (5),
// ADR 0028 S3; TestFallbackMutationConverges). R15 said such a deny_read "refuses no write" and that an unlink,
// rename, mkdir, symlink or link "keeps the Landlock verdict" at tier 2, and the owner list named only R15c's,
// R15d's and R5's refusals as this loop's own. The amendment then said a walk "that cannot
// say where the path lands" is refused under path-unreliable, the words decideFS uses for the errOtherView arm,
// which fallbackMutation never sees and which continues the syscall (TestFallbackMutationWalkFailures).
func TestR15NamesTheFallbackMutationRefusal(t *testing.T) {
	b, err := os.ReadFile("../../../docs/p0/supervisor.md")
	if err != nil {
		t.Fatal(err)
	}
	doc := string(b)
	start := strings.Index(doc, "**R15 — write-open record.**")
	end := strings.Index(doc, "**R15d — ")
	if start < 0 || end < start {
		t.Fatal("R15 not found in docs/p0/supervisor.md")
	}
	r15 := doc[start:end]
	for _, want := range []string{"fallbackMutation", "TestFallbackMutationConverges", "ADR 0021 (5)", "ADR 0028 S3",
		"errOtherView", "TestFallbackMutationWalkFailures"} {
		if !strings.Contains(r15, want) {
			t.Errorf("R15 does not name %s", want)
		}
	}
	for _, stale := range []string{"refuses no write", "keeps the Landlock verdict",
		"that cannot say where the path lands is refused"} {
		if strings.Contains(strings.Join(strings.Fields(r15), " "), stale) {
			t.Errorf("R15 still says %q, which fallbackMutation makes false at tier cgroup", stale)
		}
	}
	owner := strings.Index(doc, "- *This loop's* for what it answers itself")
	if owner < 0 {
		t.Fatal("the line-owner list's entry for this loop is not found")
	}
	entry := doc[owner:]
	if i := strings.Index(entry[1:], "\n- "); i >= 0 {
		entry = entry[:i+1]
	}
	if !strings.Contains(entry, "fallbackMutation") {
		t.Error("the line-owner list does not name fallbackMutation's refusals as this loop's own")
	}
}
