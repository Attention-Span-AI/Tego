// SPDX-License-Identifier: Apache-2.0

//go:build integration

package cgroup

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"

	ebpfbindings "github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// planeCounterDepth is how many directories deep under out/ the counters cell's file lies: out/ is then more than
// TEGO_PLANE_WALK_MAX (64) levels above it, so the plane's walk runs out before any row and ends BOUND.
const planeCounterDepth = 65

// planeCounterContract governs the counters cell: a write directory with a deny_read in it, and a shell agent.
const planeCounterContract = `version: 0
name: plane-counters
command: ["sh", "./agent.sh"]
fs:
  write: ["./out/"]
  deny_read: ["./out/secret/"]
exec:
  allow: ["sh", "sleep"]
net:
  allow: []
env:
  pass: ["PATH", "HOME"]
record: full
`

// planeCounterAgent reads the deep file (BOUND), says it is ready, waits for go (the test corrupts the deny_read's
// row meanwhile) and reads under the deny_read (identity mismatch). The shell opens each file itself. DEEP is replaced
// by the deep file's path: the contract passes the agent no variable of the test's. Each open is in a subshell (a
// fork, no exec): a failed redirection on the special builtin : ends a POSIX shell. Nothing goes to /dev/null, which
// the contract gives no write.
const planeCounterAgent = `attempt() {
    if (: < "$2"); then echo "RESULT $1 ok"; else echo "RESULT $1 refused"; fi
}
attempt deep DEEP
: > out/ready
while [ ! -e out/go ]; do sleep 0.05; done
attempt mismatch out/secret/key
`

// TestPlaneCountersBecomeGapsAtRunEnd is enforce-plane §2.8's counters half in a real run, per plane mode: a read
// 65 directories below the nearest row exhausts the walk (the slot's bound counter) and a read under a deny_read
// whose row's identity no longer matches its inode (the mismatch counter; the test overwrites the row's i_ino in
// the slot's map while the run waits, as bpf/testonly's fill does with its Corrupt flag) are both refused, and the
// ledger then carries exactly one gap what=enforce line per counter, before run_end, each with its count and the
// plane's mode in decision_plane. run_start names the mode too.
func TestPlaneCountersBecomeGapsAtRunEnd(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("the plane needs root: run as `sudo go test -tags integration,tegobpf` or `make vm-root-test`")
	}
	uid, gid, ok := sudoIDs()
	if !ok {
		t.Skip("a root `tego run` drops the agent to the sudo caller and refuses without SUDO_UID and SUDO_GID")
	}
	if _, err := bpfHash(); err != nil {
		t.Skipf("this test binary carries no BPF objects; the run belongs to the tegobpf suite: %v", err)
	}
	dir := t.TempDir()
	bin := buildPlaneTego(t, dir)
	requireTier(t, bin, "cgroup")
	modes := planeModesHere(t, bin)
	if len(modes) == 0 {
		t.Skip("no plane mode passes doctor's probe here")
	}
	for _, mode := range modes {
		t.Run(mode, func(t *testing.T) { planeCountersCell(t, bin, uid, gid, mode) })
	}
}

func planeCountersCell(t *testing.T, bin string, uid, gid int, mode string) {
	deep := "out/" + strings.Repeat("d/", planeCounterDepth) + "f"
	files := map[string]string{"agent.sh": strings.Replace(planeCounterAgent, "DEEP", deep, 1), "agent.yaml": planeCounterContract,
		"out/secret/key": "k\n", deep: "f\n"}
	p := newPlaneProject(t, uid, gid, files, nil, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	var out bytes.Buffer
	cmd := p.run(ctx, bin, "agent.yaml", mode, &out)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	waitFile(t, filepath.Join(p.project, "out", "ready"), time.Minute, cmd, &out)
	if n := corruptPlaneRow(t, mode, filepath.Join(p.project, "out", "secret")); n < 1 {
		t.Fatal("no row of out/secret to corrupt in the plane's slots")
	}
	if err := os.WriteFile(filepath.Join(p.project, "out", "go"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	runErr := <-done
	t.Logf("tego run (%s): %v\n%s", mode, runErr, out.String())
	if runErr != nil {
		t.Fatalf("the run did not complete: %v", runErr)
	}
	res := agentResults(t, out.String())
	for _, name := range []string{"deep", "mismatch"} {
		if res[name] != "refused" {
			t.Errorf("%s: %q, want refused (fail closed)", name, res[name])
		}
	}
	events := runEvents(t, p.ledger)
	if start := findEvent(events, func(e map[string]any) bool { return e["kind"] == "run_start" }); start == nil ||
		start["decision_plane"] != mode {
		t.Errorf("run_start %v, want decision_plane %s", start, mode)
	}
	end := -1
	gaps := map[string][]map[string]any{}
	for i, e := range events {
		switch e["kind"] {
		case "run_end":
			end = i
		case "gap":
			if why := fmt.Sprint(e["why"]); strings.HasPrefix(why, "plane-") {
				if end >= 0 {
					t.Errorf("plane gap %v after run_end", e)
				}
				gaps[why] = append(gaps[why], e)
			}
		}
	}
	for _, why := range []string{record.GapPlaneBound, record.GapPlaneMismatch} {
		g := gaps[why]
		if len(g) != 1 {
			t.Errorf("%d gap lines why=%s, want one: %v", len(g), why, gaps)
			continue
		}
		if g[0]["what"] != record.GapEnforce || g[0]["decision_plane"] != mode {
			t.Errorf("gap %v, want what=enforce decision_plane=%s", g[0], mode)
		}
		if n, ok := g[0]["count"].(float64); !ok || n < 1 {
			t.Errorf("gap %v has no count", g[0])
		}
	}
	if len(gaps[record.GapPlaneCountersUnread]) != 0 {
		t.Errorf("the slot's counters were not read: %v", gaps[record.GapPlaneCountersUnread])
	}
}

// corruptPlaneRow overwrites the i_ino of every row keyed by path's inode in the plane's slots of mode, so the next
// walk that meets it finds an identity that is not its inode's (ADR 0025 (4)), and returns how many it changed.
func corruptPlaneRow(t *testing.T, mode, path string) int {
	t.Helper()
	var st syscall.Stat_t
	if err := syscall.Stat(path, &st); err != nil {
		t.Fatal(err)
	}
	hash, err := ebpfbindings.Hash()
	if err != nil {
		t.Fatal(err)
	}
	outer, err := ebpf.LoadPinnedMap(filepath.Join(DefaultBPFFS, pinRoot, hash+"-"+mode, pinMaps, ebpfbindings.MapPlaneRows), nil)
	if err != nil {
		t.Fatalf("open the plane's rows: %v", err)
	}
	defer func() { _ = outer.Close() }()
	changed := 0
	var slot, id uint32
	it := outer.Iterate()
	for it.Next(&slot, &id) {
		inner, err := ebpf.NewMapFromID(ebpf.MapID(id))
		if err != nil {
			continue
		}
		var key uint64
		var row ebpfbindings.PlaneRow
		var keys []uint64
		rows := inner.Iterate()
		for rows.Next(&key, &row) {
			if row.Ino == st.Ino {
				keys = append(keys, key)
			}
		}
		for _, k := range keys {
			if err := inner.Lookup(k, &row); err != nil {
				continue
			}
			row.Ino ^= 1 << 40
			if err := inner.Update(k, row, ebpf.UpdateExist); err != nil {
				t.Fatalf("corrupt slot %d's row: %v", slot, err)
			}
			changed++
		}
		_ = inner.Close()
	}
	return changed
}
