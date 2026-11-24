// SPDX-License-Identifier: Apache-2.0

package ledgerview

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// An older window keeps the published run's context and totals. Its events must
// therefore come from that same source, rather than a replacement or rewrite.
func TestWindowBeforeRejectsChangedSource(t *testing.T) {
	for _, change := range []string{"replacement", "rewrite", "append"} {
		t.Run(change, func(t *testing.T) {
			root, id := t.TempDir(), "r-aaaaaaaa-0000000000093-window"
			at := time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)
			start := line(id, "reader", 0, at, "run_start", `"tier":"landlock","command":["sh"],"cwd":"/p/original"`)
			action := line(id, "reader", 1, at.Add(time.Second), "fs", `"op":"open","path":"/p/workpapers/old.data","flags":0,"verdict":"allow","rule":"unmatched"`)
			writeRun(t, root, id, start, action)
			r, err := LoadRun(root, id)
			if err != nil {
				t.Fatal(err)
			}
			file := filepath.Join(root, id, "events.jsonl")
			replacement := strings.ReplaceAll(start+action, "/p/original", "/p/replaced")
			replacement = strings.ReplaceAll(replacement, "old.data", "new.data")
			if len(replacement) != len(start+action) {
				t.Fatal("rewrite fixture must preserve the file size")
			}
			switch change {
			case "replacement":
				tmp := filepath.Join(root, id, "replacement.jsonl")
				if err := os.WriteFile(tmp, []byte(replacement), 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(tmp, file); err != nil {
					t.Fatal(err)
				}
			case "rewrite":
				if err := os.WriteFile(file, []byte(replacement), 0600); err != nil {
					t.Fatal(err)
				}
				// Force a different timestamp without relying on clock resolution
				// or sleeping between two same-length writes.
				stamp := time.Unix(0, r.file.mtime).Add(2 * time.Second)
				if err := os.Chtimes(file, stamp, stamp); err != nil {
					t.Fatal(err)
				}
			case "append":
				appendLines(t, root, id, line(id, "reader", 2, at.Add(2*time.Second), "fs", `"op":"open","path":"/p/workpapers/later.data","flags":0,"verdict":"allow","rule":"unmatched"`))
			}
			fi, err := os.Stat(file)
			if err != nil {
				t.Fatal(err)
			}
			now := idOf(fi)
			sameInode := now.dev == r.file.dev && now.ino == r.file.ino
			if (change == "replacement") == sameInode {
				t.Fatalf("%s fixture has unexpected source identity", change)
			}
			if change == "rewrite" && (now.size != r.file.size || now.mtime == r.file.mtime) {
				t.Fatal("rewrite fixture must change timestamps at the same size")
			}
			if change == "append" && now.size <= r.file.size {
				t.Fatal("append fixture must grow the same file")
			}
			window, err := WindowBefore(root, r, 2)
			if change != "append" {
				if err == nil {
					t.Fatalf("%s returned new-source events under the old published run context: %+v", change, window.Events)
				}
				return
			}
			if err != nil {
				t.Fatalf("a genuine append must retain access to old history: %v", err)
			}
			if window.Cwd != "/p/original" || window.Command != r.Command || window.Agent != r.Agent || window.Lines != r.Lines ||
				len(window.Events) != 2 || window.Events[1].Target != "/p/workpapers/old.data" || window.Events[1].Seq != 1 {
				t.Fatalf("append changed the original context or bounded history: %+v", window)
			}
		})
	}
}
