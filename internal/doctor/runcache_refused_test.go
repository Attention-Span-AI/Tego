// SPDX-License-Identifier: Apache-2.0

package doctor

import (
	"os"
	"path/filepath"
	"testing"
)

// TestRunCacheSaysWhyItIsUnusable: a cache directory that is there and not one only root may write (the withdrawn
// 1770 root:tego one, ADR 0042 (3)(b)) is refused, every run probes, and the cache keeps the reason for the report
// (Report.CacheNote); a missing directory is no refusal, and a working one clears it.
func TestRunCacheSaysWhyItIsUnusable(t *testing.T) {
	c, _ := testCache(t)
	k := testKey()
	if _, ok := c.load(k); ok || c.refused != "" {
		t.Fatalf("a missing cache directory: refused %q", c.refused)
	}
	p, rows, fan, fs := vouchingAnswer()
	dir := filepath.Join(c.base, "run", "tego")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o775); err != nil {
		t.Fatal(err)
	}
	if id := c.recordWith(k, p, rows, passingPlane(""), nil, fan, fs, kernelAnswers{}); id != nil {
		t.Error("an entry was written into a group-writable directory")
	}
	if c.refused == "" {
		t.Error("the refusal left no note")
	}
	if r := (&Report{cacheNote: c.refused}); r.CacheNote() == "" {
		t.Error("Report.CacheNote is empty")
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if id := c.recordWith(k, p, rows, passingPlane(""), nil, fan, fs, kernelAnswers{}); id == nil || c.refused != "" {
		t.Errorf("a working directory: id %v, refused %q", id, c.refused)
	}
}
