// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"testing"

	"github.com/attention-span-ai/tego/internal/platform/sys"
)

const adoptWriteOwnershipEnv = "TEGO_ADOPT_WRITE_OWNERSHIP_DIR"

func adoptWriteOwnershipHelper() {
	dir := os.Getenv(adoptWriteOwnershipEnv)
	if dir == "" {
		return
	}
	if _, err := sys.Inherited(-1, sys.KindFIFO, "seal-precondition"); !errors.Is(err, sys.ErrKind) {
		fmt.Fprintln(os.Stderr, "seal already closed:", err)
		os.Exit(3)
	}
	adoptStateOwner = os.Getuid()
	if err := (&adoptStore{dir: dir}).write(adoptRecord{Run: "r-00000000-0dllq06ts7400-k7m2pq"}); err != nil {
		fmt.Fprintln(os.Stderr, "write:", err)
		os.Exit(2)
	}
	fd, err := sys.Inherited(3, sys.KindFIFO, "ownership-probe")
	if !errors.Is(err, sys.ErrSealed) {
		if fd != nil {
			_ = fd.Close()
		}
		fmt.Fprintln(os.Stderr, "temporary record had no owner:", err)
		os.Exit(1)
	}
	os.Exit(0)
}

// The record writer must create its temporary descriptor as an owner before handing it to os.File. Run before
// any other sys owner, so an unrelated constructor cannot accidentally satisfy the ownership seal assertion.
func TestAdoptStoreWriteOwnsTheTemporaryRecord(t *testing.T) {
	rd, wr, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer rd.Close()
	defer wr.Close()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0])
	cmd.Env = append(os.Environ(), adoptWriteOwnershipEnv+"="+dir)
	cmd.ExtraFiles = []*os.File{rd}
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("record ownership: %v\n%s", err, out)
	}
}
