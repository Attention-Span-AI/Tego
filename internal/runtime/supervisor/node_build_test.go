// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"crypto/sha256"
	"io"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/policy/execmatch"
	"github.com/attention-span-ai/tego/pkg/policy/execmatch/rows"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// Exercise the actual fd producer. A printed/embedded version string is not a
// build pin, and a file named node-22 does not receive version 22's inventory.
func TestNodeImageBuildPin(t *testing.T) {
	impostor := filepath.Join(t.TempDir(), "node-22")
	if err := os.WriteFile(impostor, []byte("\x7fELF v22.21.1 v20.19.4\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{impostor: ""}
	for env, version := range map[string]string{"TEGO_NODE20_BIN": "20.19.4", "TEGO_NODE22_BIN": "22.21.1"} {
		if bin := os.Getenv(env); bin != "" {
			cases[bin] = version
		}
	}
	if dir := os.Getenv("TEGO_NODE_REVIEW_DIR"); dir != "" {
		bins, err := filepath.Glob(filepath.Join(dir, "node-*", "bin", "node"))
		if err != nil {
			t.Fatal(err)
		}
		for _, bin := range bins {
			// Review directories can also contain a copy of a pinned build.
			// Compute the expectation independently of ExecImage, by content,
			// rather than treating the directory or filename as an attestation.
			f, err := os.Open(bin)
			if err != nil {
				t.Fatal(err)
			}
			h := sha256.New()
			_, err = io.Copy(h, f)
			closeErr := f.Close()
			if err != nil || closeErr != nil {
				t.Fatalf("review fixture digest: %v, close: %v", err, closeErr)
			}
			var sum [sha256.Size]byte
			copy(sum[:], h.Sum(nil))
			cases[bin] = rows.NodeBuildVersion(sum)
		}
	}
	for bin, want := range cases {
		t.Run(bin, func(t *testing.T) {
			q := pathQuery{tid: os.Getpid(), dirfd: atFDCWD, path: bin, head: true}
			img, err := (sysKernel{}).ExecImage(q)
			if err != nil {
				t.Fatal(err)
			}
			if img.nodeVersion != want {
				t.Fatalf("attested %q, want %q", img.nodeVersion, want)
			}
			ps := []*execmatch.Pattern{}
			for _, entry := range []string{"a.js *", "b.js"} {
				list := execmatch.ListAllow
				if entry == "b.js" {
					list = execmatch.ListDeny
				}
				p, err := execmatch.Parse(entry, list, rows.Builtin())
				if err != nil {
					t.Fatal(err)
				}
				ps = append(ps, p)
			}
			ix := execmatch.NewIndex(rows.Builtin(), ps, execmatch.IndexOptions{})
			f := execmatch.Facts{NodeVersion: img.nodeVersion, Requested: "node", Image: "node", Argv0: "node", Argv: []string{"node", "a.js"}, ArgvComplete: true}
			r := ix.Decide(&f)
			if r.Outcome != execmatch.OutcomeAllowed {
				t.Fatalf("real image pin decision: %+v", r)
			}
			// Feed the actual image observation through the notification handler,
			// not a hand-built matcher Fact. This checks the production wiring,
			// errno/ledger refusal, and that a late pre-scan token defeats an
			// otherwise admitting 32-argument staged prefix.
			for _, late := range []bool{false, true} {
				fk := newFake()
				fk.images = map[string]execImage{"/probe/node": img}
				loop, sink := newTestLoop(t, fk, commandPolicy(t, "deny: b.js"))
				argv := []string{"node", "./a.js"}
				if late {
					for len(argv) < 100 {
						argv = append(argv, "script-arg")
					}
					argv = append(argv, "--experimental-default-config-file")
				}
				execAt(loop, fk, nrFor(t, "execve"), 42, 0, "/probe/node", argv...)
				verdict := record.VerdictAllow
				if late {
					verdict = record.VerdictRefused
				}
				wantExecAnswer(t, fk, verdict)
				if ev := sink.one(t); verdict == record.VerdictRefused && ev.Rule != execmatch.RuleCommandUnresolved {
					t.Fatalf("notification path: got %s (%s), want command-unresolved", ev.Rule, ev.Verdict)
				}
			}
			// Reopening a different identity must not produce an attestation.
			fd, err := unix.Open(bin, unix.O_PATH|unix.O_CLOEXEC, 0)
			if err != nil {
				t.Fatal(err)
			}
			_, bad := readExecBytes(fd, fileID{}, true)
			_ = unix.Close(fd) // test owns the descriptor
			if bad != "" {
				t.Fatal("wrong inode received a build pin")
			}
		})
	}
}

// A loader maps its program without an execve of that file: attestation must
// preserve that walk's lack of a MAY_EXEC requirement. Unknown content still
// receives no inventory, even when it embeds both supported version strings.
func TestNodeLoaderPinDoesNotRequireExecutePermission(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "node")
	if err := os.WriteFile(bin, []byte("\x7fELF v20.19.4 v22.21.1"), 0o600); err != nil {
		t.Fatal(err)
	}
	img, err := (sysKernel{}).ExecImage(pathQuery{tid: os.Getpid(), dirfd: atFDCWD, path: bin, nodePin: true})
	if err != nil || img.nodeVersion != "" {
		t.Fatalf("mapped program: version=%q err=%v", img.nodeVersion, err)
	}
	_, err = (sysKernel{}).ExecImage(pathQuery{tid: os.Getpid(), dirfd: atFDCWD, path: bin, head: true})
	if err != unix.EACCES {
		t.Fatalf("actual exec of non-executable file: %v", err)
	}
}
