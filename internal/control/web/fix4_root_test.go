// SPDX-License-Identifier: Apache-2.0

package web

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/control/ledgerview"
	"golang.org/x/net/html"
)

func TestWarmRootFailureKeepsKnownRequests(t *testing.T) {
	for _, shape := range []string{"unreadable", "not a folder", "directory link", "different directory"} {
		t.Run(shape, func(t *testing.T) {
			root := twoRequestFixture(t)
			appendLine(t, root, secondRequestRun, line(secondRequestRun, "Second agent", 2, time.Now(), "ask", `"ask_id":"ask-C","op":"connect","hold":"net","target":"third.example:443"`))
			s := newServer(t, root)
			c := login(t, s)
			before, err := ledgerview.Load(root)
			if err != nil || len(before.Pending()) != 3 {
				t.Fatalf("warm fixture: %v, %+v", err, before)
			}
			getRaw(t, s, c, "/approvals")
			if shape == "unreadable" && !readsThroughAnyMode() {
				if err := os.Chmod(root, 0); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = os.Chmod(root, 0700) })
			} else {
				saved := root + "-saved"
				if err := os.Rename(root, saved); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = os.RemoveAll(saved) })
				switch shape {
				case "unreadable":
					// Root reads through a mode of 000, so its folder that cannot be read is one the kernel refuses
					// by name: a link that leads to itself.
					if err := os.Symlink(root, root); err != nil {
						t.Fatal(err)
					}
				case "not a folder":
					if err := os.WriteFile(root, nil, 0600); err != nil {
						t.Fatal(err)
					}
				case "directory link":
					replacement := t.TempDir()
					if err := os.Mkdir(filepath.Join(replacement, ".live"), 0700); err != nil {
						t.Fatal(err)
					}
					if err := os.Symlink(replacement, root); err != nil {
						t.Fatal(err)
					}
				case "different directory":
					if err := os.MkdirAll(filepath.Join(root, ".live"), 0700); err != nil {
						t.Fatal(err)
					}
				}
				if shape != "not a folder" {
					t.Cleanup(func() { _ = os.RemoveAll(root); _ = os.Rename(saved, root) })
				}
			}
			snap, err := ledgerview.Load(root)
			if err != nil {
				t.Fatalf("warm root discarded its snapshot: %v", err)
			}
			if snap.ReadError == "" || snap.ReadErrorListed || len(snap.Pending()) != 3 {
				t.Fatalf("global failure lost queue: %+v", snap)
			}
			for _, run := range snap.Runs {
				if !strings.Contains(run.ReadError, "read ledger root:") || strings.Contains(run.ReadError, "record file is missing") {
					t.Errorf("root failure invented missing record: %s", run.ReadError)
				}
			}
			for _, route := range []string{"/approvals", "/"} {
				body := getRaw(t, s, c, route)
				doc := parseHTML(t, route, body)
				words := text(doc)
				if !strings.Contains(words, "(3+)") || !strings.Contains(body, `aria-label="at least 3 waiting:`) || !strings.Contains(words, "at least 3 waiting:") {
					t.Fatalf("%s lost known quantity", route)
				}
				if route == "/approvals" && (!strings.Contains(body, "ask-B") || !strings.Contains(body, "ask-C")) {
					t.Fatal("known request identities disappeared")
				}
			}
			if shape == "directory link" || shape == "different directory" {
				if !strings.Contains(snap.ReadError, "record folder changed") {
					t.Fatal("replacement did not explain its identity failure")
				}
				if err := os.RemoveAll(root); err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(root+"-saved", root); err != nil {
					t.Fatal(err)
				}
				recovered, err := ledgerview.Load(root)
				if err != nil || recovered.ReadError != "" || len(recovered.Pending()) != 3 {
					t.Fatalf("original root did not recover: %v %+v", err, recovered)
				}
			}
		})
	}
}

// readsThroughAnyMode says whether this process reads a file whatever its mode says, as root does with its
// capabilities: a mode of 000 then makes nothing unreadable.
func readsThroughAnyMode() bool { return os.Geteuid() == 0 }

func TestUnknownRunExpandedDetails(t *testing.T) {
	for _, shape := range []string{"missing", "unreadable"} {
		t.Run(shape, func(t *testing.T) {
			root := twoRequestFixture(t)
			holdLock(t, filepath.Join(root, harmRun))
			index := filepath.Join(root, ".live")
			switch {
			case shape == "missing":
				if err := os.RemoveAll(index); err != nil {
					t.Fatal(err)
				}
			case readsThroughAnyMode():
				// A mode of 000 stops no root read, so the index is unreadable as a folder the kernel refuses to
				// list: a file where its folder belongs.
				if err := os.RemoveAll(index); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(index, nil, 0600); err != nil {
					t.Fatal(err)
				}
			default:
				if err := os.Chmod(index, 0); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = os.Chmod(index, 0700) })
			}
			s := newServer(t, root)
			body := getRaw(t, s, login(t, s), "/runs/"+harmRun+"?details=1")
			doc := parseHTML(t, "expanded run details", body)
			found := map[string]bool{}
			walk(doc, func(n *html.Node) {
				if n.Data == "details" {
					if id, _ := attr(n, "id"); id == "run-details" {
						if _, ok := attr(n, "open"); !ok {
							t.Error("details were not expanded")
						}
					}
				}
				if n.Data != "dt" || (text(n) != "Ended" && text(n) != "Asks") {
					return
				}
				dd := n.NextSibling
				for dd != nil && dd.Type != html.ElementNode {
					dd = dd.NextSibling
				}
				if dd == nil {
					return
				}
				words := strings.ToLower(text(dd))
				found[text(n)] = true
				if strings.Contains(words, "lost") || !strings.Contains(words, "not known") || !strings.Contains(words, "live index") {
					t.Errorf("%s asserts a known state: %s", text(n), words)
				}
			})
			if !found["Ended"] || !found["Asks"] {
				t.Fatal("missing expanded facts")
			}
		})
	}
}

func TestChangedRootPhoneReason(t *testing.T) {
	w := waitingState{Reason: "read ledger root: the record folder changed"}
	if got := w.PhoneReason(); got != "the record folder changed" {
		t.Fatalf("changed root phone explanation is inaccurate: %q", got)
	}
}
