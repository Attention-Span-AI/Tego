// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSaveNeverFollowsAgentsLinkToRegistry(t *testing.T) {
	dir := t.TempDir()
	if err := os.Symlink(".", filepath.Join(dir, AgentsDir)); err != nil {
		t.Fatal(err)
	}
	sv := Save{Places: Places{User: dir}, Name: "config", Text: []byte("name: config\n")}
	if _, err := sv.Write(); err == nil {
		t.Fatal("Save followed agents -> .")
	}
	for _, p := range []string{filepath.Join(dir, "config.yaml"), filepath.Join(dir, AgentsDir, "config.yaml")} {
		if _, err := os.Lstat(p); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("unexpected destination %s: %v", p, err)
		}
	}
}

func TestSaveInterruptedWriteNeverPublishesPartialContract(t *testing.T) {
	dir := t.TempDir()
	interrupted := errors.New("interrupted")
	old := writeStep
	writeStep = func(step string) error {
		if step == "file-sync" {
			return interrupted
		}
		return nil
	}
	t.Cleanup(func() { writeStep = old })
	sv := Save{Places: Places{User: dir}, Name: "complete", Text: []byte(strings.Repeat("# contract\n", 1000))}
	_, err := sv.Write()
	if !errors.Is(err, interrupted) || !strings.Contains(err.Error(), "file-sync") {
		t.Fatalf("Write=%v, want interrupted file-sync", err)
	}
	if _, err := os.Lstat(filepath.Join(dir, AgentsDir, "complete.yaml")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("interrupted write published final name: %v", err)
	}
	ents, err := os.ReadDir(filepath.Join(dir, AgentsDir))
	if err != nil {
		t.Fatal(err)
	}
	if len(ents) != 0 {
		t.Fatalf("temporary files left after interruption: %v", ents)
	}
}

func TestSaveOnlyPublishesAfterFileSync(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, AgentsDir, "complete.yaml")
	var steps []string
	old := writeStep
	writeStep = func(step string) error {
		steps = append(steps, step)
		_, err := os.Lstat(path)
		if step == "directory-sync" {
			if err != nil {
				t.Errorf("complete file absent after publication: %v", err)
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			t.Errorf("final name exists before %s: %v", step, err)
		}
		return nil
	}
	t.Cleanup(func() { writeStep = old })
	text := []byte("name: complete\n")
	if _, err := (Save{Places: Places{User: dir}, Name: "complete", Text: text}).Write(); err != nil {
		t.Fatal(err)
	}
	if strings.Join(steps, ",") != "file-sync,publish,directory-sync" {
		t.Fatalf("publication order=%v", steps)
	}
	if b, err := os.ReadFile(path); err != nil || string(b) != string(text) {
		t.Fatalf("published %q: %v", b, err)
	}
}

func TestSaveBindsPinnedDirectoryIdentity(t *testing.T) {
	dir := t.TempDir()
	agents := filepath.Join(dir, AgentsDir)
	pinned, err := OpenDirectory(agents, true)
	if err != nil {
		t.Fatal(err)
	}
	id, err := pinned.Identity()
	if err != nil {
		t.Fatal(err)
	}
	if err := pinned.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(agents, agents+"-reviewed"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(agents, 0700); err != nil {
		t.Fatal(err)
	}
	sv := Save{Places: Places{User: dir}, Name: "complete", Text: []byte("name: complete\n"), ExpectedDirectory: &id}
	if _, err := sv.Write(); !errors.Is(err, ErrFileChanged) {
		t.Fatalf("new directory accepted: %v", err)
	}
	for _, d := range []string{agents, agents + "-reviewed"} {
		if ents, err := os.ReadDir(d); err != nil || len(ents) != 0 {
			t.Fatalf("wrote into %s: %v, %v", d, ents, err)
		}
	}
}

// This is a test subprocess, never a product binary. Killing it at the file-sync
// boundary proves that service termination cannot expose the temporary bytes.
func TestSaveProcessInterruptedBeforePublication(t *testing.T) {
	const childDir = "TEGO_REGISTRY_WRITE_TEST_CHILD"
	if dir := os.Getenv(childDir); dir != "" {
		writeStep = func(step string) error {
			if step == "file-sync" {
				fmt.Fprintln(os.Stdout, "ready")
				var wait [1]byte
				_, err := os.Stdin.Read(wait[:])
				return err
			}
			return nil
		}
		_, err := (Save{Places: Places{User: dir}, Name: "complete", Text: []byte(strings.Repeat("# complete contract\n", 4096))}).Write()
		if err != nil {
			t.Fatal(err)
		}
		return
	}
	dir := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestSaveProcessInterruptedBeforePublication$")
	cmd.Env = append(os.Environ(), childDir+"="+dir)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = stdin.Close() }()
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if cmd.ProcessState == nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	})
	line, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil || line != "ready\n" {
		t.Fatalf("child publication boundary: %q, %v", line, err)
	}
	if err = cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err = cmd.Wait(); err == nil {
		t.Fatal("interrupted subprocess exited successfully")
	}
	if ctx.Err() != nil {
		t.Fatalf("child timed out: %v", ctx.Err())
	}
	if _, err = os.Lstat(filepath.Join(dir, AgentsDir, "complete.yaml")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("terminated writer published final name: %v", err)
	}
}

func TestSaveDirectorySyncFailureReportsCompletePublication(t *testing.T) {
	dir := t.TempDir()
	unavailable := errors.New("sync unavailable")
	old := writeStep
	writeStep = func(step string) error {
		if step == "directory-sync" {
			return unavailable
		}
		return nil
	}
	t.Cleanup(func() { writeStep = old })
	text := []byte("name: complete\n")
	path, err := (Save{Places: Places{User: dir}, Name: "complete", Text: text}).Write()
	var se *SaveError
	if !errors.As(err, &se) || se.Step != SaveIO || se.Op != "write" || !errors.Is(err, unavailable) ||
		!strings.Contains(err.Error(), "complete complete.yaml was published") {
		t.Fatalf("failure does not say final file exists: %v", err)
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != string(text) {
		t.Fatalf("published contents=%q, err=%v", got, err)
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "complete.yaml" {
		t.Fatalf("unexpected temporary files after publication: %v", entries)
	}
}

func TestSaveRefusesWhenPublicationReviewChanges(t *testing.T) {
	dir := t.TempDir()
	changed := errors.New("review changed")
	calls := 0
	sv := Save{Places: Places{User: dir}, Name: "complete", Text: []byte("name: complete\n"), BeforePublish: func() error { calls++; return changed }}
	if _, err := sv.Write(); !errors.Is(err, changed) || calls != 1 {
		t.Fatalf("publication review calls=%d, err=%v", calls, err)
	}
	if entries, err := os.ReadDir(filepath.Join(dir, AgentsDir)); err != nil || len(entries) != 0 {
		t.Fatalf("refused publication left files=%v, err=%v", entries, err)
	}
}

func TestSaveCleanupFailureReportsRemainingContract(t *testing.T) {
	l := newLayout(t)
	sv := l.saveOf("complete")
	sv.Places.Own = []string{filepath.Dir(l.user)}
	unavailable := errors.New("removal unavailable")
	old := writeStep
	writeStep = func(step string) error {
		if step == "unusable-remove" {
			return unavailable
		}
		return nil
	}
	t.Cleanup(func() { writeStep = old })
	path, err := sv.Write()
	var se *SaveError
	if !errors.As(err, &se) || se.Step != SaveIO || se.Op != "write" || !errors.Is(err, unavailable) ||
		!strings.Contains(err.Error(), "complete complete.yaml may remain") {
		t.Fatalf("cleanup failure does not report the remaining contract: %v", err)
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != string(sv.Text) {
		t.Fatalf("remaining contract=%q, err=%v", got, err)
	}
}

func TestWriterRefusesTemporarySubstitutionDuringReview(t *testing.T) {
	for _, replace := range []bool{false, true} {
		name := "edited-bytes"
		if replace {
			name = "same-bytes-new-inode"
		}
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			text := []byte("name: complete\n")
			sv := Save{Places: Places{User: dir}, Name: "complete", Text: text}
			sv.BeforePublish = func() error {
				temporary, err := filepath.Glob(filepath.Join(dir, AgentsDir, ".complete.yaml.tego-write-*"))
				if err != nil {
					return err
				}
				if len(temporary) != 1 {
					return fmt.Errorf("temporary file count=%d", len(temporary))
				}
				if replace {
					if err := os.Rename(temporary[0], temporary[0]+".reviewed"); err != nil {
						return err
					}
					return os.WriteFile(temporary[0], text, 0600)
				}
				return os.WriteFile(temporary[0], []byte("unreviewed: true\n"), 0600)
			}
			path, err := sv.Write()
			if !errors.Is(err, ErrFileChanged) || !strings.Contains(err.Error(), "temporary-recheck") {
				t.Fatalf("temporary substitution accepted: %v", err)
			}
			if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("unreviewed temporary file published: %v", err)
			}
			entries, err := os.ReadDir(filepath.Join(dir, AgentsDir))
			if err != nil {
				t.Fatal(err)
			}
			for _, entry := range entries {
				if !replace || !strings.HasSuffix(entry.Name(), ".reviewed") {
					t.Errorf("temporary name left after refusal: %s", entry.Name())
				}
			}
		})
	}
}
