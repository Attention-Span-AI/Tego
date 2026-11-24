// SPDX-License-Identifier: Apache-2.0

//go:build integration && tegobpf

package doctor

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/platform/startphase"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

const probeExitHelper = "TEGO_TEST_DOCTOR_EXIT_HELPER"

// TestIntegrationProbeProcessExitDropsProgramsAndLinks catches a probe that pins
// an object or passes its ownership to a survivor. A descriptor count in the
// prober alone cannot establish this: inspect the guest kernel after wait reaps
// the process. The pinned-program control also proves the oracle rejects a
// surviving object, rather than accepting every exit.
func TestIntegrationProbeProcessExitDropsProgramsAndLinks(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("BPF object IDs and privileged probe exits require root in a guest")
	}
	for _, mode := range []string{"success", "error", "panic", "term", "kill", "pin"} {
		t.Run(mode, func(t *testing.T) {
			before := probeExitObjects(t)
			groups := probeExitCgroups(t)
			t.Cleanup(func() {
				// SIGKILL bypasses Go defers. Remove only the empty scratch
				// cgroup this child created, after checking its kernel objects.
				for path := range probeExitCgroups(t) {
					if !groups[path] {
						if err := os.Remove(path); err != nil {
							t.Error(err)
						}
					}
				}
			})
			pinDir, err := os.MkdirTemp("/sys/fs/bpf", "tego-probe-exit-")
			if err != nil {
				t.Fatal(err)
			}
			pin := filepath.Join(pinDir, "negative-program")
			t.Cleanup(func() {
				if err := os.Remove(pin); err != nil && !errors.Is(err, os.ErrNotExist) {
					t.Error(err)
				}
				if err := os.Remove(pinDir); err != nil {
					t.Error(err)
				}
			})
			exe, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
			defer cancel()
			cmd := exec.CommandContext(ctx, exe, "-test.run=^TestIntegrationProbeExitHelper$")
			cmd.Env = append(os.Environ(), probeExitHelper+"="+mode, "TEGO_TEST_DOCTOR_EXIT_PIN="+pin)
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			stdout, err := cmd.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			defer stdout.Close()
			stdin, err := cmd.StdinPipe()
			if err != nil {
				t.Fatal(err)
			}
			defer stdin.Close()
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			defer func() {
				if cmd.ProcessState == nil {
					_ = cmd.Process.Kill()
					_ = cmd.Wait()
				}
			}()
			line, err := bufio.NewReader(stdout).ReadString('\n')
			if err != nil || line != "probe-exit: attached\n" {
				_ = cmd.Process.Kill()
				_ = cmd.Wait()
				t.Fatalf("helper did not hold its first real hook: line=%q err=%v stderr=%s", line, err, stderr.String())
			}
			held := probeExitAdded(before, probeExitObjects(t))
			if len(held["prog"]) == 0 || len(held["link"]) == 0 {
				t.Fatalf("no actual program and link held before exit: %v", held)
			}
			switch mode {
			case "kill":
				if err := cmd.Process.Kill(); err != nil {
					t.Fatal(err)
				}
			case "term":
				if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
					t.Fatal(err)
				}
				if _, err := io.WriteString(stdin, "continue\n"); err != nil {
					t.Fatal(err)
				}
			default:
				if _, err := io.WriteString(stdin, "continue\n"); err != nil {
					t.Fatal(err)
				}
			}
			err = cmd.Wait()
			want := 0
			switch mode {
			case "error", "term":
				want = 23
			case "panic":
				want = 2
			case "kill":
				want = -1
			}
			if cmd.ProcessState.ExitCode() != want || want == 0 && err != nil {
				t.Fatalf("helper exit=%d, want=%d: %v\n%s", cmd.ProcessState.ExitCode(), want, err, stderr.String())
			}
			if mode == "kill" {
				status, ok := cmd.ProcessState.Sys().(syscall.WaitStatus)
				if !ok || status.Signal() != syscall.SIGKILL {
					t.Fatalf("not killed by SIGKILL: %v", cmd.ProcessState.Sys())
				}
			}
			// The kernel frees a tracing program (a trampoline's: tego_exec_pin_fmr, an fmod_ret) after a grace period
			// that follows its last reference, so on a preemptible kernel (fedora-7.0) its ID is listed for a few
			// milliseconds after wait reaps the process (measured 1.4 to 3.3 ms, both boots, with no descriptor, link,
			// pin or process holding it). The pinned control stays for good, so it is settled the same way and still
			// has to show its one program.
			added := probeExitSettled(t, before, mode == "pin")
			t.Logf("after %s exit: new kernel object IDs %v", mode, added)
			if mode == "pin" {
				if len(added["prog"]) != 1 || len(added["link"]) != 0 {
					t.Fatalf("oracle did not identify the deliberately pinned program: %v", added)
				}
			} else if len(added) != 0 {
				t.Fatalf("probe objects survived their owning process: %v", added)
			}
		})
	}
}

// TestIntegrationProbeExitHelper runs only in a child process. The phase sink is
// test-only instrumentation: pause after a successful real hook attachment so the
// parent can first establish that there are objects for its exit check to lose.
func TestIntegrationProbeExitHelper(t *testing.T) {
	mode := os.Getenv(probeExitHelper)
	if mode == "" {
		return
	}
	ctx, cancel := signal.NotifyContext(t.Context(), syscall.SIGTERM)
	defer cancel()
	if mode == "pin" {
		prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
			Name: "probe_exit_test", Type: ebpf.SocketFilter, License: "GPL",
			Instructions: asm.Instructions{asm.Mov.Imm(asm.R0, 0), asm.Return()},
		})
		if err != nil {
			t.Fatal(err)
		}
		defer prog.Close()
		if err := prog.Pin(os.Getenv("TEGO_TEST_DOCTOR_EXIT_PIN")); err != nil {
			t.Fatal(err)
		}
	}
	startphase.Default = func(name string, _ time.Duration) {
		if name != "probe.hook.fexit/security_file_open.attach" {
			return
		}
		fmt.Fprintln(os.Stdout, "probe-exit: attached")
		var ready [1]byte
		if _, err := io.ReadFull(os.Stdin, ready[:]); err != nil {
			panic(err)
		}
		switch mode {
		case "panic":
			panic("probe exit cleanup control")
		case "error":
			cancel()
		case "term":
			<-ctx.Done()
		}
	}
	_, err := Run(ctx, nil, "")
	if mode == "error" || mode == "term" {
		if err == nil || ctx.Err() == nil {
			t.Fatal("cancelled probe returned no context error")
		}
		os.Exit(23)
	}
	if err != nil {
		t.Fatal(err)
	}
}

func probeExitObjects(t *testing.T) map[string]map[uint32]bool {
	t.Helper()
	out := make(map[string]map[uint32]bool)
	for _, kind := range []string{"prog", "link"} {
		raw, err := exec.Command("bpftool", "-j", kind, "show").CombinedOutput()
		if err != nil {
			t.Fatalf("bpftool %s: %v: %s", kind, err, raw)
		}
		var rows []struct {
			ID uint32 `json:"id"`
		}
		if err := json.Unmarshal(raw, &rows); err != nil {
			t.Fatal(err)
		}
		out[kind] = make(map[uint32]bool, len(rows))
		for _, row := range rows {
			out[kind][row.ID] = true
		}
	}
	return out
}

// probeExitSettleBound is how long probeExitSettled waits for the kernel to finish freeing what an exited process
// held: the grace period after the last reference of a trampoline program, 1.4 to 3.3 ms measured on fedora-7.0's
// 7.0.14 kernel. A listing that is not clean after the bound is a holder, not a delay.
const probeExitSettleBound = 5 * time.Second

// probeExitSettled returns the objects added since before once they are what a clean exit leaves (none; with pinned,
// the one program the control pinned), polling until probeExitSettleBound, and what it last saw after it.
func probeExitSettled(t *testing.T, before map[string]map[uint32]bool, pinned bool) map[string][]uint32 {
	t.Helper()
	deadline := time.Now().Add(probeExitSettleBound)
	for {
		added := probeExitAdded(before, probeExitObjects(t))
		clean := len(added["prog"]) == 0 && len(added["link"]) == 0
		if pinned {
			clean = len(added["prog"]) == 1 && len(added["link"]) == 0
		}
		if clean || time.Now().After(deadline) {
			return added
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func probeExitAdded(before, after map[string]map[uint32]bool) map[string][]uint32 {
	out := make(map[string][]uint32)
	for kind, ids := range after {
		for id := range ids {
			if !before[kind][id] {
				out[kind] = append(out[kind], id)
			}
		}
		slices.Sort(out[kind])
	}
	return out
}

func probeExitCgroups(t *testing.T) map[string]bool {
	t.Helper()
	out := make(map[string]bool)
	err := filepath.WalkDir("/sys/fs/cgroup", func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() && strings.HasPrefix(entry.Name(), probeCgroupPrefix) {
			out[path] = true
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}
