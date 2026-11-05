// SPDX-License-Identifier: Apache-2.0

package bpf

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
)

// ValidateSyscallResultContext refuses syscall result hooks whose trace record
// disagrees with the BPF exit wrapper's eight-byte return at offset 16. Call
// before loading or adopting a program, including doctor's stand-in programs.
// Other programs do not read this context and need no tracefs check.
func ValidateSyscallResultContext(program string) error {
	return validateSyscallResultContext(program, os.ReadFile)
}

func validateSyscallResultContext(program string, readFile func(string) ([]byte, error)) error {
	event := ListenerTracepoints[program]
	if event == "" {
		event = ExecResultTracepoints[program]
	}
	if event == "" {
		return nil
	}
	for _, base := range []string{"/sys/kernel/tracing", "/sys/kernel/debug/tracing"} {
		path := filepath.Join(base, "events", "syscalls", event, "format")
		data, err := readFile(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return fmt.Errorf("syscall result context %s: cannot read %s: %w", event, path, err)
		}
		return validateSyscallResultFormat(event, data)
	}
	return fmt.Errorf("syscall result context %s: tracefs event format is unavailable", event)
}

var syscallReturnField = regexp.MustCompile(`(?m)^[\t ]*field:[^;\n]*[\t ]ret;[\t ]*offset:([0-9]+);[\t ]*size:([0-9]+);`)

func validateSyscallResultFormat(event string, data []byte) error {
	// syscall_trace_exit is the CO-RE trace record, not perf_call_bpf_exit's
	// syscall_tp_t wrapper. The perf link only checks access bounds against
	// the record's extent: a larger record could accept a wrongly relocated
	// read. Admit only the record layout that matches the supported wrapper.
	fields := syscallReturnField.FindAllSubmatch(data, -1)
	if len(fields) != 1 {
		return fmt.Errorf("syscall result context %s: missing or malformed ret field; BPF syscall exit wrapper requires offset 16 size 8", event)
	}
	if string(fields[0][1]) != "16" || string(fields[0][2]) != "8" {
		return fmt.Errorf("syscall result context %s: ret offset %s size %s; BPF syscall exit wrapper requires offset 16 size 8",
			event, fields[0][1], fields[0][2])
	}
	return nil
}
