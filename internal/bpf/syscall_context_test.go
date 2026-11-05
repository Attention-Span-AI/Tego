// SPDX-License-Identifier: Apache-2.0

package bpf

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestSyscallResultContextRejectsUnsupportedLayouts(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, format, want string
	}{
		{"upstream", "field:int __syscall_nr; offset:8; size:4; signed:1;\nfield:long ret; offset:16; size:8; signed:1;", ""},
		{"rhel", "field:unsigned char common_preempt_lazy_count; offset:8; size:1; signed:0;\nfield:int __syscall_nr; offset:12; size:4; signed:1;\n\tfield:long ret;\toffset:16;\tsize:8;\tsigned:1;", ""},
		// A 16-byte trace_entry moves the record's ret to 24 and grows its
		// extent to 32, which passes the kernel's bounds check even though
		// syscall_tp_t still supplies ret at 16. Reject before loading.
		{"divergent", "field:int __syscall_nr; offset:16; size:4; signed:1;\nfield:long ret; offset:24; size:8; signed:1;", "ret offset 24 size 8"},
		{"wrong_size", "field:int ret; offset:16; size:4; signed:1;", "ret offset 16 size 4"},
		{"missing_return", "field:int __syscall_nr; offset:8; size:4; signed:1;\nprint fmt: REC->ret", "missing or malformed ret field"},
		{"malformed", "field:long ret; offset:unknown; size:8; signed:1;", "missing or malformed ret field"},
		{"duplicate", "field:long ret; offset:16; size:8;\nfield:long ret; offset:24; size:8;", "missing or malformed ret field"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, programs := range []map[string]string{ListenerTracepoints, ExecResultTracepoints} {
				for name, event := range programs {
					err := validateSyscallResultContext(name, func(path string) ([]byte, error) {
						if !strings.HasSuffix(path, "/syscalls/"+event+"/format") {
							t.Fatalf("wrong event path: %s", path)
						}
						return []byte(tc.format), nil
					})
					if tc.want == "" {
						if err != nil {
							t.Fatal(err)
						}
					} else if err == nil || !strings.Contains(err.Error(), tc.want) || !strings.Contains(err.Error(), event) {
						t.Fatalf("%s: got %v, want rejection naming %s and %q", name, err, event, tc.want)
					}
				}
			}
		})
	}
}

func TestSyscallResultContextTracefsReadFailsClosed(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		err  error
		want string
	}{
		{"absent", os.ErrNotExist, "tracefs event format is unavailable"},
		{"inaccessible", os.ErrPermission, "cannot read"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			err := validateSyscallResultContext(ProgBindResult, func(string) ([]byte, error) {
				calls++
				return nil, fmt.Errorf("format: %w", tc.err)
			})
			wantCalls := 1
			if errors.Is(tc.err, os.ErrNotExist) {
				wantCalls = 2
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) || calls != wantCalls {
				t.Fatalf("got %v after %d reads, want %q after %d", err, calls, tc.want, wantCalls)
			}
		})
	}
	var paths []string
	err := validateSyscallResultContext(ProgBindResult, func(path string) ([]byte, error) {
		paths = append(paths, path)
		if len(paths) == 1 {
			return nil, os.ErrNotExist
		}
		return []byte("field:long ret; offset:16; size:8; signed:1;"), nil
	})
	if err != nil || len(paths) != 2 || !strings.HasPrefix(paths[1], "/sys/kernel/debug/tracing/") {
		t.Fatalf("fallback: %v, paths %v", err, paths)
	}
	if err := validateSyscallResultContext(ProgSchedExec, func(string) ([]byte, error) {
		t.Fatal("a program without a syscall return read checked tracefs")
		return nil, nil
	}); err != nil {
		t.Fatal(err)
	}
}
