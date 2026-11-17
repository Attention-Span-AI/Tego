// SPDX-License-Identifier: Apache-2.0

package tomoyo

import (
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/attention-span-ai/tego/internal/platform/kernelconfig"
	"golang.org/x/sys/unix"
)

const (
	selfDomain = "/sys/kernel/security/tomoyo/self_domain"
	stat       = "/sys/kernel/security/tomoyo/stat"
	limit      = 64 * 1024
)

// ReadFile bounds security-module facts without silently truncating them.
func ReadFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err == nil && len(b) > limit {
		err = errors.New("LSM fact exceeds 64 KiB")
	}
	return b, err
}

// Check reads the checking thread's domain and policy-update line afresh.
// No policy observation is kept between checks or runs (ADR 0041).
func Check(read func(string) ([]byte, error)) error {
	return check(read, omittedLoader())
}

// Only the running kernel's immutable build configuration is cached.
var omittedLoader = newLoaderOmission(unix.Uname, kernelconfig.Read)

func newLoaderOmission(uname func(*unix.Utsname) error, read func(string) (map[string]bool, bool)) func() string {
	var mu sync.Mutex
	var definite bool
	var source string
	return func() string {
		mu.Lock()
		defer mu.Unlock()
		if definite {
			return source
		}
		paths := []string{"/proc/config.gz"}
		var u unix.Utsname
		if uname(&u) == nil {
			paths = kernelconfig.Paths(unix.ByteSliceToString(u.Release[:]))
		}
		source, definite = loaderOmission(paths, read)
		return source
	}
}

// SetLoaderOmissionForTest replaces the build-configuration observation and returns
// its restore function. Tests using it must not run in parallel.
func SetLoaderOmissionForTest(load func() string) func() {
	original := omittedLoader
	omittedLoader = load
	return func() { omittedLoader = original }
}

func loaderOmission(paths []string, read func(string) (map[string]bool, bool)) (string, bool) {
	readable := false
	for _, path := range paths {
		if cfg, ok := read(path); ok {
			readable = true
			if cfg["CONFIG_SECURITY_TOMOYO_OMIT_USERSPACE_LOADER"] {
				return path, true
			}
		}
	}
	return "", readable
}

func check(read func(string) ([]byte, error), omittedSource string) error {
	domain, domainErr := read(selfDomain)
	data, statErr := read(stat)
	if domainErr != nil {
		return fmt.Errorf("TOMOYO %s: %w", selfDomain, domainErr)
	}
	s := strings.TrimSuffix(strings.TrimSuffix(string(domain), "\x00"), "\n")
	if len(domain) > limit || s == "" || strings.ContainsAny(s, "\x00\n") {
		return fmt.Errorf("TOMOYO self_domain %s is empty, malformed or exceeds 64 KiB", selfDomain)
	}
	if s != "<kernel>" {
		return fmt.Errorf("TOMOYO observed domain %q prevents held file opens", s)
	}
	if statErr != nil {
		return fmt.Errorf("TOMOYO %s: %w", stat, statErr)
	}
	if len(data) > limit {
		return fmt.Errorf("TOMOYO stat %s exceeds 64 KiB", stat)
	}
	line, _, terminated := strings.Cut(string(data), "\n")
	if !terminated {
		return fmt.Errorf("TOMOYO stat %s has a missing or malformed Policy update: line", stat)
	}
	// The sole accepted line is common.c:tomoyo_read_stat's never-updated
	// format, including its padding and newline, captured in Debian 13 as 49 bytes.
	if line+"\n" != "Policy update:                                 0\n" {
		if isUpdatedLine(line) {
			return errors.New("TOMOYO's policy has been updated since boot; held file opens are refused on this machine until TOMOYO is unused again after a restart")
		}
		return fmt.Errorf("TOMOYO stat %s has a missing or malformed Policy update: line", stat)
	}
	if omittedSource != "" {
		return fmt.Errorf("TOMOYO %s reads CONFIG_SECURITY_TOMOYO_OMIT_USERSPACE_LOADER=y; its built-in policy can enforce without a counted update; held file opens are refused on this machine; use a kernel without this option", omittedSource)
	}
	return nil
}

// Used only to explain a refusal; recognizing an update never grants an open.
var updatedLine = regexp.MustCompile(`^Policy update: +([0-9]+)(?: \(Last: ([0-9]{4}/[0-9]{2}/[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2})\))?$`)

func isUpdatedLine(line string) bool {
	m := updatedLine.FindStringSubmatch(line)
	if m == nil {
		return false
	}
	count, err := strconv.ParseUint(m[1], 10, 32)
	if err != nil {
		return false
	}
	expected := fmt.Sprintf("Policy %-30s %10d", "update:", count)
	if m[2] != "" {
		if _, err := time.Parse("2006/01/02 15:04:05", m[2]); err != nil {
			return false
		}
		expected += " (Last: " + m[2] + ")"
	}
	return expected == line && (count != 0 || m[2] != "")
}
