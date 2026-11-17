// SPDX-License-Identifier: Apache-2.0

package kernelconfig

import (
	"bufio"
	"compress/gzip"
	"io"
	"os"
	"strings"
)

// Paths lists the running kernel's configuration first, followed by its installed copies.
func Paths(release string) []string {
	return []string{"/proc/config.gz", "/boot/config-" + release, "/lib/modules/" + release + "/config"}
}

// Read returns the CONFIG_ options set to y in a plain or gzip build configuration.
// An unreadable, incomplete or empty configuration is no answer.
func Read(path string) (map[string]bool, bool) {
	f, err := os.Open(path)
	if err != nil {
		return nil, false
	}
	defer func() { _ = f.Close() }()
	var r io.Reader = f
	if strings.HasSuffix(path, ".gz") {
		gz, err := gzip.NewReader(f)
		if err != nil {
			return nil, false
		}
		defer func() { _ = gz.Close() }()
		r = gz
	}
	return Scan(r)
}

// Scan reads CONFIG_ options from configuration text; errors and empty input are no answer.
func Scan(r io.Reader) (map[string]bool, bool) {
	out := map[string]bool{}
	configs := 0
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "CONFIG_") || strings.HasPrefix(line, "# CONFIG_") {
			configs++
		}
		if k, ok := strings.CutSuffix(line, "=y"); ok && strings.HasPrefix(k, "CONFIG_") {
			out[k] = true
		}
	}
	if sc.Err() != nil || configs == 0 {
		return nil, false
	}
	return out, true
}
