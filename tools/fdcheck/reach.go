// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
)

// reachTags are the tag sets every product binary is built with (ADR 0023 A7, F11).
var reachTags = []string{"", "tegobpf", "tegotesthooks", "tegobpf,tegotesthooks"}

// ExemptPackage is whether an import path is exempt code that no product binary may link: internal/testutil,
// tools, test, or a fixture under a testdata directory.
func ExemptPackage(path string) bool {
	rel, ok := strings.CutPrefix(path, modulePath+"/")
	if !ok {
		return false
	}
	for _, p := range []string{"internal/testutil", "tools", "test"} {
		if rel == p || strings.HasPrefix(rel, p+"/") {
			return true
		}
	}
	return rel == "testdata" || strings.HasPrefix(rel, "testdata/") || strings.Contains(rel, "/testdata/") ||
		strings.HasSuffix(rel, "/testdata")
}

// ReachProblems names the exempt packages in one build's dependency list.
func ReachProblems(build string, deps []string) []string {
	var out []string
	for _, d := range deps {
		if ExemptPackage(d) {
			out = append(out, fmt.Sprintf("F11: ./cmd/... links %s (%s): exempt code never reaches a product binary (ADR 0023 A7)", d, build))
		}
	}
	return out
}

// reachBuilds are the builds F11 lists ./cmd/... under: each architecture the project ships with cgo off, as the
// release builds it, and amd64 with cgo, which a plain `go build` on a host with a C compiler makes, each under
// every tag set. A file only one of them builds (an _arm64.go file, a cgo file) can import a package the others
// never see.
func reachBuilds() []buildConfig {
	var out []buildConfig
	for _, b := range []struct {
		arch string
		cgo  bool
	}{{"amd64", false}, {"arm64", false}, {"amd64", true}} {
		for _, tags := range reachTags {
			name := "linux/" + b.arch
			if b.cgo {
				name += " cgo"
			}
			if tags == "" {
				name += " no tags"
			} else {
				name += " " + tags
			}
			out = append(out, buildConfig{name, "linux", b.arch, tags, b.cgo})
		}
	}
	return out
}

// Reach lists ./cmd/...'s dependencies under each build and checks them. The environment is the build's
// (goEnv), so the host's GOARCH, CGO_ENABLED, GOFLAGS and go.work change nothing.
func Reach(root string) ([]string, error) {
	var out []string
	for _, c := range reachBuilds() {
		args := []string{"list", "-deps"}
		if c.tags != "" {
			args = append(args, "-tags", c.tags)
		}
		args = append(args, "./cmd/...")
		cmd := exec.Command(goTool(), args...)
		cmd.Dir = root
		cmd.Env = goEnv(c)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		o, err := cmd.Output()
		if err != nil {
			return nil, fmt.Errorf("go %s (%s): %v: %s", strings.Join(args, " "), c.name, err, strings.TrimSpace(stderr.String()))
		}
		out = append(out, ReachProblems(c.name, strings.Fields(string(o)))...)
	}
	return out, nil
}
