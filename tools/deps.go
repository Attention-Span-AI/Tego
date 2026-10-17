//go:build tools

// SPDX-License-Identifier: Apache-2.0

// Package tools names the TCB's allowed third-party modules (docs/REPO-LAYOUT.md), so go.mod keeps each one at its
// pinned version. Every one but go-landlock is also imported by the code; go-landlock is in no shipped package's
// imports (internal/runtime/enforce/landlock makes the syscalls itself), and this file is all that keeps it in
// go.mod: docs/ARCHITECTURE.md's open condition on the dependency rule says so.
package tools

import (
	_ "github.com/cilium/ebpf"
	_ "github.com/landlock-lsm/go-landlock/landlock"
	_ "golang.org/x/net/bpf"
	_ "golang.org/x/sys/unix"
	_ "gopkg.in/yaml.v3"
)
