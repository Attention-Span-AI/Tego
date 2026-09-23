// SPDX-License-Identifier: Apache-2.0

package main

import "github.com/attention-span-ai/tego/internal/runtime/launch"

// childCommand is argv[1] of the child stage; the launcher execs `/proc/self/exe __child`.
const childCommand = launch.ChildCommand

// childMain runs the child stage and returns its exit code. main dispatches to it before anything else
// when os.Args[1] == childCommand: the stage must never pass through the ordinary command-line
// parser, which may print, read config or open files the sandboxed run must not see.
func childMain(args []string) int { return launch.ChildMain(args) }
