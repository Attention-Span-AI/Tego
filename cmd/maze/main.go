// SPDX-License-Identifier: Apache-2.0

// Command maze is the user-facing CLI: set up a repo, run an agent under its rules, read what happened.
// It drives the engine (cmd/tego) and is built separately from it, so it also builds on macOS.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/attention-span-ai/tego/internal/maze/cli"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := cli.Main(ctx, os.Args[1:], cli.Streams{In: os.Stdin, Out: os.Stdout, Err: os.Stderr})
	stop()
	os.Exit(code)
}
