// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "tego: this launcher needs Windows; install the Linux tego command here")
	os.Exit(125)
}
