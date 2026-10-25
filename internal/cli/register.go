// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"sort"
)

// commandTable is the command table (R29): each noun's file registers its command from init, so no file edits another
// noun's registration (ADR 0100 (2)). It holds constructors, so each Main builds fresh commands, whose flag values
// live in the closures.
var commandTable = map[string]func() Command{}

// register adds a noun's command. A second registration of one name is a programming error, caught by every test
// of this package at its start.
func register(mk func() Command) {
	name := mk().Name
	if _, dup := commandTable[name]; dup {
		panic("tego: command " + name + " registered twice")
	}
	commandTable[name] = mk
}

// commands is the dispatch table, sorted by name, the order usage lists them in.
func commands() []Command {
	names := make([]string, 0, len(commandTable))
	for n := range commandTable {
		names = append(names, n)
	}
	sort.Strings(names)
	out := make([]Command, 0, len(names))
	for _, n := range names {
		out = append(out, commandTable[n]())
	}
	return out
}
