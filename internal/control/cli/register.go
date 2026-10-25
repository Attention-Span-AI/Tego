// SPDX-License-Identifier: Apache-2.0

package cli

import "sort"

// commands is the registry: each noun's file registers its command from init (register.go), so no file edits
// another noun's registration (ADR 0100 (2)).
var commands = map[string]func() Command{}

// register adds a noun's command. A second registration of one name is a programming error.
func register(mk func() Command) {
	c := mk()
	if _, dup := commands[c.Name]; dup {
		panic("tego-control: command " + c.Name + " registered twice")
	}
	commands[c.Name] = mk
}

// Names lists the registered commands, sorted.
func Names() []string {
	out := make([]string, 0, len(commands))
	for n := range commands {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// Lookup returns the registered command name.
func Lookup(name string) (Command, bool) {
	mk, ok := commands[name]
	if !ok {
		return Command{}, false
	}
	return mk(), true
}
