// SPDX-License-Identifier: Apache-2.0

// Package shellword writes a string as one word of a shell command line, for the lines Tego prints for a person to
// paste into a terminal: the dashboard's terminal twins ("Same in a terminal": tego block, tego lift, tego compile,
// cd <folder>, a run's restart line) and tego doctor's `sudo <path> doctor`. A word made only of letters, digits and
// / . _ - : @ , + =, which sh, bash, zsh and fish read as themselves, stays as it is unless it starts with = (zsh
// reads =name as a program's path); any other word, the empty one included, goes in single quotes, with each ' and \
// in it written outside them, so the quoted text holds nothing one of those shells reads specially.
//
// The run page's Block now panel writes its twin in the browser (internal/control/web, static/twin.js) by the same
// rule; TestTwinJSRules there holds the script's copy of it to Quote. The maze setup tool quotes the commands it
// suggests with its own copy (internal/maze/cli), since maze stays separable from the engine, and tego setup quotes
// the words of a generated contract's sh -c command with its own (internal/setup), for sh, not for a person.
//
// It is pure: no I/O, no state.
//
// Imports: the standard library only.
// Must not import: anything of this module (both binaries link it: tego through internal/doctor, tego-control
// through internal/control/web).
package shellword
