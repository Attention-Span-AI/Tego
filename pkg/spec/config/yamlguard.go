// SPDX-License-Identifier: Apache-2.0

package config

import (
	"errors"
	"runtime"
	"strings"
)

// errYAMLMergeKey is GuardYAML's error for the input yaml.v3 panics on.
var errYAMLMergeKey = errors.New("yaml: a list or a mapping as a key, where a merge key (<<) applies")

// GuardYAML runs decode, a yaml.v3 decode into a Go value (yaml.Unmarshal, Decoder.Decode or Node.Decode), and
// returns as an error the panic yaml.v3 v3.0.1 raises, instead of an error, on a key that is a list or a mapping
// where a merge key (<<) applies. Its decoder then records the mapping's keys in a Go map: the keys beside the merge
// key (decode.go:964-966) and, in a map with interface keys, the keys the merge brings in (:834-835). A list or a
// mapping cannot be a Go map key, the runtime panics with "hash of unhashable type", and yaml.v3 passes on every
// panic that is not its own error, so the 7 bytes `{<<,[]}` crashed each reader this guard now wraps (the price
// table, a contract, the dashboard's reads of a run's contract copy). A decode into a yaml.Node merges nothing and
// needs no guard. Any other panic is not this one and is raised again.
func GuardYAML(decode func() error) (err error) {
	defer func() {
		r := recover()
		if r == nil {
			return
		}
		if re, ok := r.(runtime.Error); ok && strings.Contains(re.Error(), "hash of unhashable type") {
			err = errYAMLMergeKey
			return
		}
		panic(r)
	}()
	return decode()
}
