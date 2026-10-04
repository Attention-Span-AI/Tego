// SPDX-License-Identifier: Apache-2.0

package config

import (
	"bytes"
	"errors"
	"io"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// decimalPattern is the shared grammar; the exported regexp is a separate
// instance so its mutation cannot change a loader's validation.
const decimalPattern = `^-?([0-9]+(\.[0-9]*)?|\.[0-9]+)([eE][-+]?[0-9]+)?$`

var decimalRE = regexp.MustCompile(decimalPattern)

// DecimalRE is a decimal number as cost_usd and cpu take one, in the contract and in the machine config:
// digits with an optional fraction and exponent. It is the spelling check, not strconv.ParseFloat's
// grammar, which also takes "1_0" (read as 10), hex floats such as "0x1p3", "Inf" and "NaN".
// Changing this regexp does not change machine or contract validation.
var DecimalRE = regexp.MustCompile(decimalPattern)

// IsDecimal reports whether s has the decimal spelling both loaders accept,
// independently of the exported DecimalRE compatibility value.
func IsDecimal(s string) bool { return decimalRE.MatchString(s) }

// Underflows reports whether s, an IsDecimal spelling ParseFloat read as f, is a nonzero number too small
// for a float64: it reads as 0, so a cost ceiling of 1e-400 would be a zero budget that trips on the
// first cent. Such a number is refused rather than read as 0.
func Underflows(s string, f float64) bool {
	mantissa, _, _ := strings.Cut(strings.ToLower(s), "e")
	return f == 0 && strings.Trim(mantissa, "-0.") != ""
}

// YAMLDocuments is how many YAML documents data holds; a parse error past the first counts as one more,
// since it is text after the first document either way. yaml.Unmarshal reads only the first, so a
// contract, a test table and a config layer each refuse more than one rather than drop the rest.
func YAMLDocuments(data []byte) int {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	n := 0
	for {
		var doc yaml.Node
		err := dec.Decode(&doc)
		if errors.Is(err, io.EOF) {
			return n
		}
		n++
		if err != nil {
			return n
		}
	}
}
