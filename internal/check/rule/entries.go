// SPDX-License-Identifier: Apache-2.0

package rule

// Entries is the entries the contract text spells in each list an edit may change (EditKeys), in file order: what the
// Change rules form offers to remove. Only plain string entries are listed, the ones OpRemove can name; a list the
// file does not have is absent from the map. An entry a profile or the built-in list adds is never here, since the
// file does not spell it and an edit cannot remove it.
func Entries(text []byte) (map[string][]string, error) {
	_, top, err := parse(text)
	if err != nil {
		return nil, err
	}
	out := map[string][]string{}
	for _, k := range editKeys {
		if !has(top, k) {
			continue
		}
		var es []string
		for _, e := range list(top, k) {
			if hasString(top, k, e) {
				es = append(es, e)
			}
		}
		out[k] = es
	}
	return out, nil
}
