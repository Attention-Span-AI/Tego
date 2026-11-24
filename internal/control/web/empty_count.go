// SPDX-License-Identifier: Apache-2.0

package web

import "strings"

// unknownCount replaces an empty-state claim ("Nothing running", "No connections") when its source cannot establish
// the absence: an empty state is a count of zero, so it follows the same source completeness as the counts.
func unknownCount(scope countScope, subject string) string {
	if scope.Error != "" {
		return subject + " could not be read: " + scope.Error
	}
	if scope.Lower {
		return subject + " are not fully known: " + scope.Reason
	}
	return ""
}

func init() { funcs["unknownCount"] = unknownCount }

// quantityZero registers an absence with the source whose zero it describes.
func quantityZero(id, words string, scopes countScopes) (quantity, error) {
	q, err := quantityOf(id, 0, scopes)
	if err != nil {
		return quantity{}, err
	}
	switch {
	case q.Text == "could not tell whether a request is waiting":
	case q.Text == "could not read":
		q.Text = "The source could not be read"
	case q.Reason != "":
		suffix := ""
		if strings.HasSuffix(words, ".") {
			words = strings.TrimSuffix(words, ".")
			suffix = "."
		}
		q.Text = words + " seen in what is retained" + suffix
	default:
		q.Text = words
	}
	return q, nil
}

func init() { funcs["quantityZero"] = quantityZero }
