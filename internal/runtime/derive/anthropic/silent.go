// SPDX-License-Identifier: Apache-2.0

package anthropic

// Silent reports that the request spends nothing whatever its answer, by the classification Parse applies to
// an answered one (classifyPathOn): an unanswered request to such a path is not an unmetered exchange (ADR 0037
// amendment 2026-09-24). A path it cannot place is not silent.
func (p *Parser) Silent(method, target string) bool {
	return classifyPathOn(method, target, p.declared) == pathSilent
}
