// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"fmt"
	"strings"
)

// CountedAPI is a model API style whose answers a token or cost budget counts: the models[] provider value that
// declares it, and how a person is told of it.
type CountedAPI struct {
	// Provider is the models[] provider value (matched without case).
	Provider string
	// Words names the API and the value that declares it, for a message ("Anthropic's Messages API (provider:
	// anthropic)").
	Words string
}

// CountedAPIs is every model API style a build counts for limits.tokens and limits.cost_usd. It is the list the
// compiler's [budget-uncounted] warning, the end-of-run message and the documents state, and a test holds it equal to
// the provider names of the parsers the binary links (internal/cli), so it cannot name a style no parser reads.
var CountedAPIs = []CountedAPI{
	{Provider: "anthropic", Words: "Anthropic's Messages API (provider: anthropic)"},
	{Provider: "openai", Words: "OpenAI's Chat Completions and Responses APIs (provider: openai)"},
}

// BudgetCounts reports whether a token or cost budget counts the answers of a model declared with provider.
func BudgetCounts(provider string) bool {
	p := strings.ToLower(strings.TrimSpace(provider))
	for _, a := range CountedAPIs {
		if a.Provider == p {
			return true
		}
	}
	return false
}

// CountedAPIWords is the counted styles as one phrase, "A (provider: a) or B (provider: b)".
func CountedAPIWords() string {
	words := make([]string, len(CountedAPIs))
	for i, a := range CountedAPIs {
		words[i] = a.Words
	}
	switch len(words) {
	case 0:
		return "none"
	case 1:
		return words[0]
	}
	return fmt.Sprintf("%s or %s", strings.Join(words[:len(words)-1], ", "), words[len(words)-1])
}
