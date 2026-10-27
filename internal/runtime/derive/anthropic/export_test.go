// SPDX-License-Identifier: Apache-2.0

package anthropic

import (
	"encoding/json"
	"fmt"
)

// classifyPath is classifyPathOn (whose doc is the contract) for Anthropic's own host.
func classifyPath(method, target string) pathKind { return classifyPathOn(method, target, false) }

// ParseRequest is validateRequest (whose doc is the contract) that keeps encoding/json's reading of the body:
// the tests read the Request it returns.
func ParseRequest(body []byte) (*Request, error) {
	if len(body) == 0 {
		return nil, fmt.Errorf("%w: empty request body", ErrSchema)
	}
	var req Request
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, fmt.Errorf("%w: request body: %w", ErrSchema, err)
	}
	if req.Model == "" {
		return nil, fmt.Errorf("%w: request without a model", ErrSchema)
	}
	return &req, nil
}
