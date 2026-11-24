// SPDX-License-Identifier: Apache-2.0

package jsonschema

import "testing"

func TestLocalRolesConfigSchema(t *testing.T) {
	const schema = "../../../spec/config/v0/local-authority.schema.json"
	for _, mode := range []string{"owner_only", "off"} {
		Validate(t, schema, map[string]any{"local_roles": mode})
	}
	for _, doc := range []any{map[string]any{"local_roles": "approver"}, map[string]any{"local_roles": nil}, map[string]any{"local_roles": "owner_only", "role": "owner"}, map[string]any{}} {
		if Check(schema, doc) == nil {
			t.Fatalf("accepted %v", doc)
		}
	}
}
