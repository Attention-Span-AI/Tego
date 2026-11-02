// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"path/filepath"
	"testing"
)

// TestKeyLayerFilesAgree: a build carries the key layer whole or not at all. The compiler's half lets a contract's
// credentials: compile and this package's half starts the injection, so with the first and without the second a run
// would start with no key and nothing said: the skip the refusal exists to rule out. It holds in every tree.
func TestKeyLayerFilesAgree(t *testing.T) {
	_, err := os.Stat(filepath.Join("..", "..", "pkg", "spec", "agent", "credentials_vault.go"))
	if compiles := err == nil; compiles != (credentialLayer != nil) {
		t.Fatalf("credentials: compiles %t, key layer registered %t: a manifest left out one half of the layer", compiles, credentialLayer != nil)
	}
	if (credentialLayer != nil) != (routeKeyNote != "") {
		t.Fatalf("key layer registered %t, its sentence for a route's y/N %q: the layer and its promise come together", credentialLayer != nil, routeKeyNote)
	}
}
