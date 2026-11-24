// SPDX-License-Identifier: Apache-2.0

package registry

import "context"

func (p Places) Catalog() ([]CatalogEntry, []CatalogRoot) {
	return p.CatalogContext(context.Background())
}
