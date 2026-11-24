// SPDX-License-Identifier: Apache-2.0

package scan

import "context"

// Charge raw results before catalogNamesLimit can discard an overflow, error,
// invalid name or changed inode. Reserve its lookahead inside the aggregate cap.
// Even empty/failed listings spend one slot, so retries cannot get free work.
type chargedUnitDirectory struct {
	catalogDirectory
	remaining *int
}

func (d chargedUnitDirectory) names(n int) ([]string, error) {
	names, err := d.catalogDirectory.names(n)
	*d.remaining -= max(0, len(names)-1)
	return names, err
}

func unitDirectoryNames(ctx context.Context, dir catalogDirectory, remaining *int) ([]string, error) {
	return unitDirectoryNamesLimit(ctx, dir, remaining, unitDirectoryEntries)
}

func unitDirectoryNamesLimit(ctx context.Context, dir catalogDirectory, remaining *int, perDirectory int) ([]string, error) {
	if *remaining <= 0 {
		return nil, errLimit
	}
	limit := min(perDirectory, *remaining-1)
	*remaining-- // Reserve one slot even if metadata or enumeration fails.
	return catalogNamesLimit(ctx, chargedUnitDirectory{dir, remaining}, limit)
}

// unitWorkBudget is shared across every advanced account and system unit root.
type unitWorkBudget struct{ entries, directories, perDirectory, maxDirectories int }
