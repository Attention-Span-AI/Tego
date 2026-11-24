// SPDX-License-Identifier: Apache-2.0

package scan

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strconv"
)

// collectAdvancedUnits shares byte, file and enumeration allowances across all
// local accounts. A remainder source survives when result capacity stops reads.
func collectAdvancedUnits(ctx context.Context, accounts []localAccount, userRoots, systemRoots []string, budget *contentBudget) (unitSnapshot, unitSnapshot) {
	return collectAdvancedUnitsOwned(ctx, accounts, userRoots, systemRoots, budget, 0)
}

// machineUID is explicit so synthetic trees exercise machine ownership checks
// without granting a unit test root. Production always supplies uid zero.
func collectAdvancedUnitsOwned(ctx context.Context, accounts []localAccount, userRoots, systemRoots []string, budget *contentBudget, machineUID uint32) (users, system unitSnapshot) {
	budget.unitCache = newUnitReadCache(append(append([]string{}, userRoots...), systemRoots...), machineUID)
	defer func() {
		budget.unitCache.finish(&users, &system)
		budget.unitCache = nil
	}()
	sourceBytes, itemBytes := 0, 0
	seenSources := map[string]bool{}
	add := func(dst *unitSnapshot, got unitSnapshot, uid *uint32, isSystem bool) bool {
		for _, p := range got.Sources {
			key := p.Path + "\x00" + p.State + "\x00" + p.Reason
			if seenSources[key] {
				continue
			}
			seenSources[key] = true
			b, _ := json.Marshal(p)
			if len(users.Sources)+len(system.Sources) >= 1700 || sourceBytes+len(b) > 350<<10 {
				dst.Sources = append(dst.Sources, projectSource("", errLimit))
				return false
			}
			sourceBytes += len(b)
			dst.Sources = append(dst.Sources, p)
		}
		for _, p := range got.Items {
			p.UID, p.System = uid, isSystem
			b, _ := json.Marshal(p)
			if len(users.Items)+len(system.Items) >= 512 || itemBytes+len(b) > 450<<10 {
				dst.Sources = append(dst.Sources, projectSource("", errLimit))
				return false
			}
			itemBytes += len(b)
			dst.Items = append(dst.Items, p)
		}
		return true
	}
	// System configuration is read once with root ownership checks.
	if !add(&system, collectUnits(ctx, systemRoots, machineUID, budget), nil, true) {
		return users, system
	}
	seen := map[string]bool{}
	for _, a := range accounts {
		key := a.Home + ":" + strconv.FormatUint(uint64(a.UID), 10)
		if seen[key] {
			continue
		}
		seen[key] = true
		paths := []string{filepath.Join(a.Home, ".config/systemd/user")}
		if len(userRoots) > 0 {
			paths = append(paths, userRoots[0])
		}
		paths = append(paths, filepath.Join(a.Home, ".local/share/systemd/user"))
		if len(userRoots) > 1 {
			paths = append(paths, userRoots[1])
		}
		uid := a.UID
		if !add(&users, collectUnits(ctx, paths, a.UID, budget), &uid, false) {
			break
		}
		if ctx.Err() != nil || budget.remaining <= 0 || budget.files >= budget.maxFiles() {
			users.Sources = append(users.Sources, projectSource("", errLimit))
			break
		}
	}
	return users, system
}
