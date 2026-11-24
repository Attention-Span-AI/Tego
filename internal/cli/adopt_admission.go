// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// reloadConfiguration supplies strict fresh discovery to the named configuration
// check during preparation and after the migration lock wait.
func (a *preparedAdoption) reloadConfiguration() (*config.Machine, error) {
	m, diagnostics, err := loadMachine(config.TrustAbort)
	if err != nil {
		return nil, fmt.Errorf("current machine configuration could not be loaded: %w (%v)", err, diagnostics)
	}
	return m, nil
}

func (a *preparedAdoption) recheckOwnerConfiguration(m *config.Machine) (*config.Machine, error) {
	if a.locationCheck != nil {
		if err := a.locationCheck(m); err != nil {
			return nil, err
		}
	}
	if a.boundary {
		home, err := adoptHomeOf(a.owner)
		if err != nil || home != a.home {
			return nil, fmt.Errorf("uid %d's passwd home changed or is unavailable before adoption; prepare again", a.owner)
		}
		if a.homeLocation.identity != nil {
			location, err := resolveAdoptionHome(a.home)
			old, statErr := os.Stat(a.homeLocation.existing)
			if err != nil || statErr != nil || location.resolved != a.homeLocation.resolved || !os.SameFile(a.homeLocation.identity, old) {
				return nil, fmt.Errorf("uid %d's home placement changed before adoption; prepare again", a.owner)
			}
		}
		if a.homeNotOwners {
			var st unix.Stat_t
			if err := unix.Stat(a.home, &st); err != nil {
				return nil, fmt.Errorf("owner home unavailable before adoption: %w", err)
			}
			writable, err := homeWritableBy(st, a.owner)
			if err != nil || writable {
				return nil, fmt.Errorf("owner home write admission changed before adoption; prepare again")
			}
		}
		if a.stale() {
			return nil, fmt.Errorf("uid %d's home or own tego records changed before adoption; prepare again", a.owner)
		}
	}
	return m, nil
}
