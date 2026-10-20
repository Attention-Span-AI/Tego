// SPDX-License-Identifier: Apache-2.0

package agent

import "path/filepath"

// evalLander is a test's Lander for trees with no "..", no dangling link and nothing missing beneath a link, where
// filepath.EvalSymlinks lands a path as the kernel's walk does. compile --test passes the run's own walk
// (internal/runtime/supervisor.Land), whose tests hold it to the kernel; this package may not import it (depguard).
func evalLander(p string, how Lookup) (string, error) {
	if how == LookupFollow || how == LookupCreate {
		if r, err := filepath.EvalSymlinks(p); err == nil {
			return r, nil
		}
	}
	d, err := filepath.EvalSymlinks(filepath.Dir(p))
	if err != nil {
		return "", err
	}
	return filepath.Join(d, filepath.Base(p)), nil
}

// evalUnixLander is evalLander for a connect's or a datagram's unix name, followed as connect(2) follows it; a name
// it cannot land names nothing (UnixWalkAbsent). compile --test passes supervisor.LandUnix.
func evalUnixLander(p string) (UnixLanding, error) {
	at, err := evalLander(p, LookupFollow)
	if err != nil {
		return UnixLanding{Walk: UnixWalkAbsent}, nil
	}
	return UnixLanding{At: at}, nil
}

// evalLanders are a test's Landers over evalLander and evalUnixLander.
var evalLanders = Landers{Path: evalLander, Unix: evalUnixLander}
