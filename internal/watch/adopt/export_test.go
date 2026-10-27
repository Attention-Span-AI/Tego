// SPDX-License-Identifier: Apache-2.0

package adopt

// Members is the tree an adoption of root would move now: root and its descendants in root's cgroup, parents first,
// and the ones it would not move. It moves nothing.
func Members(p Proc, root Process, extra []Identity) ([]Process, []Skip, error) {
	return walk(p, root.Identity, root.Cgroup, "", extra)
}
