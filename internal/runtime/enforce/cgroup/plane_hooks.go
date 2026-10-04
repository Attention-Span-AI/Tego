// SPDX-License-Identifier: Apache-2.0

package cgroup

// planeFillTestHook is the fill's test seam: nil in a product build, set from the environment by a build with
// -tags tegotesthooks (plane_testhook.go). It runs between the plan and the fill, with the descriptor numbers the
// plan holds, so a root test can reuse one of them in the real binary (enforce-plane §7: the fill disagreeing with
// fdinfo fails Prepare before arming).
var planeFillTestHook func(fds []int)
