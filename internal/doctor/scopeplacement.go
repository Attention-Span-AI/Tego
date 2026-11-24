// SPDX-License-Identifier: Apache-2.0

package doctor

import "context"

type scopePlacementKey struct{}

// WithUserScopePlacement records a successful entry rehearsal by the CLI. It proves only that a new launcher can
// enter the user delegation. Probes still run in the caller and verify the delegated tree and cgroup.kill. Runtime
// callers never set this: the real launcher must establish its own placement before it creates a run.
func WithUserScopePlacement(ctx context.Context) context.Context {
	return context.WithValue(ctx, scopePlacementKey{}, true)
}

func userScopePlacement(ctx context.Context) bool {
	proved, _ := ctx.Value(scopePlacementKey{}).(bool)
	return proved
}

type scopeFailureKey struct{}

// WithUserScopeFailure records why the CLI's entry rehearsal failed: tego could not open a user scope from this shell
// (Report.UserScopeFailure). It grants nothing; it only lets the report, and the check tego setup stores, say why.
func WithUserScopeFailure(ctx context.Context, why string) context.Context {
	return context.WithValue(ctx, scopeFailureKey{}, why)
}

// UserScopeFailure is what WithUserScopeFailure recorded in ctx, "" when nothing was.
func UserScopeFailure(ctx context.Context) string {
	why, _ := ctx.Value(scopeFailureKey{}).(string)
	return why
}

// ThroughScopeFact is what doctor, tego setup's check and tego start say of a shell outside the user manager's cgroup
// from which entry into a user scope was just rehearsed and worked: the commands that start a run open one themselves,
// so the shell is no blocker (ADR 0142, amendment of 2026-11-19, round 4).
const ThroughScopeFact = "this shell is outside your user manager's cgroup; tego run, watch and test open a user scope for each run (checked)"

// noteScope sets UserScopeFailure from ctx on a report of a shell that is outside the user manager's cgroup and was
// not shown to enter a user scope.
func (r *Report) noteScope(ctx context.Context) {
	if r.OutsideUserManager && !r.ThroughUserScope {
		r.UserScopeFailure = UserScopeFailure(ctx)
	}
}
