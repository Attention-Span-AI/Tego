// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"

	"github.com/attention-span-ai/tego/pkg/spec/runstatus"
)

// writeRunStatus is called only by the launcher's synchronous lifecycle. The
// background release path deliberately never revises the returned assertion.
func (r *runner) writeRunStatus(removed, deferred bool) error {
	if r.deps.RunStatus == nil || !r.statusScopeAcquired {
		return nil
	}
	s := runstatus.Status{Schema: runstatus.Schema, Run: string(r.id), Scope: r.cg.Path, Removed: removed, Deferred: deferred}
	if r.cg.ID != 0 {
		s.CgroupID = strconv.FormatUint(r.cg.ID, 10)
	}
	if err := s.Validate(); err != nil {
		return err
	}
	return r.deps.RunStatus(s)
}

// scopeConfirmedAbsent requires identity from this run and the post-removal
// lookup. Successful Remove alone does not establish that the path is absent.
func (r *runner) scopeConfirmedAbsent() bool {
	if r.cg.ID == 0 || r.cg.Path == "" || !filepath.IsAbs(r.cg.Path) {
		return false
	}
	_, err := os.Lstat(r.cg.Path)
	return errors.Is(err, os.ErrNotExist)
}
