// SPDX-License-Identifier: Apache-2.0

package tree

// Has reports whether tgid is one of the session's live processes.
func (s *Session) Has(tgid int32) bool { _, ok := s.members[tgid]; return ok }
