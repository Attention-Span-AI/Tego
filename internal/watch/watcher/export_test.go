// SPDX-License-Identifier: Apache-2.0

package watcher

// Processes is how many processes, agents and descendants, are followed now.
func (w *Watcher) Processes() int { return w.tr.PIDs() }

// Sessions is how many agent sessions are followed now.
func (w *Watcher) Sessions() int { return len(w.tr.Sessions()) }
