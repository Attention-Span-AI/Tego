// SPDX-License-Identifier: Apache-2.0

package uprobe

// size is how many binaries are attached.
func (c *cache) size() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.byID)
}
