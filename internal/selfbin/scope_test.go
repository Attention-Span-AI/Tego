// SPDX-License-Identifier: Apache-2.0

package selfbin

import (
	"os"
	"testing"
)

func TestProgramGroupWriteStillRefused(t *testing.T) {
	nodes := map[string]os.FileInfo{
		"/":         chainInfo{chainNode{"/", 0, 0, 0755 | os.ModeDir}},
		"/bin":      chainInfo{chainNode{"/bin", 0, 0, 0755 | os.ModeDir}},
		"/bin/tego": chainInfo{chainNode{"/bin/tego", 1000, 1000, 0775}},
	}
	if trustedChainWithGroups("/bin/tego", 1000, func(p string) (os.FileInfo, error) { return nodes[p], nil }, fixtureGroups("person:x:1000:1000::/:/bin/sh\n", "person:x:1000:person\n", "passwd: files\ngroup: files\n", 1000, 1000), func(string) bool { return true }) {
		t.Fatal("group-writable binary accepted")
	}
}
