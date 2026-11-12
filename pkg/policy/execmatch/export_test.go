// SPDX-License-Identifier: Apache-2.0

package execmatch

// WithoutMulticall is ix as it was before the multicall applet readings (multicall.go): the same rows and patterns,
// no applet read by a multicall image's names. The differential tests hold the two to the same allow side.
func WithoutMulticall(ix *Index) *Index {
	c := *ix
	c.mc, c.mcNames, c.mcApplets, c.mcLongest = nil, nil, nil, 0
	return &c
}

// IsMulticallImage reports whether ix reads a walked file of links links named image for its multicall applets.
func IsMulticallImage(ix *Index, links uint64, image string) bool {
	return ix.multicallImage(links, image)
}
