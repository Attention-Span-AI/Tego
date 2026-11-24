// SPDX-License-Identifier: Apache-2.0

package doctor

// pendingWSLProofs names the WSL containment rows this build does not count as proven: all four while held is true,
// none otherwise. held is peer.WSLGateHolds on this machine (checks.wslHeld): any one of WSL's marks holds (a hold
// needs one; ADR 0100, amended 2026-11-19, round 5: detection is asymmetric) and the rule's relaxation on WSL, which
// needs two marks and the build's switch, does not apply. Readiness and the gate are one switch (round 4): an ordinary
// build on WSL withholds both until the commit that turns the rule on; a test build with its switch on
// (wslgate_testhook.go) proves the rows in a guest with both lifted, on a machine that shows two marks. A
// distribution with interop off shows its kernel release alone: readiness stays held there in every build.
func pendingWSLProofs(held bool) []string {
	if !held {
		return nil
	}
	return []string{"Windows launcher", "home-folder alias", "Windows drive", "GUI and audio sockets"}
}
