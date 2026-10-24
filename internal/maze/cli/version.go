// SPDX-License-Identifier: Apache-2.0

package cli

// Build information, set by the release build with -ldflags "-X github.com/attention-span-ai/tego/internal/maze/cli.version=..."
// (.goreleaser.yaml, the maze build). A `go build` or `make maze` leaves the defaults, so a developer's binary
// says it is one.
var (
	version = "dev"
	commit  = ""
)

// versionLine is what `maze --version` prints: the version, and the commit when the build recorded one.
func versionLine() string {
	if commit == "" {
		return "maze " + version
	}
	short := commit
	if len(short) > 12 {
		short = short[:12]
	}
	return "maze " + version + " (" + short + ")"
}
