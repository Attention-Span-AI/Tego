// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"runtime/debug"

	"github.com/attention-span-ai/tego/internal/buildinfo"
	"github.com/attention-span-ai/tego/internal/handoff"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

func init() { register(cmdVersion) }

// Version is what tego-control version prints, in this field order: the same version, commit and date as the tego
// of its release (internal/buildinfo), and the SHA-256 of the image this process runs, which is the hash a matched
// tego pins (tego version's control_sha256).
type Version struct {
	Control string `json:"tego-control"`
	Commit  string `json:"commit"`
	Date    string `json:"date"`
	Go      string `json:"go"`
	SHA256  string `json:"sha256"`
}

// selfImage is the image this process runs: /proc/self/exe, which after a handoff is the sealed memfd.
var selfImage = "/proc/self/exe"

// versionOf assembles the version over read and the image at image.
func versionOf(read func() (*debug.BuildInfo, bool), image string) (Version, error) {
	s := buildinfo.Resolve(read)
	v := Version{Control: s.Version, Commit: s.Commit, Date: s.Date, Go: runtime.Version()}
	f, err := os.Open(image)
	if err != nil {
		return v, fmt.Errorf("read own image: %w", err)
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return v, fmt.Errorf("hash own image: %w", err)
	}
	v.SHA256 = hex.EncodeToString(h.Sum(nil))
	return v, nil
}

// cmdVersion is `tego-control version [--json]`.
func cmdVersion() Command {
	return Command{
		Name:    "version",
		Summary: "print the build's version and the SHA-256 tego pins for this binary",
		Usage:   "[--json]",
		Run: func(_ context.Context, args []string, stdout, stderr io.Writer) int {
			fs := flag.NewFlagSet(handoff.Name+" version", flag.ContinueOnError)
			fs.SetOutput(stderr)
			asJSON := fs.Bool("json", false, "one JSON object instead of key=value lines")
			if err := fs.Parse(args); err != nil {
				if err == flag.ErrHelp {
					return identity.ExitOK
				}
				return exits[codeUsage]
			}
			if fs.NArg() != 0 {
				diag(stderr, handoff.Name+" version: takes no arguments", codeUsage, "run "+handoff.Name+" version")
				return exits[codeUsage]
			}
			v, err := versionOf(debug.ReadBuildInfo, selfImage)
			if err != nil {
				diag(stderr, handoff.Name+" version: "+err.Error(), codeIO, "check that /proc is mounted")
				return exits[codeIO]
			}
			if *asJSON {
				b, _ := json.Marshal(v)
				_, err = fmt.Fprintf(stdout, "%s\n", b)
			} else {
				_, err = fmt.Fprintf(stdout, "tego-control=%s\ncommit=%s\ndate=%s\ngo=%s\nsha256=%s\n", v.Control, v.Commit, v.Date, v.Go, v.SHA256)
			}
			if err != nil {
				diag(stderr, handoff.Name+" version: write: "+err.Error(), codeIO, "check the output")
				return exits[codeIO]
			}
			return identity.ExitOK
		},
	}
}
