// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"

	ebpfbindings "github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/internal/buildinfo"
	"github.com/attention-span-ai/tego/internal/handoff"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// contractSchema is the agent.yaml version this binary reads (spec/agent/v0).
const contractSchema = 0

// none is the rendering of a field this build has no value for.
const none = buildinfo.None

// BuildInfo is what `tego version` prints (R30, VERSIONING.md §1), in this field order.
type BuildInfo struct {
	Tego           string   `json:"tego"`
	Commit         string   `json:"commit"`
	Date           string   `json:"date"`
	Go             string   `json:"go"`
	ContractSchema int      `json:"contract_schema"`
	RecordV        int      `json:"record_v"`
	RecordReaders  []int    `json:"record_readers"`
	BPFHash        string   `json:"bpf_hash"`
	Parsers        []string `json:"parsers"`
	// ControlSHA256 is the SHA-256 of the tego-control this build hands off to (ADR 0100 (1b)), or "none" for an
	// unpinned build; tego-control version prints the same hash of itself.
	ControlSHA256 string `json:"control_sha256"`
}

// buildInfo assembles the version from the ldflags values, falling back to debug.ReadBuildInfo (read is
// injectable for tests), as internal/buildinfo resolves it for both binaries.
func buildInfo(read func() (*debug.BuildInfo, bool)) BuildInfo {
	s := buildinfo.Resolve(read)
	return BuildInfo{
		Tego:           s.Version,
		Commit:         s.Commit,
		Date:           s.Date,
		Go:             runtime.Version(),
		ContractSchema: contractSchema,
		RecordV:        record.Version,
		RecordReaders:  []int{record.Version},
		BPFHash:        buildBPFHash(),
		// R30/VERSIONING.md §1: the parsers this build links, read from the one list that also
		// builds the forwarder's dispatcher. It was hard-coded empty, so `version` said
		// "parsers=none" while the binary was deriving with anthropic-2026-09-1, and every
		// run_start stamped parsers:{} — the one question that field exists to answer.
		Parsers:       parserNames(),
		ControlSHA256: controlPin(),
	}
}

// controlPin is the pinned hash of tego-control, or "none".
func controlPin() string {
	if p := handoff.Pin(); p != "" {
		return p
	}
	return none
}

// buildBPFHash is R30's bpf_hash: the hash over the BPF objects this binary embeds, the name of the pin
// directory and build lock its tier-2 runs share (enforce-cgroup-observe.md §3), or "none" for a build
// without them. It was hard-coded "none", so a tegobpf build reported the same as an untagged one and
// a bug report could not tell which programs a tier-2 run had loaded.
func buildBPFHash() string {
	h, err := embeddedBPFHash()
	if err != nil {
		return none
	}
	return h
}

// embeddedBPFHash is internal/bpf's Hash, a variable so a test can describe the other build.
var embeddedBPFHash = ebpfbindings.Hash

// WriteText prints one key=value line per field in R30's order.
func (b BuildInfo) WriteText(w io.Writer) error {
	readers := make([]string, len(b.RecordReaders))
	for i, r := range b.RecordReaders {
		readers[i] = strconv.Itoa(r)
	}
	parsers := strings.Join(b.Parsers, ",")
	if parsers == "" {
		parsers = none
	}
	_, err := fmt.Fprintf(w, "tego=%s\ncommit=%s\ndate=%s\ngo=%s\ncontract_schema=%d\nrecord_v=%d\nrecord_readers=%s\nbpf_hash=%s\nparsers=%s\ncontrol_sha256=%s\n",
		b.Tego, b.Commit, b.Date, b.Go, b.ContractSchema, b.RecordV, strings.Join(readers, ","), b.BPFHash, parsers, b.ControlSHA256)
	if err != nil {
		return fmt.Errorf("write version: %w", err)
	}
	return nil
}

// Line renders the same fields on one line, the banner of doctor and of every bug report.
func (b BuildInfo) Line() string {
	return fmt.Sprintf("tego=%s commit=%s date=%s go=%s contract_schema=%d record_v=%d",
		b.Tego, b.Commit, b.Date, b.Go, b.ContractSchema, b.RecordV)
}

func init() { register(cmdVersion) }

// cmdVersion is `tego version [--json]` (R30).
func cmdVersion() Command {
	var asJSON bool
	return Command{
		Name:    "version",
		Summary: "print the build's versions (first line of every bug report)",
		Usage:   "[--json]",
		Flags: func(fs *flag.FlagSet) {
			fs.BoolVar(&asJSON, "json", false, "one JSON object instead of key=value lines")
		},
		Run: func(_ context.Context, fs *flag.FlagSet, stdout, stderr io.Writer) int {
			if fs.NArg() != 0 {
				message(stderr, "", 0, 0, "tego version: takes no arguments", codeUsage)
				return identity.ExitUsage // R25: usage error
			}
			b := buildInfo(debug.ReadBuildInfo)
			var err error
			if asJSON {
				err = writeJSON(stdout, b)
			} else {
				err = b.WriteText(stdout)
			}
			if err != nil {
				message(stderr, "", 0, 0, "tego version: "+err.Error(), codeIO)
				return identity.ExitError // R25: Tego's own error
			}
			return identity.ExitOK
		},
	}
}

// writeJSON prints v as exactly one JSON object line (E22).
func writeJSON(w io.Writer, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("encode json: %w", err)
	}
	if _, err := fmt.Fprintf(w, "%s\n", data); err != nil {
		return fmt.Errorf("write json: %w", err)
	}
	return nil
}
