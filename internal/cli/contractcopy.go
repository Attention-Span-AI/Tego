// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// contractCopy is what a run leaves in its directory as contract.yaml: the canonical bytes of the
// merged contract, whose sha256 is the run's contract_hash (agent-contract.md R13, P0-DESIGN §3.3
// "copy as compiled (hash = contract_hash)"). The file the user wrote is not that: its comments and
// layout never hashed, and an `extends:` in it names a profile that may change or vanish after the
// run, so a copy of those bytes could neither be checked against contract_hash nor recompiled into
// the table the run enforced.
func contractCopy(rt *agent.RuleTable) ([]byte, error) {
	if rt == nil || rt.Contract == nil {
		return nil, errors.New("no compiled contract")
	}
	return rt.Contract.Canonical()
}

// sealedProfiles resolves every `extends:` name to an empty profile. It is how a canonical
// contract.yaml is reloaded: Canonical keeps the extends name (it is part of what contract_hash
// covers) but the entries the profile contributed are already merged into the copy, so resolving
// the name again would either merge them a second time or fail because the profile has changed
// since the run. Merging onto an empty profile changes nothing (agent merge: every list is the
// contract's, every scalar the contract's when written), so the reload reproduces the run's
// contract and its hash.
type sealedProfiles struct{}

// Resolve implements agent.ProfileSource.
func (sealedProfiles) Resolve(name string) (string, []byte, error) {
	return "(merged into contract.yaml: " + name + ")", []byte("{}\n"), nil
}

// runOrigin is what drift needs from a run's run_start to recompile its contract as the run did:
// the hash the run recorded, the directory relative entries resolved against, and the command the run was
// given on its command line, which that run's table granted beside the contract (agent.WithRunCommand).
type runOrigin struct {
	contractHash string
	cwd          string
	// runCommand is run_start.run_command_grant, the absolute path the run granted; a ledger written before
	// that field existed falls back to run_start.command[0], which compiles to the same grant, or to none
	// when a declared entry covers it (the contract's own command included) (agent-contract.md R8).
	runCommand string
}

// readRunOrigin reads run_start, the first line of the run's ledger. A ledger with no run_start yet
// yields a zero origin, not an error: drift still reports what the ledger holds.
func readRunOrigin(r *ledger.Reader) (runOrigin, error) {
	for e, err := range r.Iter() {
		if err != nil {
			return runOrigin{}, err
		}
		if e.Kind != record.KindRunStart {
			return runOrigin{}, nil
		}
		var p record.RunStartPayload
		if err := e.DecodePayload(&p); err != nil {
			return runOrigin{}, fmt.Errorf("decode run_start: %w", err)
		}
		o := runOrigin{contractHash: p.ContractHash, cwd: p.Cwd, runCommand: p.RunCommandGrant}
		// A ledger at or past MinorRunCommandGrant omits run_command_grant on purpose: the run execs the
		// contract's own command, or a declared entry covered it, and nothing is granted. Only an older one,
		// whose writer did not record the grant, falls back to the command it ran.
		if o.runCommand == "" && p.RecordMinor < record.MinorRunCommandGrant && len(p.Command) > 0 {
			o.runCommand = p.Command[0]
		}
		return o, nil
	}
	return runOrigin{}, nil
}

// loadContractCopy loads a run directory's contract.yaml. A copy whose sha256 is the run's
// contract_hash is the canonical one contractCopy wrote, self-contained, and loads with its extends
// sealed. Any other copy — written by a binary from before the copy was canonical, or edited since —
// is loaded as a contract file with today's profiles, which is the best that can be done with it;
// drift's hash comparison then says whether it still describes what the run enforced (R16).
func loadContractCopy(path, recordedHash string, profiles agent.ProfileSource) (*agent.Contract, []agent.Diagnostic, error) {
	data, err := readCopy(path)
	if err != nil {
		return nil, nil, err
	}
	sum := sha256.Sum256(data)
	if recordedHash != "" && hex.EncodeToString(sum[:]) == recordedHash {
		profiles = sealedSources()
	}
	return agent.LoadBytes(path, data, profiles)
}

// readCopy reads contract.yaml under the same size cap the loader applies to any contract, so a
// run directory's copy is never a way past it (agent-contract.md E25). Tego wrote the copy as a
// regular file, so anything else there (a FIFO would block drift forever) is refused.
func readCopy(path string) ([]byte, error) {
	f, err := os.OpenFile(filepath.Clean(path), agent.OpenFlags|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	if st, err := f.Stat(); err != nil {
		return nil, err
	} else if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("%s: %w", path, agent.ErrNotAFile)
	}
	data, err := io.ReadAll(io.LimitReader(f, agent.MaxContractSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > agent.MaxContractSize {
		return nil, fmt.Errorf("%s: %w", path, agent.ErrTooLarge)
	}
	return data, nil
}
