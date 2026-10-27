// SPDX-License-Identifier: Apache-2.0

package rulefile

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/attention-span-ai/tego/internal/check/rule"
	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// Found is a run's event and the contract file it ran under.
type Found struct {
	Event    *record.Event
	Run      string
	Contract string // the contract file's absolute path, from run_start.contract_source
	Text     []byte // the contract file's bytes now, read through the guards
	Cwd      string // the run's working directory, which relative entries are read from
	// Tier and RunCommandGrant are run_start's tier and run_command_grant: what the change is compiled for
	// (internal/nextrun), as the dashboard's rule service compiles it.
	Tier, RunCommandGrant string
	Mode                  os.FileMode
	// Guard is where the contract may not be and which ledger root journals a write (the one FindIn was given).
	Guard Guard
	// Via and Summary are what Write records in the journal: the writer ("cli", "dashboard"; "" is read from the
	// program's name) and the change in words.
	Via, Summary string
}

// ErrNoContract is FindIn's error for a run whose record names no contract file: a tego watch run, a contract tego
// generated, or a record from before contract_source. `tego rule` follows it with the way to get a contract.
var ErrNoContract = errors.New("the run's record names no contract file (a tego watch run, a contract tego generated, " +
	"or a record from before contract_source): there is no file to change")

// FindIn reads the run record in dir up to the line seq, and the contract file the run names through the guards of
// Read, with the guard given: `tego rule`, which may be given a run directory by its path, passes the
// machine's ledger root.
func FindIn(dir string, seq uint64, g Guard) (*Found, error) {
	r, err := ledger.OpenReader(dir)
	if err != nil {
		return nil, err
	}
	defer func() { _ = r.Close() }()
	r.SkipNewerVersions()
	f := &Found{Guard: g}
	for e, err := range r.Iter() {
		if err != nil {
			return nil, err
		}
		if e.Kind == record.KindRunStart && f.Contract == "" {
			var p record.RunStartPayload
			if err := e.DecodePayload(&p); err != nil {
				return nil, fmt.Errorf("run_start: %w", err)
			}
			f.Run, f.Cwd, f.Tier, f.RunCommandGrant = e.Run, p.Cwd, p.Tier, p.RunCommandGrant
			if p.ContractSource != nil {
				f.Contract = p.ContractSource.Path
			}
		}
		if e.Seq == seq {
			f.Event = e
			break
		}
	}
	if f.Event == nil {
		return nil, fmt.Errorf("the run has no line #%d", seq)
	}
	if f.Contract == "" {
		return nil, ErrNoContract
	}
	file, err := Read(f.Contract, g)
	if err != nil {
		return nil, err
	}
	f.Text, f.Mode = file.Text, file.Mode
	return f, nil
}

// Request is the rule.Request for f.
func (f *Found) Request(a rule.Action, folder bool, home, date string, check func([]byte) error) rule.Request {
	return rule.Request{Contract: f.Text, ContractPath: f.Contract, Cwd: f.Cwd, Home: home, Event: f.Event, Action: a, Folder: folder,
		Date: date, Check: check}
}

// Base is the sha256 of the text FindIn read: the base a preview shows and a confirm carries back.
func (f *Found) Base() string { return Sum(f.Text) }

// Write replaces f.Contract with text through Replace: the file must still hold f.Text (else nothing is written), the
// old bytes go to <file>.bak, the new file (same mode) is renamed over the old one, so a reader sees one or the
// other, and the change is journaled under f.Guard's ledger root with f.Via, f.Summary and the run's line.
func (f *Found) Write(text []byte) (bak string, err error) {
	e, err := f.WriteChange(context.Background(), text, Change{Via: f.Via, Summary: f.Summary})
	if e != nil {
		bak = e.Bak
	}
	return bak, err
}

// WriteChange is Write with the whole Change to journal; its Run and Line are f's when unset. The journal entry comes
// back, also with ErrJournal (the file was written; the entry says where the old text is).
func (f *Found) WriteChange(ctx context.Context, text []byte, c Change) (*Entry, error) {
	if c.Run == "" && c.Line == 0 && f.Event != nil {
		c.Run, c.Line = f.Run, f.Event.Seq
	}
	e, err := Replace(ctx, f.Guard, f.Contract, f.Base(), text, c)
	if errors.Is(err, ErrStale) {
		return nil, fmt.Errorf("%s changed since it was read: nothing was written; try again: %w", f.Contract, err)
	}
	return e, err
}
