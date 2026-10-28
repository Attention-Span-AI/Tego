// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"context"

	"github.com/attention-span-ai/tego/internal/rulefile"
)

// Writer is the authority the rule service writes contracts through: a guarded read, a guarded replace with a base
// hash and a journal line, a revert from the journal, and the journal line of what "also apply now" did. Today it is
// localWriter, internal/rulefile in this process, the code `tego rule` writes through. A helper child granted the
// contracts directory alone could sit behind this same seam.
type Writer interface {
	// Read reads the contract at path through every guard and writes nothing.
	Read(path string) (*rulefile.File, error)
	// Replace writes text over the contract at path when it still holds base, and journals c.
	Replace(ctx context.Context, path, base string, text []byte, c rulefile.Change) (*rulefile.Entry, error)
	// Revert gives the contract of the journal's change id its old text back, while it holds that change's text.
	Revert(ctx context.Context, id string, o rulefile.RevertOptions) (*rulefile.Entry, error)
	// AppendLive journals the live blocks placed for the change of after it was written.
	AppendLive(ctx context.Context, of string, live []rulefile.Live) error
}

// Creator is the Writer that also writes a new contract where there is no file (rulefile.Create): never over a file,
// journaled as op create. A Writer that is not a Creator refuses "Set up a new agent" (new.go).
type Creator interface {
	Create(ctx context.Context, path string, text []byte, c rulefile.Change) (*rulefile.Entry, error)
}

// localWriter is Writer through internal/rulefile under one guard.
type localWriter struct{ g rulefile.Guard }

func (w localWriter) Read(path string) (*rulefile.File, error) { return rulefile.Read(path, w.g) }

func (w localWriter) Replace(ctx context.Context, path, base string, text []byte, c rulefile.Change) (*rulefile.Entry, error) {
	return rulefile.Replace(ctx, w.g, path, base, text, c)
}

func (w localWriter) Revert(ctx context.Context, id string, o rulefile.RevertOptions) (*rulefile.Entry, error) {
	return rulefile.Revert(ctx, w.g, id, o)
}

func (w localWriter) AppendLive(ctx context.Context, of string, live []rulefile.Live) error {
	return rulefile.AppendLive(ctx, w.g.LedgerRoot, of, live)
}

func (w localWriter) Create(ctx context.Context, path string, text []byte, c rulefile.Change) (*rulefile.Entry, error) {
	return rulefile.Create(ctx, w.g, path, text, c)
}

// writer is Service.Writer, else the local writer under the service's guard.
func (s *Service) writer() Writer {
	if s.Writer != nil {
		return s.Writer
	}
	return localWriter{s.guard()}
}
