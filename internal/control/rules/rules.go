// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/attention-span-ai/tego/internal/check/livestatus"
	"github.com/attention-span-ai/tego/internal/rulefile"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// Via is what the journal records as the writer of every change the service makes.
const Via = "dashboard"

// Service makes and changes rules for the runs under Ledger.
type Service struct {
	Ledger string
	// Home is the invoking user's home, for ~/ entries.
	Home string
	// Now is the clock the changed line's date is read from; nil is time.Now.
	Now func() time.Time
	// Machine is the machine config every compile runs against (check.go); nil refuses every write.
	Machine *config.Machine
	// Anchor is the chain anchor the runs anchor in, which a write entry may not cover (R10); "" names none.
	Anchor string
	// PATH is the PATH compiles find programs on before the run's exec directories; "" is this process's.
	PATH string
	// Refuse are more directories no contract may be under (rulefile.Guard.Refuse): the machine's ledger root and
	// tego's home under the machine's home, beside the served ledger root and ~/.tego DefaultGuard refuses.
	Refuse []string
	// Compile, when set, replaces the compiler (tests): nil when text compiles in cc.
	Compile func(ctx context.Context, cc CheckContext, text []byte) error
	// Check is Compile in its older form, the contract's path and the run's working directory only, which the web
	// package's tests still set; Compile wins when both are set.
	Check func(contract, cwd string, text []byte) error
	// Writer is the authority writes go through; nil is internal/rulefile in this process (localWriter).
	Writer Writer
	// AckKey is the key every plan's acknowledgement is an HMAC under (ack.go); nil makes 32 random bytes on first
	// use, kept for the service's life.
	AckKey  []byte
	ackOnce sync.Once

	// Test seams: a run directory's liveness, a running run's held reads, a live block's placement, and a run's live
	// facts (runact.StartFacts); a live block's removal and a run's live block keys now (lift.go); the clock a
	// listing of the ledger root is judged settled by (contracts.go, starts), nil for time.Now.
	live      func(dir string) bool
	readsHeld func(run string) (bool, string)
	block     func(ctx context.Context, run, kind, value string) error
	facts     func(run string) livestatus.Facts
	unblock   func(ctx context.Context, run, kind, value string) error
	overlay   func(run string) []string
	clock     func() time.Time

	mu      sync.Mutex
	cache   map[string]start // run_start by run id (contracts.go)
	listing *listing         // the ledger root's last listing, kept while the root's key stays the same (contracts.go)
	feed    *feedCache       // the last rule-change feed read (feed.go)

	readMu sync.Mutex
	reads  map[string]readMemo // each contract's guarded-read view by path, while the file looks the same (contracts.go)
}

// ErrNoLine is ActOn's error for a run or line that does not exist or names no contract file.
var ErrNoLine = errors.New("no rule can be made from this line")

// found reads line seq of run and the contract it ran through the service's guard, and the context to compile the
// contract in: that run's own. With a hint it reads run_start and the hinted line only (rulefile.FindAtIn, which
// checks the hint and scans when it does not hold).
func (s *Service) found(run string, seq uint64, hint *rulefile.Hint) (*rulefile.Found, CheckContext, error) {
	if !runID(run) {
		return nil, CheckContext{}, fmt.Errorf("%w: %q is not a run id", ErrNoLine, run)
	}
	dir := filepath.Join(s.Ledger, run)
	var f *rulefile.Found
	var err error
	if hint != nil {
		f, err = rulefile.FindAtIn(dir, seq, *hint, s.guard())
	} else {
		f, err = rulefile.FindIn(dir, seq, s.guard())
	}
	if err != nil {
		return nil, CheckContext{}, fmt.Errorf("%w: %v", ErrNoLine, err)
	}
	cc := CheckContext{Contract: f.Contract, Cwd: f.Cwd}
	if st, err := readStart(dir); err == nil {
		cc.Tier, cc.RunCommandGrant = st.Tier, st.Grant
	}
	cc.runDir = dir
	return f, cc, nil
}

func (s *Service) date() string {
	now := time.Now
	if s.Now != nil {
		now = s.Now
	}
	return now().Format(time.DateOnly)
}

// runID is the run ids the dashboard reads (ledgerview's rule): r-, then lower-case letters, digits and dashes, so
// the id is one directory name under the ledger root.
func runID(id string) bool {
	if !strings.HasPrefix(id, "r-") || len(id) > 128 {
		return false
	}
	for _, c := range id {
		if c != '-' && (c < '0' || c > '9') && (c < 'a' || c > 'z') {
			return false
		}
	}
	return true
}
