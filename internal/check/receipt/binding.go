// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	"github.com/attention-span-ai/tego/internal/buildinfo"
	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// Exact reports whether m names one build: a version and a commit, neither unknown nor marked "+dirty" (a tree no
// commit names). Two builds that are not exact cannot be told apart, so a check never takes one for the other.
func Exact(m MadeBy) bool {
	unknown := func(s string) bool { return s == "" || s == buildinfo.None }
	return !unknown(m.TegoVersion) && !unknown(m.Commit) && !strings.Contains(m.TegoVersion, "+dirty")
}

// ExecutableSHA256 hashes the running Linux image, including after its pathname was replaced.
// It never resolves a workspace executable through PATH.
func ExecutableSHA256() (string, error) { return executableSHA256() }

var executableSHA256 = sync.OnceValues(func() (string, error) {
	f, err := os.Open("/proc/self/exe")
	if err != nil {
		return "", fmt.Errorf("receipt producer image: %w", err)
	}
	defer func() { _ = f.Close() }() // read-only descriptor
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("receipt producer image: %w", err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
})

// payloadDigest uses sorted JSON object keys, preserves array order and number spellings,
// escapes strings as encoding/json.Marshal does, and adds no whitespace or newline.
func payloadDigest(m map[string]any) (string, error) {
	b, ok := m["binding"].(map[string]any)
	if !ok {
		return "", fmt.Errorf("binding: expected an object")
	}
	old, present := b["receipt_sha256"]
	delete(b, "receipt_sha256")
	defer func() {
		if present {
			b["receipt_sha256"] = old
		}
	}()
	data, err := json.Marshal(m)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

func (rc *Receipt) seal() error {
	if rc.Binding == nil || rc.Binding.V == 1 {
		return nil
	}
	data, err := json.Marshal(rc)
	if err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil {
		return err
	}
	rc.Binding.ReceiptSHA256, err = payloadDigest(m)
	return err
}

func lowerSHA256(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// limitsFor is the limits of a run at tier: the three that hold for every run, and record-only for a watched one.
func limitsFor(tier string) []Limit {
	l := []Limit{{Code: LimitLaunchingUser, Why: "the user who started the run can rewrite this record and its receipt together, " +
		"so a pair that matches can still have been made up"}}
	if tier == string(backend.TierObserve) {
		l = append(l, Limit{Code: LimitRecordOnly, Why: "the run was watched, not enforced: the agent itself could rewrite this record"})
	}
	return append(l,
		Limit{Code: LimitTailNotSynced, Why: "lines are not synced to disk during the run, so a crash can lose the last ones and " +
			"nothing counts them"},
		Limit{Code: LimitNoSignature, Why: "no key vouches for this receipt or its record: the binding says which record the " +
			"receipt was computed from, not who made either"})
}

func limitsForBinding(tier string, version int) []Limit {
	l := limitsFor(tier)
	if version >= 2 {
		for i := range l {
			if l[i].Code == LimitNoSignature {
				l[i].Why = "This JSON carries no signature. A CI signature is a detached bundle checked separately."
			}
		}
	}
	return l
}

// bindingOf is the binding of a receipt computed by by over the pass bd bound.
func bindingOf(bd ledger.Bound, by MadeBy, tier string) *Binding {
	b := &Binding{V: BindingVersion, ReceiptBy: by, Limits: limitsForBinding(tier, BindingVersion)}
	if bd.Err != nil {
		b.Error = bd.Err.Error()
		return b
	}
	b.Chain = &BoundChain{Run: bd.Run, Lines: bd.Lines, Head: bd.Head, Ended: bd.Ended, Bytes: bd.Bytes, SHA256: bd.SHA256,
		TornBytes: bd.TornBytes, NewerLines: bd.Newer}
	return b
}
