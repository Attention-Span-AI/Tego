// SPDX-License-Identifier: Apache-2.0

package record_test

import (
	"bytes"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestVocabularyListsDoNotRedefineV1 exercises the exported listing variables as
// an external consumer can: neither editing their elements nor replacing the
// slices may extend or shrink the codec's frozen vocabulary.
func TestVocabularyListsDoNotRedefineV1(t *testing.T) {
	t.Run("kinds", func(t *testing.T) {
		checkListing(t, &record.Kinds, record.KindRunStart, record.Kind.Valid)
	})
	t.Run("verdicts", func(t *testing.T) {
		checkListing(t, &record.Verdicts, record.VerdictAllow, record.Verdict.Valid)
	})
	t.Run("authorities", func(t *testing.T) {
		checkListing(t, &record.Authorities, record.AuthorityRule, record.Authority.Valid)
	})
	t.Run("sources", func(t *testing.T) {
		checkListing(t, &record.Sources, record.SourceKernel, record.Source.Valid)
	})
	t.Run("reasons", func(t *testing.T) {
		checkListing(t, &record.Reasons, record.ReasonWriteOutsideContract, record.Reason.Valid)
	})
	t.Run("run end reasons", func(t *testing.T) {
		checkListing(t, &record.RunEndReasons, record.RunEndExit, record.IsRunEndReason)
	})
	t.Run("confidences", func(t *testing.T) {
		checkListing(t, &record.Confidences, record.ConfidenceExact, func(s string) bool {
			return (&record.Attribution{Confidence: s, Method: record.MethodNone}).Valid()
		})
	})
	t.Run("methods", func(t *testing.T) {
		checkListing(t, &record.Methods, record.MethodToolID, func(s string) bool {
			return (&record.Attribution{Confidence: record.ConfidenceExact, Method: s}).Valid()
		})
	})
}

func checkListing[T ~string](t *testing.T, listing *[]T, known T, valid func(T) bool) {
	t.Helper()
	original := *listing
	values := slices.Clone(original)
	t.Cleanup(func() {
		copy(original, values)
		*listing = original
	})
	foreign := T("foreign-v1-value")
	(*listing)[0] = foreign
	check := func() {
		t.Helper()
		if valid(foreign) {
			t.Error("editing the listing admitted a foreign v1 value")
		}
		if !valid(known) {
			t.Errorf("editing the listing rejected defined value %q", known)
		}
		if valid(T("")) {
			t.Error("empty vocabulary value is valid")
		}
	}
	check()
	*listing = []T{foreign}
	check()
}

func TestMarshalLineKeepsFrozenKindAfterListingEdit(t *testing.T) {
	original := record.Kinds
	t.Cleanup(func() { record.Kinds = original })
	foreign := record.Kind("foreign-v1-kind")
	record.Kinds = []record.Kind{foreign}
	e := &record.Event{V: record.Version, TS: time.Unix(1, 0), Run: "r-test", Agent: "agent",
		Kind: foreign, Source: record.SourceSupervisor}
	if _, err := e.MarshalLine(); !errors.Is(err, record.ErrInvalidEvent) {
		t.Errorf("foreign kind MarshalLine error = %v, want ErrInvalidEvent", err)
	}
	e.Kind = record.KindRunStart
	if _, err := e.MarshalLine(); err != nil {
		t.Errorf("defined kind MarshalLine after listing edit: %v", err)
	}
}

func TestDigestPlaceholderDoesNotRedefineV1(t *testing.T) {
	e := &record.Event{V: record.Version, TS: time.Unix(1, 0), Run: "r-test", Agent: "agent",
		Kind: record.KindRunStart, Source: record.SourceSupervisor}
	baseline, err := e.MarshalLine()
	if err != nil {
		t.Fatal(err)
	}
	for _, placeholder := range []string{"", "0", strings.Repeat("f", record.IDLen)} {
		t.Run(placeholder, func(t *testing.T) {
			original := record.ZeroID
			t.Cleanup(func() { record.ZeroID = original })
			record.ZeroID = placeholder
			if _, err := record.VerifyLine(baseline); err != nil {
				t.Errorf("placeholder assignment invalidated a frozen-v1 line: %v", err)
			}
			got, err := e.MarshalLine()
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, baseline) {
				t.Errorf("placeholder assignment changed canonical bytes\n got %s\nwant %s", got, baseline)
			}
		})
	}
}
