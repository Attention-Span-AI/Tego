// SPDX-License-Identifier: Apache-2.0

package runstatus

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// Schema is the status schema this version reads and writes.
const Schema = "tego.run-status/1"

// MaxBytes bounds one complete encoded status, including whitespace.
const MaxBytes = 4 << 10

// Status names one runtime-owned scope and whether its removal was confirmed.
// Unknown scope and ID are empty strings. Deferred means cleanup was handed off
// before return, and is never changed to a later successful background result.
type Status struct {
	Schema   string `json:"schema"`
	Run      string `json:"run"`
	Scope    string `json:"scope"`
	CgroupID string `json:"cgroup_id"`
	Removed  bool   `json:"removed"`
	Deferred bool   `json:"deferred"`
}

// Validate checks every semantic field and refuses contradictory removal claims.
func (s Status) Validate() error {
	if s.Schema != Schema {
		return fmt.Errorf("run status: unsupported schema %q", s.Schema)
	}
	if !identity.RunID(s.Run).Valid() {
		return errors.New("run status: invalid run id")
	}
	if s.Scope != "" && (!filepath.IsAbs(s.Scope) || filepath.Clean(s.Scope) != s.Scope || s.Scope == "/" || strings.ContainsAny(s.Scope, "\x00\r\n")) {
		return errors.New("run status: scope must be an absolute clean path, or empty when unknown")
	}
	if s.CgroupID != "" {
		id, err := strconv.ParseUint(s.CgroupID, 10, 64)
		if err != nil || id == 0 || strconv.FormatUint(id, 10) != s.CgroupID {
			return errors.New("run status: cgroup_id must be a positive decimal string, or empty when unknown")
		}
	}
	if s.Removed && (s.Scope == "" || s.CgroupID == "" || s.Deferred) {
		return errors.New("run status: removed requires known scope and cgroup_id and no deferred cleanup")
	}
	return nil
}

// Decode reads exactly one bounded object, requiring all fields and refusing
// duplicate keys, unknown keys, nulls, wrong types and trailing values.
func Decode(data []byte) (Status, error) {
	var s Status
	if len(data) > MaxBytes {
		return s, errors.New("run status: exceeds 4 KiB")
	}
	if !utf8.Valid(data) {
		return s, errors.New("run status: invalid UTF-8")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	tok, err := d.Token()
	if err != nil || tok != json.Delim('{') {
		return s, errors.New("run status: expected object")
	}
	seen := make(map[string]bool, 6)
	for d.More() {
		tok, err := d.Token()
		if err != nil {
			return s, fmt.Errorf("run status: key: %w", err)
		}
		key, ok := tok.(string)
		if !ok || seen[key] {
			return s, fmt.Errorf("run status: invalid or duplicate key %q", key)
		}
		seen[key] = true
		var raw json.RawMessage
		if err := d.Decode(&raw); err != nil {
			return s, fmt.Errorf("run status: %s: %w", key, err)
		}
		if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return s, fmt.Errorf("run status: %s cannot be null", key)
		}
		var target any
		switch key {
		case "schema":
			target = &s.Schema
		case "run":
			target = &s.Run
		case "scope":
			target = &s.Scope
		case "cgroup_id":
			target = &s.CgroupID
		case "removed":
			target = &s.Removed
		case "deferred":
			target = &s.Deferred
		default:
			return s, fmt.Errorf("run status: unknown key %q", key)
		}
		if err := json.Unmarshal(raw, target); err != nil {
			return s, fmt.Errorf("run status: %s: %w", key, err)
		}
	}
	if _, err := d.Token(); err != nil {
		return s, fmt.Errorf("run status: closing object: %w", err)
	}
	if tok, err := d.Token(); !errors.Is(err, io.EOF) {
		return s, fmt.Errorf("run status: trailing value %v", tok)
	}
	if len(seen) != 6 {
		return s, errors.New("run status: all six fields are required")
	}
	if err := s.Validate(); err != nil {
		return Status{}, err
	}
	return s, nil
}

// Encode validates and encodes a status, including one trailing newline.
func Encode(s Status) ([]byte, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	b, err := json.Marshal(s)
	if err != nil {
		return nil, fmt.Errorf("run status: encode: %w", err)
	}
	b = append(b, '\n')
	if len(b) > MaxBytes {
		return nil, errors.New("run status: exceeds 4 KiB")
	}
	return b, nil
}
