// SPDX-License-Identifier: Apache-2.0

package config

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Layer file locations (spec/config/v0/README.md).
const (
	// EtcPath is the system layer.
	EtcPath = "/etc/tego/config.yaml"
	// UserRelPath is the per-user layer relative to the invoking user's home directory (from the
	// passwd database, never $HOME).
	UserRelPath = ".tego/config.yaml"
	// EnvConfigVar names the environment variable of the fourth layer; ignored under AT_SECURE.
	EnvConfigVar = "TEGO_CONFIG"
)

// Sources are the file paths of the three file layers; "" leaves a layer unselected.
type Sources struct {
	Etc     string
	User    string
	EnvFile string
}

// Resolve discovers the layer paths for invokingUID (R14, R19, R21): the fixed /etc path, the
// per-user path under the passwd home directory (unselected when no home is known, E9),
// and $TEGO_CONFIG unless secure. home is the passwd home directory or "".
// $HOME is never read, not even through os/user's pure-Go fallback for the own uid (LookupPasswd).
func Resolve(invokingUID int, secure bool) (src Sources, home string, diags []Diagnostic) {
	src.Etc = EtcPath
	if u, err := LookupPasswd(invokingUID); err == nil && u.HomeDir != "" {
		home = u.HomeDir
		src.User = home + "/" + UserRelPath
	}
	if !secure { // R14/R21: $TEGO_CONFIG is skipped entirely under AT_SECURE
		src.EnvFile = os.Getenv(EnvConfigVar)
	}
	return src, home, diags
}

// Load reads the machine config for invokingUID with the abort trust mode of tego run.
//
// Pre: invokingUID and secure come from InvokingUID and DetectSecureExec (or are fixed in tests).
// Post: on success a fully populated *Machine with correct provenance (built-in fills anything
// unset) and possibly warnings; on error the diagnostics gathered so far. Errors: *UntrustedError
// (errors.Is ErrUntrusted), ErrInvalid wrapped for a malformed layer or unsupported version, or a
// wrapped I/O error; tego run maps any of them to exit 125 [config-untrusted]. Read-only and
// idempotent for an unchanged filesystem; opens only the layer files and their directories.
func Load(invokingUID int, secure bool) (*Machine, []Diagnostic, error) {
	return LoadMode(invokingUID, secure, TrustAbort)
}

// LoadMode selects strict decision loads or degraded observation loads (ADR 0144).
// A degraded snapshot must never be used to start a run or decide its rules.
func LoadMode(invokingUID int, secure bool, mode TrustMode) (*Machine, []Diagnostic, error) {
	src, home, diags := Resolve(invokingUID, secure)
	m, more, err := LoadSources(src, home, invokingUID, mode)
	return m, append(diags, more...), err
}

// LoadSources merges the built-in layer and the given layer files in order. home expands a
// leading "~/" in ordinary path settings, never baseline entries. Each layer is trust-checked as
// it is opened (R20, ADR 0144); TrustAbort stops at a failure, while TrustWarn marks it unknown. An absent
// system/user layer is optional; a selected missing TEGO_CONFIG is a strict error or UNKNOWN (E13).
func LoadSources(src Sources, home string, invokingUID int, mode TrustMode) (*Machine, []Diagnostic, error) {
	return loadSources(src, home, invokingUID, mode, readLayer)
}

// LoadSourcesBounded applies the same trust and merge rules with a smaller
// per-layer byte limit for callers with a shared input budget.
func LoadSourcesBounded(src Sources, home string, invokingUID int, mode TrustMode, maxBytes int64) (*Machine, []Diagnostic, error) {
	if maxBytes <= 0 || maxBytes > MaxLayerSize {
		return nil, nil, fmt.Errorf("%w: invalid layer bound", ErrInvalid)
	}
	return loadSources(src, home, invokingUID, mode, func(path string, layer Layer, uid int) ([]byte, bool, error) {
		return readLayerBounded(path, layer, uid, maxBytes)
	})
}

// layerReader keeps filesystem fixtures separate from the system placement trust policy.
type layerReader func(string, Layer, int) ([]byte, bool, error)

func loadSources(src Sources, home string, invokingUID int, mode TrustMode, read layerReader) (*Machine, []Diagnostic, error) {
	return loadSourcesWithAuthority(src, home, invokingUID, mode, read, pinLocalAuthority)
}

type authorityPinner func(string, int, []byte) (LocalAuthority, error)

func loadSourcesWithAuthority(src Sources, home string, invokingUID int, mode TrustMode, read layerReader, pin authorityPinner) (*Machine, []Diagnostic, error) {
	// A failed input is UNKNOWN, never evidence that no baseline exists.
	m := Builtin()
	m.Sources = &src
	m.SourceDigests = make(map[string]string)
	m.Home = home
	var diags []Diagnostic
	layers := []struct {
		path  string
		layer Layer
	}{{src.Etc, LayerEtc}, {src.User, LayerUser}, {src.EnvFile, LayerEnvFile}}
	for _, l := range layers {
		if l.path == "" {
			m.sources = append(m.sources, LayerSource{Layer: l.layer, State: LayerUnselected})
			continue
		}
		// A relative layer ($TEGO_CONFIG=machine.yaml) is refused unread, as a relative path setting is (parser.path):
		// it names another file in every working directory, and R10 keeps a run's writes off only the place its own Load
		// read, so a run started in one directory could plant the layer that later runs started in another load
		// (ADR 0059). Etc is absolute, and User is the passwd home's. An absolute path whose walk reaches
		// procfs (/proc/self/cwd/machine.yaml, a link to /proc/thread-self/cwd, /dev/fd/../cwd) is refused the same way:
		// the kernel resolves it against the process that opens it, so it too names <cwd>/machine.yaml everywhere.
		// The layer's name in every message about it is decided here, once: its path, which is a place and is named
		// as the settings file a message is about always is, or "$TEGO_CONFIG" when that variable's value is not an
		// absolute clean path of printable characters. Such a value failed validation, so it is never echoed: the
		// message names the variable and how to print it (pkg/spec/identity envtext.go, rules (b) and (c); this leaf
		// package restates EnvPlace, and internal/adapters' parity test holds the two to the same answers).
		shown := l.path
		if l.layer == LayerEnvFile && !EnvPlace(l.path) {
			shown = "$" + EnvConfigVar
		}
		if why := layerPathProblem(l.path, shown == l.path); why != "" {
			quoted := strconv.Quote(l.path)
			if shown != l.path {
				quoted = "named by " + shown
			}
			d := Diagnostic{File: shown, Code: CodeInvalid, Severity: SeverityError,
				Message: "machine config layer " + quoted + " " + why,
				Fix:     "Set $" + EnvConfigVar + " to an absolute path that does not pass through /proc."}
			if shown != l.path {
				d.Fix += " Print the value with: echo $" + EnvConfigVar
			}
			if l.layer != LayerEnvFile {
				d.Fix = "Give the invoking user an absolute home directory that does not pass through /proc in the passwd database."
			}
			err := fmt.Errorf("%w: %s", ErrInvalid, d.String())
			if mode == TrustAbort {
				diags = append(diags, d)
				return nil, diags, fmt.Errorf("%w: %s", ErrInvalid, shown)
			}
			markUnknown(m, l.path, shown, l.layer, err, &diags)
			continue
		}
		// A place a later Load reads, present or not (R10, ADR 0059), named as written: R10 walks it as the open did.
		m.Layers = append(m.Layers, l.path)
		start := len(diags)
		if err := applyFile(m, l.path, shown, l.layer, invokingUID, &diags, read, pin); err != nil {
			if mode == TrustAbort {
				return nil, diags, err
			}
			// The unknown diagnostic contains the refusal once, including parser details.
			if len(diags) > start {
				err = fmt.Errorf("%w: %s", err, diags[start].String())
				diags = diags[:start]
			}
			markUnknown(m, l.path, shown, l.layer, err, &diags)
		}
	}
	expandHome(m, home, &diags)
	return m, diags, nil
}

// layerPathProblem says why a layer path names a different file for each process that opens it, or "" when it does
// not: a relative path is read against the opener's working directory, and a path whose walk reaches procfs against
// whatever the opener's /proc/self names (its working directory, its root, its descriptors). showVia is false for a
// value that is never echoed: the spelling that reached procfs is a part of it.
func layerPathProblem(path string, showVia bool) string {
	if !filepath.IsAbs(path) {
		return "is not an absolute path: it names another file in every working directory"
	}
	if via, ok := ThroughProc(path); ok {
		at := ""
		if showVia {
			at = " (" + strconv.Quote(via) + ")"
		}
		return "reaches procfs" + at + ", which names a file relative to the process that opens it: it names another file in every working directory"
	}
	return ""
}

// applyFile reads, trust-checks, parses and merges one layer atomically. The caller selects
// whether a failure aborts or marks the layer unknown. path is the file opened; shown is its name in every
// diagnostic, error and provenance (loadSources decides it once per layer).
func applyFile(m *Machine, path, shown string, layer Layer, invokingUID int, diags *[]Diagnostic, read layerReader, pin authorityPinner) error {
	// Every error leaving here names the layer as shown: an identity probe's error carries the path it opened.
	hide := func(err error) error {
		if shown != path {
			return hideLayerValue(err, path, shown)
		}
		return err
	}
	before, inspectErr := inspectLayerIdentity(path)
	data, absent, err := read(path, layer, invokingUID)
	if err != nil {
		return hide(err)
	}
	if inspectErr != nil {
		return hide(fmt.Errorf("config: inspect layer identity %s: %w", shown, inspectErr))
	}
	after, err := inspectLayerIdentity(path)
	if err != nil {
		return hide(fmt.Errorf("config: recheck layer identity %s: %w", shown, err))
	}
	if before != after || absent != (after.Missing != "") {
		return fmt.Errorf("config: layer %s changed while it was being read", shown)
	}
	m.layerIdentities[int(layer)-1] = after.layerIdentity
	if m.SourceDigests == nil {
		m.SourceDigests = make(map[string]string)
	}
	// Every record of the layer that a message, a report or a digest table can reach names it as shown: an unplaced
	// $TEGO_CONFIG value is never exported (rule (b)). path is used to open the file and by Machine.Layers, which
	// R10 reads to keep a run's writes off the file; nothing prints Layers.
	if absent {
		m.SourceDigests[shown] = "absent"
		if layer == LayerEnvFile {
			// E13: the operator explicitly named this path; a missing file is not an optional layer. It
			// also wraps fs.ErrNotExist, so run's refusal does not point at parse errors that were never printed.
			named := path
			if shown != path {
				named = "a file by a value that is not an absolute clean path (not shown; print it with: echo $" + EnvConfigVar + ")"
			}
			return fmt.Errorf("%w: $TEGO_CONFIG names %s: %w", ErrInvalid, named, fs.ErrNotExist)
		}
		m.sources = append(m.sources, LayerSource{Layer: layer, File: shown, State: LayerAbsent})
		return nil
	}
	m.SourceDigests[shown] = fmt.Sprintf("%x", sha256.Sum256(data))
	if m.layerBytes == nil {
		m.layerBytes = make(map[Layer][]byte)
	}
	m.layerBytes[layer] = append([]byte{}, data...)
	d, parsed := parseLayer(shown, data)
	if HasErrors(parsed) {
		*diags = append(*diags, parsed...)
		// "config: invalid layer: <path>": the sentinel already names the package, and wrapping it as
		// "config: <path>: %w" printed "config: <path>: config: invalid layer".
		return fmt.Errorf("%w: %s", ErrInvalid, shown)
	}
	if layer == LayerEtc && d.localRoles.set && d.localRoles.value == LocalRolesOwnerOnly {
		a, err := pin(path, invokingUID, data)
		if err != nil {
			return hide(err)
		}
		m.localAuthority = a
	}
	*diags = append(*diags, parsed...)
	sum := sha256.Sum256(data)
	m.sources = append(m.sources, LayerSource{Layer: layer, File: shown, State: LayerPresent, SHA256: hex.EncodeToString(sum[:])})
	merger{file: shown, layer: layer, diags: diags}.apply(m, d)
	return nil
}

// markUnknown keeps observation loads useful without presenting a missing refusal as empty. shown is the layer's
// name in the diagnostic (loadSources decides it); the list of sources names it the same way.
func markUnknown(m *Machine, path, shown string, layer Layer, err error, diags *[]Diagnostic) {
	m.baseline.unknown = true
	if layer == LayerEtc {
		m.localAuthorityUnknown = true
	}
	m.sources = append(m.sources, LayerSource{Layer: layer, File: shown, State: LayerUnknown, Reason: err.Error()})
	d := Diagnostic{File: shown, Code: CodeBaselineUnknown, Severity: SeverityWarning,
		Message: fmt.Sprintf("baseline UNKNOWN: %s layer could not be read: %v", layer, err)}
	var ue *UntrustedError
	if errors.As(err, &ue) {
		d.Fix = ue.Fix()
	}
	if errors.Is(err, fs.ErrPermission) {
		d.Fix = "Check the layer file owner read bits and directory search bits; tego run or non-dry tego gc restores missing owner bits on the user's own Tego state."
	}
	*diags = append(*diags, d)
}

// folderOnTheWay names a folder that is a prefix of an unplaced $TEGO_CONFIG value. The value failed validation, so
// no part of it is echoed; the folder is described by the file the variable names.
const folderOnTheWay = "a folder on the way to the file $" + EnvConfigVar + " names"

// hideLayerValue keeps a $TEGO_CONFIG value that is not a place out of the error its read returned (rule (b)): an
// untrusted file named by that value is named by shown, which a shell also expands, an untrusted folder on the way to
// it (any prefix of the value) is named folderOnTheWay, and any other error's text has the value replaced by shown and
// each prefix of it by folderOnTheWay. errors.Is and errors.As still reach the error the read returned.
func hideLayerValue(err error, value, shown string) error {
	var ue *UntrustedError
	if errors.As(err, &ue) {
		if ue.Path == value {
			ue.Path = shown
		} else if isValuePrefix(value, ue.Path) {
			ue.Path = folderOnTheWay
		}
	}
	h := &hiddenValueError{err: err, value: value, shown: shown}
	if replaceValue(err.Error(), value, shown, true) == err.Error() {
		return err
	}
	return h
}

// isValuePrefix reports whether folder is value up to a path separator: a folder on the way to the file value names.
func isValuePrefix(value, folder string) bool {
	return folder != "" && folder != "/" && len(folder) < len(value) && value[len(folder)] == '/' && strings.HasPrefix(value, folder)
}

// hiddenValueError is an error whose text names a layer by shown in place of its value and a folder on the way to it by
// folderOnTheWay (hideLayerValue).
type hiddenValueError struct {
	err          error
	value, shown string
}

func (e *hiddenValueError) Error() string {
	text := e.err.Error()
	hidden := replaceValue(text, e.value, e.shown, true)
	if hidden == text {
		return text
	}
	return hidden + " (the value is not shown; print it with: echo $" + EnvConfigVar + ")"
}

// HideUnplaced returns text with an unplaced location-variable value (one EnvPlace refuses, from $TEGO_CONFIG)
// replaced by "$TEGO_CONFIG", and each folder on the way to it that is itself not a place (a control character or a
// ".." in it) by a description of the file the variable names. A value that is a place is left as it is. Messages that
// mention other paths use it, since a clean folder such as /tmp may be a part of those too.
func HideUnplaced(text, value string) string {
	if value == "" || EnvPlace(value) {
		return text
	}
	return replaceValue(text, value, "$"+EnvConfigVar, false)
}

// replaceValue replaces value by shown in text, and the folders on the way to it (longest first: a shorter prefix is a
// part of every longer one) by folderOnTheWay: every one, or with all false only a folder that is not a place.
func replaceValue(text, value, shown string, all bool) string {
	text = strings.ReplaceAll(text, value, shown)
	for i := len(value) - 1; i > 0; i-- {
		if value[i] == '/' && (all || !EnvPlace(value[:i])) {
			text = strings.ReplaceAll(text, value[:i], folderOnTheWay)
		}
	}
	return text
}

func (e *hiddenValueError) Unwrap() error { return e.err }

// EnvPlace reports whether value, read from a location variable such as $TEGO_CONFIG, is a place a message may
// print: an absolute, clean path of printable characters. Any other value failed validation and is never echoed.
// It restates pkg/spec/identity's EnvPlace, which this leaf package may not import (the depguard rule in .golangci.yml);
// internal/adapters' TestEnvPlaceParity holds the two to the same answers.
func EnvPlace(value string) bool {
	if value == "" || !filepath.IsAbs(value) || filepath.Clean(value) != value {
		return false
	}
	for i := 0; i < len(value); i++ {
		if c := value[i]; c < 0x20 || c == 0x7f {
			return false
		}
	}
	return true
}

// expandHome replaces a leading "~/" in the path settings with home. With no home, ledger_root keeps
// its "~/" (the run refuses it, or falls back to $HOME when not AT_SECURE), but prices, profiles and registry are
// dropped with a diagnostic: read as written they would resolve against the cwd, in a directory
// literally named "~" that the agent can write.
func expandHome(m *Machine, home string, diags *[]Diagnostic) {
	if home == "" {
		for _, s := range []*Setting[string]{&m.Prices, &m.Profiles, &m.Registry} {
			if s.Value == "~" || strings.HasPrefix(s.Value, "~/") {
				if s.Source.Layer == LayerBuiltin {
					s.Value = "" // the default, not a choice: no home means no default table, profiles or registry
					continue
				}
				*diags = append(*diags, Diagnostic{File: s.Source.File, Line: s.Source.Line,
					Message: "path setting " + strconv.Quote(s.Value) + " needs a home directory and the passwd database names none for this uid",
					Code:    CodeIgnored, Severity: SeverityWarning,
					Fix: "The setting was left empty; set it to an absolute path."})
				s.Value = ""
			}
		}
		return
	}
	for _, s := range []*Setting[string]{&m.LedgerRoot, &m.Prices, &m.Profiles, &m.Registry} {
		if strings.HasPrefix(s.Value, "~/") {
			s.Value = home + s.Value[1:]
		}
	}
}
