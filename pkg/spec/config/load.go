// SPDX-License-Identifier: Apache-2.0

package config

import (
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

// Sources are the file paths of the three file layers; "" means the layer is absent.
type Sources struct {
	Etc     string
	User    string
	EnvFile string
}

// Resolve discovers the layer paths for invokingUID (R14, R19, R21): the fixed /etc path, the
// per-user path under the passwd home directory (a missing passwd entry leaves the layer absent
// with a warning, E9), and $TEGO_CONFIG unless secure. home is the passwd home directory or "".
// $HOME is never read, not even through os/user's pure-Go fallback for the own uid (LookupPasswd).
func Resolve(invokingUID int, secure bool) (src Sources, home string, diags []Diagnostic) {
	src.Etc = EtcPath
	if u, err := LookupPasswd(invokingUID); err == nil && u.HomeDir != "" {
		home = u.HomeDir
		src.User = home + "/" + UserRelPath
	} else {
		diags = append(diags, Diagnostic{Code: CodeIgnored, Severity: SeverityWarning,
			Message: fmt.Sprintf("no passwd entry for uid %d: per-user config layer skipped", invokingUID)})
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

// LoadMode is Load with an explicit trust mode: TrustAbort for tego run, TrustWarn for compile
// and doctor, which warn about an untrusted or invalid layer and skip it (I11).
func LoadMode(invokingUID int, secure bool, mode TrustMode) (*Machine, []Diagnostic, error) {
	src, home, diags := Resolve(invokingUID, secure)
	m, more, err := LoadSources(src, home, invokingUID, mode)
	return m, append(diags, more...), err
}

// LoadSources merges the built-in layer and the given layer files in order. home expands a
// leading "~/" in path settings; "" leaves them as written. Each present layer is trust-checked as
// it is opened (R20) and, in TrustAbort mode, a failure aborts before any later layer is read
// (R14); in TrustWarn mode the layer is skipped whole and never partially applied.
func LoadSources(src Sources, home string, invokingUID int, mode TrustMode) (*Machine, []Diagnostic, error) {
	m := Builtin()
	m.Home = home
	var diags []Diagnostic
	layers := []struct {
		path  string
		layer Layer
	}{{src.Etc, LayerEtc}, {src.User, LayerUser}, {src.EnvFile, LayerEnvFile}}
	for _, l := range layers {
		if l.path == "" {
			continue
		}
		// A relative layer ($TEGO_CONFIG=machine.yaml) is refused unread, as a relative path setting is (parser.path):
		// it names another file in every working directory, and R10 keeps a run's writes off only the place its own Load
		// read, so a run started in one directory could plant the layer that later runs started in another load
		// (ADR 0059). Etc is absolute, and User is the passwd home's. An absolute path whose walk reaches
		// procfs (/proc/self/cwd/machine.yaml, a link to /proc/thread-self/cwd, /dev/fd/../cwd) is refused the same way:
		// the kernel resolves it against the process that opens it, so it too names <cwd>/machine.yaml everywhere.
		if why := layerPathProblem(l.path); why != "" {
			d := Diagnostic{File: l.path, Code: CodeInvalid, Severity: SeverityError,
				Message: "machine config layer " + strconv.Quote(l.path) + " " + why,
				Fix:     "Set $" + EnvConfigVar + " to an absolute path that does not pass through /proc."}
			if l.layer != LayerEnvFile {
				d.Fix = "Give the invoking user an absolute home directory that does not pass through /proc in the passwd database."
			}
			if mode == TrustWarn {
				d = demote([]Diagnostic{d})[0]
			}
			diags = append(diags, d)
			if err := skipOrAbort(l.path, fmt.Errorf("%w: %s", ErrInvalid, l.path), mode, nil); err != nil {
				return nil, diags, err
			}
			continue
		}
		// A place a later Load reads, present or not (R10, ADR 0059), named as written: R10 walks it as the open did.
		m.Layers = append(m.Layers, l.path)
		if err := applyFile(m, l.path, l.layer, invokingUID, mode, &diags); err != nil {
			return nil, diags, err
		}
	}
	expandHome(m, home, &diags)
	return m, diags, nil
}

// layerPathProblem says why a layer path names a different file for each process that opens it, or "" when it does
// not: a relative path is read against the opener's working directory, and a path whose walk reaches procfs against
// whatever the opener's /proc/self names (its working directory, its root, its descriptors).
func layerPathProblem(path string) string {
	if !filepath.IsAbs(path) {
		return "is not an absolute path: it names another file in every working directory"
	}
	if via, ok := ThroughProc(path); ok {
		return "reaches procfs (" + strconv.Quote(via) + "), which names a file relative to the process that opens it: it names another file in every working directory"
	}
	return ""
}

// applyFile reads, trust-checks, parses and merges one layer; in TrustWarn mode a failure becomes
// a warning and the layer is skipped.
func applyFile(m *Machine, path string, layer Layer, invokingUID int, mode TrustMode, diags *[]Diagnostic) error {
	data, absent, err := readTrusted(path, invokingUID)
	if err != nil {
		return skipOrAbort(path, err, mode, diags)
	}
	if absent {
		if layer == LayerEnvFile {
			// E13: the operator explicitly named this path; a missing file is not an optional layer. It
			// also wraps fs.ErrNotExist, so run's refusal does not point at parse errors that were never printed.
			return skipOrAbort(path, fmt.Errorf("%w: $TEGO_CONFIG names %s: %w", ErrInvalid, path, fs.ErrNotExist), mode, diags)
		}
		return nil
	}
	d, parsed := parseLayer(path, data)
	if HasErrors(parsed) {
		if mode == TrustWarn {
			parsed = demote(parsed) // the layer is skipped whole; what was wrong stays visible
		}
		*diags = append(*diags, parsed...)
		// "config: invalid layer: <path>": the sentinel already names the package, and wrapping it as
		// "config: <path>: %w" printed "config: <path>: config: invalid layer".
		return skipOrAbort(path, fmt.Errorf("%w: %s", ErrInvalid, path), mode, nil)
	}
	*diags = append(*diags, parsed...)
	merger{file: path, layer: layer, diags: diags}.apply(m, d)
	return nil
}

// skipOrAbort returns err in TrustAbort mode, else records a warning and returns nil.
func skipOrAbort(path string, err error, mode TrustMode, diags *[]Diagnostic) error {
	if mode == TrustAbort {
		return err
	}
	if diags == nil {
		return nil // the parse diagnostics already say what is wrong
	}
	d := Diagnostic{File: path, Message: err.Error(), Code: CodeInvalid, Severity: SeverityWarning,
		Fix: "The layer was skipped."}
	var ue *UntrustedError
	if errors.As(err, &ue) {
		d.Message, d.Code, d.Fix = ue.Error(), CodeUntrusted, ue.Fix()+" The layer was skipped."
	}
	*diags = append(*diags, d)
	return nil
}

// demote turns a skipped layer's error diagnostics into warnings that say the layer was skipped.
func demote(diags []Diagnostic) []Diagnostic {
	out := make([]Diagnostic, len(diags))
	for i, d := range diags {
		if d.Severity == SeverityError {
			d.Severity = SeverityWarning
			d.Fix = strings.TrimSpace(d.Fix + " The layer was skipped.")
		}
		out[i] = d
	}
	return out
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
