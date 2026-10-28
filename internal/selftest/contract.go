// SPDX-License-Identifier: Apache-2.0

package selftest

import (
	"bytes"
	_ "embed" // the contract template
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/template"

	"github.com/attention-span-ai/tego/pkg/spec/config"
	"gopkg.in/yaml.v3"
)

//go:embed contract.yaml.tmpl
var contractText string

var contractTmpl = template.Must(template.New("contract").Parse(contractText))

// quoted is s as a YAML double-quoted scalar: JSON's string syntax is a subset of YAML's, so no path, however
// spelled, can break out of its entry.
func quoted(s string) string {
	b, err := json.Marshal(s)
	if err != nil { // a Go string always marshals
		panic(err)
	}
	return string(b)
}

// writeContract fills the embedded contract with the tree's paths and the tego binary, and writes it beside the
// workdir, outside every write entry.
func (t tree) writeContract(tego string) error {
	var buf bytes.Buffer
	err := contractTmpl.Execute(&buf, map[string]string{
		"Tego": quoted(tego),
		"Out":  quoted(t.out()),
		"SSH":  quoted(filepath.Dir(t.key()) + "/"),
		"Env":  quoted(t.env()),
	})
	if err != nil {
		return err
	}
	return os.WriteFile(t.contract(), buf.Bytes(), 0o600)
}

// ConfigError is a caller's $TEGO_CONFIG layer that tego run itself would refuse ([config-untrusted]): tego test
// refuses it too rather than copy it into the tree, where the copy would pass every check the original fails.
type ConfigError struct {
	// Err is pkg/spec/config's error: *config.UntrustedError, or one wrapping config.ErrInvalid.
	Err error
	// Detail is the first error diagnostic's message and fix, when Load gave one (a relative or /proc path, a key it
	// rejects); "" otherwise.
	Detail string
}

func (e *ConfigError) Error() string {
	if e.Detail != "" {
		return e.Err.Error() + ": " + e.Detail
	}
	return e.Err.Error()
}

func (e *ConfigError) Unwrap() error { return e.Err }

// trustedLayer reads the caller's layer only after it passes the checks tego run's own Load applies to it (R14, R20,
// the relative and procfs path refusal of ADR 0059), so tego test acts on no layer tego run would refuse. The bytes
// come from a second trusted read, which re-checks owner and mode on the descriptor it reads.
func trustedLayer(layer string) ([]byte, error) {
	uid, _ := config.InvokingUID()
	if _, diags, err := config.LoadSources(config.Sources{EnvFile: layer}, "", uid, config.TrustAbort); err != nil {
		ce := &ConfigError{Err: err}
		for _, d := range diags {
			if d.Severity == config.SeverityError {
				ce.Detail = strings.TrimSpace(d.Message + ". " + d.Fix)
				break
			}
		}
		return nil, ce
	}
	b, err := config.ReadTrusted(layer, uid)
	if err != nil {
		return nil, &ConfigError{Err: err}
	}
	return b, nil
}

// writeConfig writes the machine config layer the runs read through $TEGO_CONFIG: the caller's own $TEGO_CONFIG
// layer, when it has one and tego run would trust it (trustedLayer), with ledger_root replaced by the tree's, so every
// setting but where the record goes is the caller's own and the four runs' ledgers stay in the tree.
func (t tree) writeConfig(callerLayer string) error {
	doc := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	if callerLayer != "" {
		b, err := trustedLayer(callerLayer)
		if err != nil {
			return err
		}
		var root yaml.Node
		if err := yaml.Unmarshal(b, &root); err != nil {
			return fmt.Errorf("read $TEGO_CONFIG %s: %w", callerLayer, err)
		}
		switch {
		case root.Kind == 0: // an empty file
		case root.Kind == yaml.DocumentNode && len(root.Content) == 1 && root.Content[0].Kind == yaml.MappingNode:
			doc = root.Content[0]
		default:
			return fmt.Errorf("read $TEGO_CONFIG %s: not a mapping", callerLayer)
		}
	}
	kept := doc.Content[:0]
	for i := 0; i+1 < len(doc.Content); i += 2 {
		if doc.Content[i].Value == "ledger_root" {
			continue
		}
		kept = append(kept, doc.Content[i], doc.Content[i+1])
	}
	kept = append(kept,
		&yaml.Node{Kind: yaml.ScalarNode, Value: "ledger_root"},
		&yaml.Node{Kind: yaml.ScalarNode, Value: t.ledger(), Style: yaml.DoubleQuotedStyle})
	doc.Content = kept
	out, err := yaml.Marshal(doc)
	if err != nil {
		return err
	}
	return os.WriteFile(t.config(), out, 0o600)
}
