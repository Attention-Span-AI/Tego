// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/attention-span-ai/tego/internal/contracts"
	"github.com/attention-span-ai/tego/internal/contractsrc"
	"github.com/attention-span-ai/tego/internal/registry"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

func init() { register(cmdContracts) }

func cmdContracts() Command {
	var asJSON, verbose bool
	return Command{
		Name: "contracts", Summary: "find contracts and check today's files without running an agent",
		Usage: "[show <name|path>] [--json] [-v]",
		Flags: func(fs *flag.FlagSet) {
			fs.BoolVar(&asJSON, "json", false, "one versioned JSON object (spec/contracts/v1)")
			fs.BoolVar(&verbose, "v", false, "full hashes, context, compile warnings and the compiled table")
			fs.BoolVar(&verbose, "verbose", false, "same as -v")
		},
		Run: func(ctx context.Context, fs *flag.FlagSet, stdout, stderr io.Writer) int {
			ctx, cancel := contractsContext(ctx)
			defer cancel()
			if fs.NArg() != 0 && (fs.NArg() != 2 || fs.Arg(0) != "show" || fs.Arg(1) == "") {
				message(stderr, "", 0, 0, "tego contracts: use tego contracts [show <name|path>] [--json] [-v]", codeUsage)
				return identity.ExitUsage
			}
			if err := ctx.Err(); err != nil {
				return contractsFailure(stdout, stderr, asJSON, "interrupted", "interrupted", err)
			}
			m, ds, err := loadMachine(config.TrustAbort)
			if err := ctx.Err(); err != nil {
				return contractsFailure(stdout, stderr, asJSON, "interrupted", "interrupted", err)
			}
			writeConfigDiagnostics(stderr, ds)
			if err != nil {
				return contractsConfigFailure(stdout, stderr, asJSON, err)
			}
			places, rerr := registryPlaces(m)
			if rerr != nil {
				return contractsConfigFailure(stdout, stderr, asJSON, rerr)
			}
			if err := ctx.Err(); err != nil {
				return contractsFailure(stdout, stderr, asJSON, "interrupted", "interrupted", err)
			}
			anchor, _ := anchorPath(m) // An unresolved anchor leaves the compiler's normal home guard.
			names := make([]string, 0)
			for _, kv := range launchEnviron() {
				name, _, _ := strings.Cut(kv, "=")
				names = append(names, name)
			}
			general := contractsrc.ReadGeneral(ctx, m, places.UID)
			opts := contracts.Options{General: &general, Machine: m, Places: places, PATH: os.Getenv("PATH"), Tiers: builtTiers(),
				CompileContext: contracts.CompileContext{ChainAnchor: anchor, OwnBinary: runningBinary(), RuntimeDirs: config.RuntimeDirBases(), EnvNames: names}}
			return runContracts(ctx, fs.Args(), opts, asJSON, verbose, stdout, stderr)
		},
	}
}

const contractsTimeout = 60 * time.Second

func contractsContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, contractsTimeout)
}

// contractsCaller marks the command's helper checks as a governed program's when this process sits inside a run, or
// looks it, or cannot tell (selfAnswer: only an outside answer is the person's): they never take the helper slots kept for a person's checks.
func contractsCaller(ctx context.Context) context.Context {
	return contracts.WithGovernedCaller(ctx, func() bool {
		return !selfAnswer().Outside()
	})
}

func runContracts(ctx context.Context, args []string, o contracts.Options, asJSON, verbose bool, stdout, stderr io.Writer) int {
	ctx, closeSession := contracts.WithHelperSession(contractsCaller(ctx))
	defer closeSession()
	ctx, cancel := contractsContext(ctx)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return contractsFailure(stdout, stderr, asJSON, "interrupted", "interrupted", err)
	}
	var catalog contracts.Catalog
	selector := ""
	if len(args) == 2 {
		selector = args[1]
	}
	o.KeepTableFor = selector
	if selector != "" && !registry.IsName(selector) {
		path := selector
		// Preserve a path's kernel walk before any filepath.Join/Clean changes it.
		if !filepath.IsAbs(selector) {
			path = o.Places.Dir + string(filepath.Separator) + selector
		}
		walked, placeErr := contracts.PlacePath(ctx, path)
		if err := ctx.Err(); err != nil {
			return contractsFailure(stdout, stderr, asJSON, "interrupted", "interrupted", err)
		}
		if placeErr != nil {
			return contractsFailure(stdout, stderr, asJSON, "source-path", "cannot place that path", placeErr)
		}
		catalog = contracts.Inspect(ctx, walked, o)
		selector = walked
	} else {
		catalog = contracts.Discover(ctx, o)
	}
	var err error
	code := catalog.ExitCode()
	if selector == "" {
		if asJSON {
			err = writeJSON(stdout, catalog)
		} else {
			err = contracts.PrintList(stdout, catalog, verbose)
		}
	} else {
		if registry.IsName(selector) && catalog.Incomplete {
			message(stderr, "", 0, 0, "tego contracts: discovery is incomplete, so that name cannot be proven unambiguous; give the contract's path", codeIO)
			return identity.ExitError
		}
		e, selErr := catalog.Select(selector)
		if selErr != nil {
			code := registry.CodeNotFound
			if errors.Is(selErr, contracts.ErrAmbiguous) {
				code = registry.CodeAmbiguous
			}
			message(stderr, "", 0, 0, "tego contracts: "+selErr.Error(), code)
			return identity.ExitFinding
		}
		var show contracts.Show
		show, err = catalog.Describe(*e)
		if err == nil {
			if asJSON {
				err = writeJSON(stdout, show)
			} else {
				err = contracts.PrintShow(stdout, show, verbose)
			}
		}
		// Other broken contracts do not fail a selected contract's check.
		selected := contracts.Catalog{Contracts: []contracts.Entry{*e}, Incomplete: catalog.Incomplete}
		if filepath.IsAbs(selector) {
			selected.Contracts[0].Ambiguous = false
		}
		code = selected.ExitCode()
	}
	if err != nil {
		message(stderr, "", 0, 0, "tego contracts: write output: "+err.Error(), codeIO)
		return identity.ExitError
	}
	return code
}

func contractsConfigFailure(stdout, stderr io.Writer, asJSON bool, err error) int {
	return contractsFailure(stdout, stderr, asJSON, "machine-context", "machine context", err)
}

func contractsFailure(stdout, stderr io.Writer, asJSON bool, code, what string, err error) int {
	message(stderr, "", 0, 0, "tego contracts: "+what+": "+err.Error(), codeIO)
	c := contracts.Catalog{Schema: contracts.Schema, Contracts: []contracts.Entry{}, Roots: []contracts.Root{},
		Issues: []contracts.Diagnostic{{Code: code, Message: err.Error(), Severity: agent.SeverityError}}, Incomplete: true, Context: contracts.ContextNote, Footer: contracts.Footer}
	if asJSON {
		_ = writeJSON(stdout, c)
	} else {
		_ = contracts.PrintList(stdout, c, false)
	}
	return identity.ExitError
}
