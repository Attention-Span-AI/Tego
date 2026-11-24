// SPDX-License-Identifier: Apache-2.0

package config

import (
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"time"
)

// CallerContext is a caller-selected value for offline checks in an empty-environment
// helper. Workers use these facts instead of deriving the caller from their process.
// It contains selected public paths and identity facts, never secret values.
type CallerContext struct {
	Cwd, CwdError string
	CheckedAt     time.Time
	// RuleDate is an explicit caller clock override for rule comments.
	RuleDate                  string
	UID                       int
	Username, Home, HomeError string
	RuntimeDirs               []string
	GuardHomes                []string
	TMUXDir, ScreenDir, PATH  string
	// ResolverSettings names active resolver selectors, never their values.
	ResolverSettings []string
}

// CaptureCaller computes process-dependent check inputs once, before dispatch.
func CaptureCaller() CallerContext {
	uid, _ := InvokingUID()
	c := CallerContext{UID: uid, Username: strconv.Itoa(uid), RuntimeDirs: runtimeDirBases(uid, os.Getenv("XDG_RUNTIME_DIR"), LogindRuntimeRoot), CheckedAt: time.Now(),
		TMUXDir: os.Getenv("TMUX_TMPDIR"), ScreenDir: os.Getenv("SCREENDIR"), PATH: os.Getenv("PATH"), ResolverSettings: resolverSettings(os.LookupEnv)}

	cwd, cwdErr := os.Getwd()
	c.Cwd = cwd
	if cwdErr != nil {
		c.CwdError = cwdErr.Error()
	}
	u, err := LookupPasswd(uid)
	var unknown user.UnknownUserIdError
	if err == nil {
		c.Username, c.Home = u.Username, u.HomeDir
	} else if !errors.As(err, &unknown) {
		c.HomeError = err.Error()
	}
	effectiveHome := c.Home
	if os.Geteuid() != uid {
		// Match DefaultGuard: a failed passwd-home lookup adds no spelling.
		effectiveHome, _ = PasswdHome(os.Geteuid())
	}
	if effectiveHome != "" {
		c.GuardHomes = append(c.GuardHomes, filepath.Join(effectiveHome, ".tego"))
	}
	if h := os.Getenv("HOME"); filepath.IsAbs(h) {
		c.GuardHomes = append(c.GuardHomes, filepath.Join(h, ".tego"))
	}
	return c
}
