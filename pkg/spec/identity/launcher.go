// SPDX-License-Identifier: Apache-2.0

package identity

import (
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// EnvSudoUID is the variable sudo sets to the real uid of the account that invoked it.
const EnvSudoUID = "SUDO_UID"

// MaxHostBytes is the longest host run_start records (ADR 0073): a longer nodename is not recorded, never cut.
const MaxHostBytes = 255

// noUID is (uid_t)-1, which names no account (setresuid's "leave unchanged"), so a SUDO_UID spelling it is no uid.
const noUID = 1<<32 - 1

// Launcher is who launched a run and where, as run_start records it (ADR 0073, record-ledger.md §2.2): the launcher's
// real uid and its passwd name, the account sudo says invoked a root launcher, and the host's kernel nodename. Every
// field is what the launcher's own process could read when the run started: none is a verified fact about a person.
type Launcher struct {
	// UID is the launcher's real uid, written on every run_start (launcher_uid), 0 included.
	UID uint32
	// User is UID's passwd name; "" when the passwd database names none or the name is not valid UTF-8 or holds a
	// character a label value may not (the database is the mount namespace's to replace).
	User string
	// SudoUID is SUDO_UID's uid, set only when the launcher's euid is 0 and SUDO_UID is the decimal of a uid;
	// nil otherwise. It is sudo's claim, which any root process can set.
	SudoUID *uint32
	// SudoUser is SudoUID's passwd name, never the SUDO_USER string; "" when SudoUID is nil or has no entry, or the
	// name breaks User's rule.
	SudoUser string
	// Host is the kernel nodename; "" when it could not be read, is empty, is longer than MaxHostBytes, is not
	// UTF-8 or holds a character a label value may not (a control, format, line or paragraph separator character).
	Host string
}

// LauncherOf is the Launcher of a process with real uid uid and effective uid euid (a caller whose real uid is not 0,
// or that is uid 0 of a user namespace other than the initial one, is no root, and passes an euid that is not 0), and
// environment environ (the launcher process's own, never an environment it builds for its agent: KEY=VALUE,
// the last entry for a key wins, as getenv's), passwd the passwd name of a uid (an error or "" for none) and hostname
// the kernel nodename. It is pure: it reads nothing but its arguments, and a nil passwd or hostname reads as none.
func LauncherOf(uid, euid uint32, passwd func(uint32) (string, error), environ []string,
	hostname func() (string, error)) Launcher {
	l := Launcher{UID: uid, User: passwdName(passwd, uid), Host: hostOf(hostname)}
	if euid != 0 {
		return l
	}
	if s, ok := lookupEnv(environ, EnvSudoUID); ok {
		if v, ok := parseUID(s); ok {
			l.SudoUID = &v
			l.SudoUser = passwdName(passwd, v)
		}
	}
	return l
}

// passwdName is uid's passwd name, or "" when there is none or it cannot be recorded as it is: the passwd database is
// the mount namespace's, which a user in its own user and mount namespace can replace, so a name takes the host's
// rule (valid UTF-8, nothing viewUnsafe finds) and one that breaks it is not recorded, never cleaned.
func passwdName(passwd func(uint32) (string, error), uid uint32) string {
	if passwd == nil {
		return ""
	}
	name, err := passwd(uid)
	if err != nil || !utf8.ValidString(name) {
		return ""
	}
	if _, why := viewUnsafe(name); why != "" {
		return ""
	}
	return name
}

// hostOf is the nodename hostname reads, or "" when it cannot be recorded as it is. The nodename is whoever holds the
// UTS namespace's to set (root, a container runtime, an unprivileged user in its own user and UTS namespace), so it
// takes the label value's character rule (viewUnsafe) for the same reason: a host a view prints beside the run may
// neither break that line nor reorder or hide what is printed beside it. A name that breaks it is not recorded, never
// cleaned: a changed name names another host.
func hostOf(hostname func() (string, error)) string {
	if hostname == nil {
		return ""
	}
	h, err := hostname()
	if err != nil || h == "" || len(h) > MaxHostBytes || !utf8.ValidString(h) {
		return ""
	}
	if _, why := viewUnsafe(h); why != "" {
		return ""
	}
	return h
}

// viewUnsafe is the first character of the valid UTF-8 s that a view must not print as it is, with what kind it is:
// a control (Cc), format (Cf), line or paragraph separator character. why is "" when s holds none.
func viewUnsafe(s string) (c rune, why string) {
	for _, c := range s {
		switch {
		case unicode.Is(unicode.Cc, c):
			return c, "control character"
		case unicode.Is(unicode.Cf, c):
			return c, "format character"
		case unicode.In(c, unicode.Zl, unicode.Zp):
			return c, "line or paragraph separator"
		}
	}
	return 0, ""
}

func lookupEnv(environ []string, key string) (string, bool) {
	val, found := "", false
	for _, kv := range environ {
		if k, v, ok := strings.Cut(kv, "="); ok && k == key {
			val, found = v, true
		}
	}
	return val, found
}

// parseUID is s as a uid, read as identity-config.md E8 reads SUDO_UID and as the launcher's drop to the invoking
// account reads it: an unsigned 32-bit decimal (no sign or blank space) other than (uid_t)-1.
func parseUID(s string) (uint32, bool) {
	v, err := strconv.ParseUint(s, 10, 32)
	if err != nil || v == noUID {
		return 0, false
	}
	return uint32(v), true
}

// Role is what a run is for, as run_start's role records it (ADR 0073).
type Role string

const (
	// RoleAgent is the agent's own run: run_start writes no role.
	RoleAgent Role = ""
	// RoleCheck is reserved for a run a checking command started; no shipped command sets it.
	RoleCheck Role = "check"
)

// Valid reports whether r is a role this version knows.
func (r Role) Valid() bool { return r == RoleAgent || r == RoleCheck }

// Label limits (ADR 0073).
const (
	// MaxLabels is the most labels one run carries.
	MaxLabels = 32
	// MaxLabelValueBytes is the longest label value, in bytes.
	MaxLabelValueBytes = 256
	// ReservedLabelPrefix starts the keys tego keeps for its own labels; a caller's label may not.
	ReservedLabelPrefix = "tego."
)

var labelKey = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)

// ValidLabels reports the first rule labels break, keys taken in byte order, nil when it breaks none (nil and empty are no labels): at most
// MaxLabels; each key ^[a-z0-9][a-z0-9._-]{0,62}$ and not under ReservedLabelPrefix; each value at most
// MaxLabelValueBytes of valid UTF-8 with no control (Cc), format (Cf), line or paragraph separator character, so a
// value can neither break a line of a view nor reorder or hide what is printed beside it.
func ValidLabels(labels map[string]string) error {
	if len(labels) > MaxLabels {
		return fmt.Errorf("%d labels: a run carries at most %d", len(labels), MaxLabels)
	}
	for _, k := range slices.Sorted(maps.Keys(labels)) {
		v := labels[k]
		if !labelKey.MatchString(k) {
			return fmt.Errorf("label key %q: a key is 1 to 63 of a-z, 0-9, '.', '_' and '-', starting with a letter or digit", k)
		}
		if strings.HasPrefix(k, ReservedLabelPrefix) {
			return fmt.Errorf("label key %q: the %q prefix is reserved for tego", k, ReservedLabelPrefix)
		}
		if err := validLabelValue(v); err != nil {
			return fmt.Errorf("label %q: %w", k, err)
		}
	}
	return nil
}

func validLabelValue(v string) error {
	if len(v) > MaxLabelValueBytes {
		return fmt.Errorf("the value is %d bytes, at most %d", len(v), MaxLabelValueBytes)
	}
	if !utf8.ValidString(v) {
		return fmt.Errorf("the value is not valid UTF-8")
	}
	if c, why := viewUnsafe(v); why != "" {
		return fmt.Errorf("the value holds the %s %U", why, c)
	}
	return nil
}
