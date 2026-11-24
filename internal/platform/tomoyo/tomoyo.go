// SPDX-License-Identifier: Apache-2.0

package tomoyo

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/attention-span-ai/tego/internal/platform/kernelconfig"
	"github.com/attention-span-ai/tego/internal/platform/sys"
	"golang.org/x/sys/unix"
)

const (
	// dir holds TOMOYO's securityfs files.
	dir        = "/sys/kernel/security/tomoyo/"
	selfDomain = "/sys/kernel/security/tomoyo/self_domain"
	stat       = "/sys/kernel/security/tomoyo/stat"
	profile    = "/sys/kernel/security/tomoyo/profile"
	limit      = 64 * 1024
)

// ReadFile reads one of TOMOYO's securityfs files, bounded without silently truncating it, and only from a descriptor
// that sits on securityfs (CheckSecurityfs): a mount namespace that shows another filesystem at /sys/kernel/security
// does not get to say what TOMOYO's profile is.
func ReadFile(path string) ([]byte, error) {
	return readBounded(path, true)
}

// readBounded is ReadFile with the securityfs check optional (the bound's own test reads a file anywhere).
func readBounded(path string, onSecurityfs bool) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	if onSecurityfs {
		if err := checkOpened(path, f); err != nil {
			return nil, err
		}
	}
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err == nil && len(b) > limit {
		err = errors.New("LSM fact exceeds 64 KiB")
	}
	return b, err
}

// CheckSecurityfs refuses an open file that is not on securityfs (fstatfs magic SECURITYFS_MAGIC). The profile, the
// update line and the domain are TOMOYO's own files there; whoever controls the launcher's mount namespace can show
// any file at the same path, and a profile read from it would prove nothing.
func CheckSecurityfs(f *os.File) error {
	typ, err := statfsType(f)
	if err != nil {
		return fmt.Errorf("TOMOYO fact %s: cannot tell what filesystem it is on: %w", f.Name(), err)
	}
	if typ != uint32(unix.SECURITYFS_MAGIC) {
		return fmt.Errorf("TOMOYO fact %s is not on securityfs (filesystem type %#x); held file opens are refused on this machine", f.Name(), typ)
	}
	return nil
}

// statfsType is f's filesystem magic (fstatfs); a variable so tests can stand in for securityfs without root.
var statfsType = func(f *os.File) (uint32, error) {
	var st unix.Statfs_t
	if err := sys.FileDo(f, func(fd int) error { return unix.Fstatfs(fd, &st) }); err != nil {
		return 0, err
	}
	return uint32(st.Type), nil
}

// CheckFact is CheckSecurityfs for an open file that is at path when path is one of TOMOYO's securityfs files: a reader
// that serves other modules' files too calls it for each file it opens and passes the rest.
func CheckFact(path string, f *os.File) error {
	if cfg, _ := currentFacts(); cfg != "" && strings.HasPrefix(path, cfg+"/") {
		return checkFactsDirFile(path, cfg, f)
	}
	if !strings.HasPrefix(path, dir) {
		return nil
	}
	return CheckSecurityfs(f)
}

// Check reads the checking thread's domain and policy-update line afresh, and, where the update counter has moved or
// the kernel's build omits the userspace loader, the whole of TOMOYO's profile between two reads of that line (a
// thread that can open it, which is root in the initial user namespace). No policy observation is kept between checks
// or runs (ADR 0041).
func Check(read func(string) ([]byte, error)) error {
	_, err := CheckVia(read)
	return err
}

// CheckVia is Check that also says how an admission was reached: viaProfile is true when the counter had moved (or the
// loader is omitted) and a fresh read of the profile proved that nothing enforces, false for the never-updated line.
func CheckVia(read func(string) ([]byte, error)) (viaProfile bool, err error) {
	return check(factsRead(read), omittedLoader())
}

// Only the running kernel's immutable build configuration is cached.
var omittedLoader = newLoaderOmission(unix.Uname, kernelconfig.Read)

func newLoaderOmission(uname func(*unix.Utsname) error, read func(string) (map[string]bool, bool)) func() string {
	var mu sync.Mutex
	var definite bool
	var source string
	return func() string {
		mu.Lock()
		defer mu.Unlock()
		if definite {
			return source
		}
		paths := []string{"/proc/config.gz"}
		var u unix.Utsname
		if uname(&u) == nil {
			paths = kernelconfig.Paths(unix.ByteSliceToString(u.Release[:]))
		}
		source, definite = loaderOmission(paths, read)
		return source
	}
}

// SetLoaderOmissionForTest replaces the build-configuration observation and returns
// its restore function. Tests using it must not run in parallel.
func SetLoaderOmissionForTest(load func() string) func() {
	original := omittedLoader
	omittedLoader = load
	return func() { omittedLoader = original }
}

func loaderOmission(paths []string, read func(string) (map[string]bool, bool)) (string, bool) {
	readable := false
	for _, path := range paths {
		if cfg, ok := read(path); ok {
			readable = true
			if cfg["CONFIG_SECURITY_TOMOYO_OMIT_USERSPACE_LOADER"] {
				return path, true
			}
		}
	}
	return "", readable
}

// rootTierNote ends the refusal of a thread that cannot prove nothing enforces (SEC08b): tier landlock runs as the
// invoking user, to whom TOMOYO's profile is closed.
const rootTierNote = "; a root tier can prove nothing is enforced, and this tier cannot read TOMOYO's profile"

// check decides one held open's TOMOYO fact. The first read of the update line decides which proof applies: the
// never-updated line (the loader's omission aside) is the stateless proof of ADR 0041, anything else a counter an
// unprivileged process may have moved (a program started as /sbin/modprobe in a mount namespace of its own makes a
// domain), which the profile proof of SEC08b answers where this thread can read the profile.
func check(read func(string) ([]byte, error), omittedSource string) (viaProfile bool, err error) {
	for attempt := 1; ; attempt++ {
		viaProfile, err = checkOnce(read, omittedSource)
		var moved *profileMoved
		if !errors.As(err, &moved) {
			return viaProfile, err
		}
		// A counted update landed between the two reads of the update line (a learning-mode machine counts every ACL
		// entry it learns). Each attempt is the whole bracketed proof, from a fresh first read; the open is refused only
		// when no attempt was clean.
		if attempt == proofAttempts {
			return false, fmt.Errorf("%w in each of %d attempts", err, proofAttempts)
		}
		time.Sleep(retryPause)
	}
}

// proofAttempts is how many whole bracketed proofs one check makes before it refuses a profile that kept changing under
// it, and retryPause the wait between two of them (a var so tests do not wait).
const proofAttempts = 3

var retryPause = 3 * time.Millisecond

// checkOnce is one attempt of check: one read of the update line decides the proof, and a profile proof ends in its own
// second read of that line.
func checkOnce(read func(string) ([]byte, error), omittedSource string) (viaProfile bool, err error) {
	data, statErr := read(stat)
	if statErr == nil && len(data) <= limit {
		if line, _, terminated := strings.Cut(string(data), "\n"); terminated {
			switch {
			case line+"\n" != neverUpdated && isUpdatedLine(line), line+"\n" == neverUpdated && omittedSource != "":
				err := profileProof(read, line)
				var unread *profileUnread
				switch {
				case err == nil:
					return true, nil
				case errors.As(err, &unread):
					return false, checkStateless(read, data, statErr, omittedSource, unread.err)
				}
				return false, err
			}
		}
	}
	return false, checkStateless(read, data, statErr, omittedSource, nil)
}

// neverUpdated is common.c:tomoyo_read_stat's never-updated line, including its padding and newline, captured in
// Debian 13 as 49 bytes.
const neverUpdated = "Policy update:                                 0\n"

// profileProof is SEC08b: with the update line first as first, it reads the whole profile to its end within 64 KiB and
// the update line again, and admits only when the two lines are byte-equal, every profile line parses in the kernel's
// printed grammar, and no mode in any namespace, profile or category is enforcing (the only mode that denies:
// tomoyo_supervisor). It returns nil for an admission. A thread that cannot read the profile gets a *profileUnread,
// and the caller keeps the counter's refusal; every other failure is the refusal itself.
func profileProof(read func(string) ([]byte, error), first string) error {
	prof, err := read(profile)
	if err != nil {
		return &profileUnread{fmt.Errorf("TOMOYO %s: %w", profile, err)}
	}
	if len(prof) > limit {
		return fmt.Errorf("TOMOYO profile %s exceeds 64 KiB", profile)
	}
	if err := parseProfile(prof); err != nil {
		return err
	}
	again, err := read(stat)
	if err != nil {
		return fmt.Errorf("TOMOYO %s: %w", stat, err)
	}
	if len(again) > limit {
		return fmt.Errorf("TOMOYO stat %s exceeds 64 KiB", stat)
	}
	second, _, terminated := strings.Cut(string(again), "\n")
	if !terminated || second != first {
		return &profileMoved{}
	}
	return nil
}

// profileMoved is a profile read the update line did not bracket: the line differed before and after it.
type profileMoved struct{}

func (*profileMoved) Error() string {
	return "TOMOYO's policy changed while its profile was read; held file opens are refused on this machine for this open"
}

// profileUnread is a profile this thread could not read: the proof was not made, and the refusal is the counter's.
type profileUnread struct{ err error }

func (u *profileUnread) Error() string { return u.err.Error() }
func (u *profileUnread) Unwrap() error { return u.err }

var (
	profileVersionLine = regexp.MustCompile(`^PROFILE_VERSION=[0-9]+$`)
	profileCommentLine = regexp.MustCompile(`^[0-9]{1,3}-COMMENT=`)
	profilePrefLine    = regexp.MustCompile(`^[0-9]{1,3}-PREFERENCE=\{ ([a-z_]+=[0-9]+ )*\}$`)
	profileConfigLine  = regexp.MustCompile(`^([0-9]{1,3})-CONFIG(?:::[a-z0-9_]+(?:::[a-z0-9_]+)?)?=\{ mode=([a-z]+) grant_log=(?:yes|no) reject_log=(?:yes|no) \}$`)
)

// parseProfile reads common.c:tomoyo_read_profile's output strictly: each line is, after an optional "<namespace> ",
// PROFILE_VERSION=N, N-COMMENT=text, N-PREFERENCE={ key=N ... } or N-CONFIG[::category[::operation]]={ mode=M
// grant_log=yes|no reject_log=yes|no }, every byte printable ASCII (the kernel prints a comment's own escapes as text,
// never a line break), M one of disabled, learning, permissive, and the data ending in a line break. Anything else, the
// mode enforcing in particular, is an error: the proof never guesses at a line it does not know.
func parseProfile(b []byte) error {
	bad := func(why string) error {
		return fmt.Errorf("TOMOYO profile %s has %s; held file opens are refused on this machine", profile, why)
	}
	if len(b) == 0 || b[len(b)-1] != '\n' {
		return bad("no complete text")
	}
	versions := 0
	for _, line := range strings.Split(string(b[:len(b)-1]), "\n") {
		for i := 0; i < len(line); i++ {
			if line[i] < 0x20 || line[i] > 0x7e {
				return bad("a line with a control or non-ASCII byte")
			}
		}
		rest := line
		if strings.HasPrefix(rest, "<") {
			name, after, ok := strings.Cut(rest, " ")
			if !ok || len(name) < 3 || !strings.HasSuffix(name, ">") {
				return bad("a line this check does not parse")
			}
			rest = after
		}
		switch {
		case profileVersionLine.MatchString(rest):
			versions++
		case profileCommentLine.MatchString(rest), profilePrefLine.MatchString(rest):
		default:
			m := profileConfigLine.FindStringSubmatch(rest)
			if m == nil {
				return bad("a line this check does not parse")
			}
			switch m[2] {
			case "disabled", "learning", "permissive":
			case "enforcing":
				return fmt.Errorf("TOMOYO profile %s enforces (profile %s is in mode enforcing); held file opens are refused on this machine", profile, m[1])
			default:
				return bad("a mode this check does not know")
			}
		}
	}
	if versions == 0 {
		return bad("no PROFILE_VERSION line")
	}
	return nil
}

// checkStateless is the never-updated line's proof (ADR 0041) over the update line this check read (data, statErr): the
// thread's domain is the initial one, the update line is the never-updated line, and the loader is not omitted. unreadable, when set, is why the profile proof could not
// be tried, and ends the refusals that proof would have answered.
func checkStateless(read func(string) ([]byte, error), data []byte, statErr error, omittedSource string, unreadable error) error {
	domain, domainErr := read(selfDomain)
	if domainErr != nil {
		return fmt.Errorf("TOMOYO %s: %w", selfDomain, domainErr)
	}
	s := strings.TrimSuffix(strings.TrimSuffix(string(domain), "\x00"), "\n")
	if len(domain) > limit || s == "" || strings.ContainsAny(s, "\x00\n") {
		return fmt.Errorf("TOMOYO self_domain %s is empty, malformed or exceeds 64 KiB", selfDomain)
	}
	if s != "<kernel>" {
		return fmt.Errorf("TOMOYO observed domain %q prevents held file opens", s)
	}
	if statErr != nil {
		return fmt.Errorf("TOMOYO %s: %w", stat, statErr)
	}
	if len(data) > limit {
		return fmt.Errorf("TOMOYO stat %s exceeds 64 KiB", stat)
	}
	line, _, terminated := strings.Cut(string(data), "\n")
	if !terminated {
		return fmt.Errorf("TOMOYO stat %s has a missing or malformed Policy update: line", stat)
	}
	// The sole accepted line is the never-updated format.
	if line+"\n" != neverUpdated {
		if isUpdatedLine(line) {
			return errors.New("TOMOYO's policy has been updated since boot; held file opens are refused on this machine until TOMOYO is unused again after a restart" + whyUnproved(unreadable))
		}
		return fmt.Errorf("TOMOYO stat %s has a missing or malformed Policy update: line", stat)
	}
	if omittedSource != "" {
		return fmt.Errorf("TOMOYO %s reads CONFIG_SECURITY_TOMOYO_OMIT_USERSPACE_LOADER=y; its built-in policy can enforce without a counted update; held file opens are refused on this machine; use a kernel without this option%s", omittedSource, whyUnproved(unreadable))
	}
	return nil
}

// whyUnproved says why the profile proof was not made: the thread may not read it (tier landlock), or the read failed.
func whyUnproved(unreadable error) string {
	switch {
	case unreadable == nil:
		return ""
	case errors.Is(unreadable, fs.ErrPermission):
		return rootTierNote
	}
	return "; its profile could not be read (" + unreadable.Error() + ")"
}

// Used only to explain a refusal; recognizing an update never grants an open.
var updatedLine = regexp.MustCompile(`^Policy update: +([0-9]+)(?: \(Last: ([0-9]{4}/[0-9]{2}/[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2})\))?$`)

func isUpdatedLine(line string) bool {
	m := updatedLine.FindStringSubmatch(line)
	if m == nil {
		return false
	}
	count, err := strconv.ParseUint(m[1], 10, 32)
	if err != nil {
		return false
	}
	expected := fmt.Sprintf("Policy %-30s %10d", "update:", count)
	if m[2] != "" {
		if _, err := time.Parse("2006/01/02 15:04:05", m[2]); err != nil {
			return false
		}
		expected += " (Last: " + m[2] + ")"
	}
	return expected == line && (count != 0 || m[2] != "")
}
