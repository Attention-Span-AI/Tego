// SPDX-License-Identifier: Apache-2.0

package runact

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/askclient"
	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/pkg/spec/askproto"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// ErrBadAlternate is a stand-in path the dashboard refuses before any request is answered: not absolute, not clean,
// too long, with a control character or a symbolic link on the way, or not an existing regular file. The request
// stays pending.
var ErrBadAlternate = errors.New("invalid stand-in file")

// altFile is the stand-in held by descriptor from the moment it is opened (askclient.Descriptor).
type altFile struct{ f *sys.FD }

// Control lends the descriptor for fn's duration (sys.FD.Borrow).
func (a altFile) Control(fn func(fd int) error) error { return a.f.Borrow(fn) }

// openAlternate is internal/runtime/ask.OpenAlternateFile, which tego-control may not link: O_PATH, the final
// component not followed, openat2 RESOLVE_NO_SYMLINKS|RESOLVE_NO_MAGICLINKS, a regular file, and the kernel's name
// for the descriptor as the name the broker is given. Unlike the CLI, the path must be absolute: the dashboard has
// no working directory the person chose.
func openAlternate(path string) (altFile, string, error) {
	if !filepath.IsAbs(path) || len(path) > askproto.MaxAlternate || !askproto.ValidAlternate(path) {
		return altFile{}, "", fmt.Errorf("%w: %s: name a file by an absolute, clean path of at most %d bytes with no control character", ErrBadAlternate, strconv.Quote(path), askproto.MaxAlternate)
	}
	var f *sys.FD
	var err error
	for tries := 0; ; tries++ {
		f, err = sys.Own(unix.Openat2(unix.AT_FDCWD, path, &unix.OpenHow{Flags: unix.O_PATH | unix.O_NOFOLLOW | unix.O_CLOEXEC,
			Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS}))
		if (err == unix.EAGAIN && tries < 8) || err == unix.EINTR {
			continue
		}
		break
	}
	var st unix.Stat_t
	named := ""
	if err == nil {
		err = f.Borrow(func(fd int) error {
			if e := unix.Fstat(fd, &st); e != nil {
				return e
			}
			if st.Mode&unix.S_IFMT == unix.S_IFLNK {
				return unix.ELOOP // O_NOFOLLOW with O_PATH opens a final symbolic link itself
			}
			n, e := os.Readlink("/proc/self/fd/" + strconv.Itoa(fd))
			named = n
			return e
		})
		if err != nil {
			_ = f.Close()
		}
	}
	if errors.Is(err, unix.ELOOP) {
		hint := ""
		if real, e := filepath.EvalSymlinks(path); e == nil && real != path {
			hint = " (it resolves to " + strconv.Quote(real) + " now; check that file, then name it)"
		}
		return altFile{}, "", fmt.Errorf("%w: %s: name it by a path with no symbolic link in it%s", ErrBadAlternate, strconv.Quote(path), hint)
	}
	if err != nil {
		return altFile{}, "", fmt.Errorf("%w: %s: %v", ErrBadAlternate, strconv.Quote(path), err)
	}
	a := altFile{f}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		_ = a.f.Close()
		return altFile{}, "", fmt.Errorf("%w: %s: not a regular file", ErrBadAlternate, strconv.Quote(path))
	}
	if !askproto.ValidAlternate(named) {
		_ = a.f.Close()
		return altFile{}, "", fmt.Errorf("%w: %s: its path cannot be shown to a person", ErrBadAlternate, strconv.Quote(path))
	}
	return a, named, nil
}

// Alternate answers the held file open askID of run with the stand-in file at path, as
// `tego alternate <run> <ask_id> --file <path> [--always]` does (ADR 0057): the file is opened only now, after the
// run and ask checks passed, and handed to the broker by descriptor.
func Alternate(ctx context.Context, root, run, askID, path string, always bool) (Answered, error) {
	dir, err := runDir(root, run)
	if err != nil {
		return Answered{}, err
	}
	if !askproto.ValidID(askID) {
		return Answered{}, ErrBadAsk
	}
	if !filepath.IsAbs(path) || !askproto.ValidAlternate(path) {
		_, _, err = openAlternate(path)
		return Answered{}, err
	}
	target, err := askclient.Launcher(dir)
	if err != nil {
		return Answered{}, err
	}
	defer func() { _ = target.Close() }()
	alt, named, err := openAlternate(path)
	if err != nil {
		return Answered{}, err
	}
	defer func() { _ = alt.f.Close() }()
	d, err := askclient.Alternate(ctx, dir, target.PID(), askID, named, alt, always)
	if err != nil {
		return Answered{}, err
	}
	return Answered{Run: run, Decision: d, Word: alternateWord(d, always)}, nil
}

// endedFirst ends the word for an always answer that stands although the request it answered ended after the
// answer line was recorded (internal/cli's endedFirst).
const endedFirst = "this request itself ended after your answer was recorded, so its operation was refused"

// alternateWord is internal/cli's alternateWord.
func alternateWord(d askproto.Decision, asked bool) string {
	switch {
	case d.Alternate == "" && d.Always:
		return "recorded, and gives the file for every later request for the same operation, rule and target in this run; " + endedFirst
	case d.Alternate == "" && d.Reason == reasonTimeout:
		return "not given: the hold timed out first, so the operation was refused"
	case d.Alternate == "":
		return "not given: the answer could not be kept (the run ended, was cancelled, or its ledger refused the line), so the operation was refused"
	}
	word := "gave " + record.Printable(d.Alternate) + " in place of the file the agent asked for"
	switch {
	case d.Always:
		word += ", and gives it again for every later request for the same operation, rule and target in this run"
	case asked:
		word += ", for this request only: the answer could not be made to stand for later requests"
	}
	return word
}
