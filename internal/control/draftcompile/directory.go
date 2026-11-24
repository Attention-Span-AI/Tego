// SPDX-License-Identifier: Apache-2.0

package draftcompile

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// DirectoryRequest describes the project folder and authority exclusions supplied by the service.
type DirectoryRequest struct {
	Typed, Home string
	Refuse      []string
}

// ProjectDirectory validates and canonicalizes a project path in a cancellable child.
func ProjectDirectory(ctx context.Context, req DirectoryRequest) (string, error) {
	r, err := Check(ctx, Request{Directory: &req})
	return r.Directory, err
}

func checkDirectory(req DirectoryRequest) Result {
	dir, problem := projectDirectory(req)
	return Result{Directory: dir, Error: problem}
}

func projectDirectory(req DirectoryRequest) (dir, problem string) {
	typed := req.Typed
	typed = strings.TrimSpace(typed)
	switch {
	case typed == "":
		return "", "Type the project folder: the folder the agent works in, where agent.yaml is written."
	case len(typed) > 4096 || strings.ContainsRune(typed, 0):
		return "", "That is not a folder path."
	case typed == "~" || strings.HasPrefix(typed, "~/"):
		h := req.Home
		if h == "" {
			return "", "This dashboard does not know your home folder: type the full path."
		}
		typed = filepath.Join(h, strings.TrimPrefix(strings.TrimPrefix(typed, "~"), "/"))
	case !filepath.IsAbs(typed):
		return "", fmt.Sprintf("Type the full path of the project folder (it starts with / or ~/), not %q.", typed)
	}
	dir, err := filepath.EvalSymlinks(filepath.Clean(typed))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", fmt.Sprintf("%s does not exist. Set up an agent in a project folder that exists: create it first.", typed)
		}
		return "", fmt.Sprintf("%s cannot be read: %v.", typed, err)
	}
	var st unix.Stat_t
	if err := unix.Stat(dir, &st); err != nil {
		return "", fmt.Sprintf("%s cannot be read: %v.", dir, err)
	}
	switch euid := uint32(os.Geteuid()); {
	case st.Mode&unix.S_IFMT != unix.S_IFDIR:
		return "", fmt.Sprintf("%s is not a folder.", dir)
	case st.Uid != euid:
		return "", fmt.Sprintf("%s is owned by uid %d, not by you (uid %d): set up an agent in a folder of your own.", dir, st.Uid, euid)
	case st.Mode&0o002 != 0 && st.Mode&unix.S_ISVTX == 0:
		return "", fmt.Sprintf("%s is writable by every user, so another user could swap the rules file: chmod o-w %s, or pick another folder.", dir, dir)
	}
	refuse := req.Refuse
	for _, r := range refuse {
		if r == "" {
			continue
		}
		rr := r
		if e, err := filepath.EvalSymlinks(r); err == nil {
			rr = e
		}
		if directoryWithin(dir, rr) {
			return "", fmt.Sprintf("%s is tego's own folder (the ledger root or tego's home, %s) or inside it: an agent's rules never live there. Pick the project folder.", dir, r)
		}
	}
	return dir, ""
}

func directoryWithin(path, parent string) bool {
	rel, err := filepath.Rel(parent, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, "../")
}
