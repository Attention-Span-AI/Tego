// SPDX-License-Identifier: Apache-2.0

package scope

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// The pre-push check. When the person pushes, git runs .git/hooks/pre-push; Maze's hook lists the
// commits in the push that Claude Code made (by the agent's email) and asks before they leave. The agent
// can't remove it: the engine's built-in rules protect .git/hooks. The hook is plain sh and runs only git, so it
// works without Maze on PATH. A pre-push hook the person already had keeps running: it is moved aside and Maze's
// hook runs it after its own check.
const (
	hookMark    = "# maze-pre-push"
	chainedHook = "pre-push.before-maze"
)

// prePushScript is the hook. It reads the refs git is pushing and collects the commits in them that the agent
// authored or committed. It fails closed: when the remote's tip isn't known here (a force push over
// commits never fetched) it checks everything not yet on any remote, and when git can't list the commits it
// stops the push. With such commits it asks on the terminal; without a terminal (a GUI client, CI) it stops,
// unless MAZE_ALLOW_AGENT_PUSH is set, because pushing unreviewed agent commits by accident is what it exists to
// stop. A pre-push hook the person had before runs after it.
var prePushTemplate = `#!/bin/sh
` + hookMark + ` (added by maze; maze workspace remove takes it out)
# Asks before you push commits Claude Code made under Maze. Your own commits pass untouched.
refs=$(cat)
remote="$1"
zero=0000000000000000000000000000000000000000
agent='` + AgentEmail + `'
key='@@KEY@@'
signers='@@SIGNERS@@'
found=""
while read -r local_ref local_sha remote_ref remote_sha; do
  [ -z "$local_sha" ] && continue
  case "$local_sha" in 0000000*) continue ;; esac
  if [ "$remote_sha" = "$zero" ] || ! git cat-file -e "$remote_sha^{commit}" 2>/dev/null; then
    range="$local_sha --not --remotes"
  else
    range="$remote_sha..$local_sha"
  fi
  # shellcheck disable=SC2086
  # Each commit with its author, committer and the key that signed it: a commit signed with the agent's key is the
  # agent's whatever name it carries.
  if ! log=$(git -c gpg.ssh.allowedSignersFile="$signers" log --format='%h%x09%ae%x09%ce%x09%GF%x09%s' $range 2>/dev/null); then
    echo "maze: couldn't check this push for Claude Code's commits. Run git fetch, then push again." >&2
    exit 1
  fi
  commits=$(printf '%s\n' "$log" | awk -F '\t' -v a="$agent" -v k="$key" 'tolower($2) == a || tolower($3) == a || (k != "" && $4 == k) { print "  " $1 " " $5 }')
  [ -n "$commits" ] && found="$found$commits
"
done <<EOF
$refs
EOF
found=$(printf '%s' "$found" | awk 'NF && !seen[$0]++')
if [ -n "$found" ]; then
  echo "maze: this push has commits Claude Code made:" >&2
  printf '%s\n' "$found" >&2
  case "$MAZE_ALLOW_AGENT_PUSH" in
  1 | true | yes) echo "maze: pushing them (MAZE_ALLOW_AGENT_PUSH)." >&2 ;;
  *)
    # A subshell, because a failed redirection of ':' (a special builtin) exits dash and bash --posix on the spot,
    # which stopped the push without saying why.
    if ( : > /dev/tty ) 2>/dev/null; then
      printf 'Push them to %s? [y/N] ' "$remote" > /dev/tty
      read -r answer < /dev/tty || answer=n
      case "$answer" in
        y | Y | yes | YES) ;;
        *) echo "maze: push stopped. Nothing was sent." >&2; exit 1 ;;
      esac
    else
      echo "maze: push stopped: there's no terminal to ask you in. Push from a terminal to review them." >&2
      exit 1
    fi
    ;;
  esac
fi
before="$(dirname "$0")/` + chainedHook + `"
if [ "$(basename "$0")" = pre-push ] && [ -x "$before" ]; then
  printf '%s\n' "$refs" | "$before" "$@"
  exit $?
fi
exit 0
`

// prePushScript is the hook for this person: it knows the agent's key by its fingerprint (when the key exists)
// and where its allowed-signers file is, so git can name the key each commit was signed with.
func prePushScript(home string) string {
	k := AgentKeyPaths(home)
	return strings.NewReplacer("@@KEY@@", keyFingerprint(k.Public), "@@SIGNERS@@", k.AllowedSigners).Replace(prePushTemplate)
}

// keyFingerprint is an SSH public key's fingerprint as ssh-keygen and git print it (SHA256:…), or "".
func keyFingerprint(pubPath string) string {
	data, ok, err := readFile(pubPath)
	if err != nil || !ok {
		return ""
	}
	f := strings.Fields(string(data))
	if len(f) < 2 {
		return ""
	}
	blob, err := base64.StdEncoding.DecodeString(f[1])
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(blob)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}

// HookResult says what InstallPrePush did, for the line after saving.
type HookResult struct {
	// Installed is true when Maze's hook is in place (new, or updated).
	Installed bool
	// Chained is true when the person's own pre-push hook was kept and runs after Maze's.
	Chained bool
	// Skipped says why no hook was installed, in plain words, or "".
	Skipped string
	// Helper, when git runs hooks from elsewhere (husky), is the line that runs Maze's check from the person's
	// own pre-push hook; the check itself is installed beside git's hooks as maze-pre-push.
	Helper string
}

// helperHook is where the check goes when git runs hooks from another folder.
const helperHook = "maze-pre-push"

// InstallPrePush puts Maze's pre-push hook in the project's .git/hooks. It is skipped, and says why, where git
// wouldn't run it: no .git folder (not a repo, or a worktree), or core.hooksPath pointing elsewhere (husky), set
// in the repo or in the person's git config under home.
func InstallPrePush(home, root string) (HookResult, error) {
	gitDir := filepath.Join(root, ".git")
	fi, err := os.Lstat(gitDir)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return HookResult{Skipped: "not a git repo"}, nil
	case err != nil:
		return HookResult{}, err
	case !fi.IsDir():
		return HookResult{Skipped: "this is a git worktree, and the check comes later for worktrees"}, nil
	}
	if err := realDirs(root, ".git/hooks"); err != nil {
		return HookResult{Skipped: err.Error()}, nil
	}
	hooks := filepath.Join(gitDir, "hooks")
	for _, config := range []string{filepath.Join(gitDir, "config"), filepath.Join(home, ".gitconfig"), filepath.Join(home, ".config", "git", "config")} {
		if p, err := hooksPath(config); err != nil {
			return HookResult{}, err
		} else if p != "" {
			if err := writeFile(filepath.Join(hooks, helperHook), []byte(prePushScript(home)), 0o755, 0o755); err != nil {
				return HookResult{}, err
			}
			return HookResult{
				Skipped: "git runs hooks from " + p + " (core.hooksPath)",
				// Safe in a worktree (the common git dir), a no-op once Maze is removed, and it stops the push when
				// the check does, even in a hook not run with sh -e.
				Helper: `h="$(git rev-parse --git-common-dir)/hooks/` + helperHook + `"; [ ! -f "$h" ] || sh "$h" "$@" || exit 1`,
			}, nil
		}
	}
	hook := filepath.Join(hooks, "pre-push")
	if fi, err := os.Lstat(hook); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		return HookResult{Skipped: ".git/hooks/pre-push is a link, so Maze left it alone"}, nil
	}
	res := HookResult{Installed: true}
	current, exists, err := readFile(hook)
	if err != nil {
		return HookResult{}, err
	}
	if exists && !bytes.Contains(current, []byte(hookMark)) {
		before := filepath.Join(hooks, chainedHook)
		if _, err := os.Lstat(before); err == nil {
			return HookResult{}, errors.New(".git/hooks/" + chainedHook + " already exists; Maze won't overwrite it")
		}
		if err := os.Rename(hook, before); err != nil {
			return HookResult{}, err
		}
	}
	if _, err := os.Lstat(filepath.Join(hooks, chainedHook)); err == nil {
		res.Chained = true
	}
	return res, writeFile(hook, []byte(prePushScript(home)), 0o755, 0o755)
}

// RemovePrePush takes Maze's hook (and the helper used with core.hooksPath) out and puts back the one it ran
// after, if any.
func RemovePrePush(root string) error {
	hooks := filepath.Join(root, ".git", "hooks")
	if err := os.Remove(filepath.Join(hooks, helperHook)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	hook := filepath.Join(hooks, "pre-push")
	current, exists, err := readFile(hook)
	if err != nil || !exists || !bytes.Contains(current, []byte(hookMark)) {
		return err
	}
	if err := os.Remove(hook); err != nil {
		return err
	}
	before := filepath.Join(hooks, chainedHook)
	if _, err := os.Lstat(before); err == nil {
		return os.Rename(before, hook)
	}
	return nil
}

// hooksPath reads core.hooksPath from a git config file, or "" when it isn't set or there's no file. It reads the
// file directly, so no git process is started.
func hooksPath(config string) (string, error) {
	data, ok, err := readFile(config)
	if err != nil || !ok {
		return "", err
	}
	section := ""
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "[") {
			section = strings.ToLower(strings.Trim(line, "[] "))
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if ok && section == "core" && strings.EqualFold(strings.TrimSpace(key), "hookspath") {
			return strings.Trim(strings.TrimSpace(value), `"`), nil
		}
	}
	return "", sc.Err()
}

// HooksPath is where git runs this project's hooks from when core.hooksPath is set (in the repo's config or the
// person's), or "".
func HooksPath(home, root string) string {
	for _, config := range []string{filepath.Join(root, ".git", "config"), filepath.Join(home, ".gitconfig"), filepath.Join(home, ".config", "git", "config")} {
		if p, err := hooksPath(config); err == nil && p != "" {
			return p
		}
	}
	return ""
}
