#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Builds a release snapshot of maze with goreleaser and serves it from a local Homebrew tap, so a developer can
# install maze exactly the way a user does (`brew install --cask attention-span-ai/local/maze`) before any release
# exists. The cask is the one goreleaser generated, with its GitHub download URLs pointed at this checkout's
# dist/ instead; nothing is uploaded anywhere.
#
# Usage: scripts/maze-local-tap.sh            (then: brew install --cask attention-span-ai/local/maze)
#        after a code change, run it again     (then: brew reinstall --cask attention-span-ai/local/maze)
# Needs: goreleaser and brew on PATH (macOS).
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

command -v goreleaser >/dev/null || { echo "maze-local-tap: goreleaser is not on PATH (brew install goreleaser)" >&2; exit 2; }
command -v brew >/dev/null || { echo "maze-local-tap: brew is not on PATH" >&2; exit 2; }

goreleaser release --snapshot --clean
cask=dist/homebrew/Casks/maze.rb
[ -f "$cask" ] || { echo "maze-local-tap: goreleaser wrote no $cask" >&2; exit 1; }

brew tap-new --no-git attention-span-ai/local >/dev/null 2>&1 || true
tap="$(brew --repository)/Library/Taps/attention-span-ai/homebrew-local"
mkdir -p "$tap/Casks"
# Every download URL in the cask, whatever release path goreleaser templated, becomes this checkout's dist/.
sed -E "s#url \"https://[^\"]*/(maze_[^\"]*)\"#url \"file://$PWD/dist/\\1\"#" "$cask" >"$tap/Casks/maze.rb"
grep -q "file://$PWD/dist/" "$tap/Casks/maze.rb" || { echo "maze-local-tap: no URL was rewritten in $tap/Casks/maze.rb" >&2; exit 1; }

echo
echo "local tap ready: $tap/Casks/maze.rb"
echo "install as a user:   brew install --cask attention-span-ai/local/maze"
echo "after a rebuild:     brew reinstall --cask attention-span-ai/local/maze"
