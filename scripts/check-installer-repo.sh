#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# check-installer-repo.sh OWNER/REPO — scripts/install.sh names the repository a release is built in.
#
# install.sh downloads from, and holds the cosign certificate identity to, the repository named by its repo_owner
# and repo_name. A release signed by the workflow of another repository is refused by every installer (exit 9,
# or 5 when it finds no release), and release.yml's own verify step builds its identity from github.repository,
# so it cannot see the mismatch. release.yml runs this before it builds anything: a release from a repository
# the installer does not name stops there, with nothing published.
#
# Exit: 0 when they agree; 1 when they differ; 2 on a usage error.
set -eu

here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
want="${1:-}"
[ -n "$want" ] || { echo "usage: check-installer-repo.sh OWNER/REPO" >&2; exit 2; }
owner=$(sed -n 's/^repo_owner="\(.*\)"$/\1/p' "${INSTALLER:-$here/install.sh}")
name=$(sed -n 's/^repo_name="\(.*\)"$/\1/p' "${INSTALLER:-$here/install.sh}")
[ -n "$owner" ] && [ -n "$name" ] || { echo "check-installer-repo: install.sh has no repo_owner/repo_name" >&2; exit 2; }
if [ "$owner/$name" != "$want" ]; then
	echo "check-installer-repo: install.sh installs from and verifies ${owner}/${name}, but this release is built in ${want}; a release signed here is refused by the installer. Move the repository or change install.sh's repo_owner/repo_name (and install_test.sh) first." >&2
	exit 1
fi
echo "check-installer-repo: install.sh names ${want}"
