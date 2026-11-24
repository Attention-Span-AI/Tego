#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Release-shaped local/CI mirror, never executed on the build host. The source
# checkout must contain the output so the real staging boundary can validate it.
set -euo pipefail
if [ "$#" -ne 1 ]; then echo "usage: $0 NEW_OUTPUT" >&2; exit 2; fi
root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"
export TEGO_FIXTURE_VERSION=${TEGO_FIXTURE_VERSION:-v0.2.0}
export TEGO_FIXTURE_PUBLIC_COMMIT=${TEGO_FIXTURE_PUBLIC_COMMIT:-$(git rev-parse HEAD)}
./test/vm/service-install-mirror.sh "$1"
release=$(cd "$1/$TEGO_FIXTURE_VERSION" && pwd)
case "$release/" in "$root/"*) ;; *) echo 'build fixture inside its source checkout for staging validation' >&2; exit 2;; esac
version=${TEGO_FIXTURE_VERSION#v}
for arch in amd64 arm64; do
    GOOS=windows GOARCH=$arch CGO_ENABLED=0 go build -p 2 -trimpath -buildmode=exe -ldflags '-s -w' -o "$release/tego_${version}_windows_${arch}.exe" ./cmd/tego-windows
done
python3 - "$release" <<'PYTHON'
import hashlib, importlib.util, json, pathlib, shutil, sys
root = pathlib.Path.cwd()
release = pathlib.Path(sys.argv[1])
# The shared Linux service fixture adds a test-only unit, not a release asset.
(release/'tego-agent@.service').unlink()
spec = importlib.util.spec_from_file_location('stage', root/'scripts/stage-release-assets.py')
stage = importlib.util.module_from_spec(spec)
spec.loader.exec_module(stage)
for name, source in stage.checksum_extra_files(root, root/'.goreleaser.yaml').items():
    shutil.copyfile(source, release/name)
assets = sorted(p for p in release.iterdir() if p.is_file() and p.name not in ('fixture.json','artifacts.json') and not p.name.endswith('_checksums.txt'))
(release/'artifacts.json').write_text(json.dumps([{'name':p.name,'path':str(p.relative_to(root))} for p in assets if p.name not in stage.checksum_extra_files(root,root/'.goreleaser.yaml')]))
sums = next(release.glob('*_checksums.txt'))
sums.write_text(''.join(hashlib.sha256(p.read_bytes()).hexdigest()+'  '+p.name+'\n' for p in assets))
stage.stage(sums, release.parent/'staged')
PYTHON
