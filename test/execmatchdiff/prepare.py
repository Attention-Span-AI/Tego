#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Build a private, disposable base-package import and instrumentation overlay."""
import json
import pathlib
import subprocess
import sys

repo = pathlib.Path.cwd()
if sys.argv[1:] == ['--verify']:
    prefix = 'github.com/attention-span-ai/tego/pkg/policy/execmatch'
    target_prefix = 'github.com/attention-span-ai/tego/test/execmatchdiff/internal/baseline'
    names = subprocess.check_output(['/usr/bin/git', 'ls-tree', '-r', '--name-only', '70a9e8c56', 'pkg/policy/execmatch'], text=True).splitlines()
    checked = 0
    for name in names:
        if not name.endswith('.go') or name.endswith('_test.go'):
            continue
        expected = subprocess.check_output(['/usr/bin/git', 'show', '70a9e8c56:' + name]).replace(prefix.encode(), target_prefix.encode())
        copied = repo / 'test/execmatchdiff/internal/baseline' / name.removeprefix('pkg/policy/execmatch/')
        if copied.read_bytes() != expected:
            raise SystemExit('baseline differs: ' + str(copied))
        checked += 1
    if checked != 20:
        raise SystemExit(f'unexpected frozen source count: {checked}')
    print(f'baseline byte verification: {checked} files match 70a9e8c56 after import rewrite')
    raise SystemExit(0)

out = pathlib.Path(sys.argv[1]).resolve()
base = sys.argv[2]
out.mkdir(parents=True, exist_ok=True)
module = 'github.com/attention-span-ai/tego/execmatchbaseline'
for name in subprocess.check_output(['/usr/bin/git', 'ls-tree', '-r', '--name-only', base, 'pkg/policy/execmatch'], text=True).splitlines():
    if not name.endswith('.go') or name.endswith('_test.go') and not name.endswith('/export_test.go'):
        continue
    rel = name.removeprefix('pkg/policy/execmatch/')
    if rel == 'export_test.go':
        rel = 'testbridge.go'
    target = out / 'base' / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    data = subprocess.check_output(['/usr/bin/git', 'show', f'{base}:{name}'], text=True)
    target.write_text(data.replace('github.com/attention-span-ai/tego/pkg/policy/execmatch', module))
(out / 'base/comparison_bridge.go').write_text("""// SPDX-License-Identifier: Apache-2.0
package execmatch

// AllInterpretationsForComparison exposes existing private deny-only multicall
// readings to the disposable observer. It changes no parser or decision code.
func (ix *Index) AllInterpretationsForComparison(f *Facts) []Invocation {
    invs := ix.Interpretations(f)
    return append(invs, ix.multicallInterpretations(f, invs)...)
}
""")
(out / 'base/go.mod').write_text(f'module {module}\n\ngo 1.27\n')
mod = (repo / 'go.mod').read_text() + f'\nrequire {module} v0.0.0\nreplace {module} => {out / "base"}\n'
(out / 'go.mod').write_text(mod)
index = (repo / 'pkg/policy/execmatch/index.go').read_text()
index = index.replace('func (ix *Index) Decide(f *Facts) Result {', 'func (ix *Index) Decide(f *Facts) (result Result) {\n defer func() { tighteningObserve(ix, f, result) }()')
(out / 'index.go').write_text(index)
overlay = {str(repo / 'go.mod'): str(out / 'go.mod'), str(repo / 'pkg/policy/execmatch/index.go'): str(out / 'index.go')}
for dest, source in [('pkg/policy/execmatch/terminator_observe.go', 'observer.go.txt'),
                     ('pkg/policy/execmatch/terminator_compare_test.go', 'generated_test.go.txt'),
                     ('pkg/policy/execmatch/terminator_observer_internal_test.go', 'observer_internal_test.go.txt'),
                     ('pkg/policy/execmatch/rows/terminator_compare_test.go', 'rowmain_test.go.txt')]:
    overlay[str(repo / dest)] = str(repo / 'test/execmatchdiff' / source)
(out / 'overlay.json').write_text(json.dumps({'Replace': overlay}))
print(out / 'overlay.json')
