#!/usr/bin/python3
# SPDX-License-Identifier: Apache-2.0
"""Stage the installed sudo-rs and PAM dependencies for the later guest only.

Usage: python3 -I contracts-stage-sudo.py OUTPUT_DIRECTORY
Reads trusted installed ELF files with ldd; does not execute sudo or alter the host.
"""

import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys


def main(destination):
    sudo = Path('/usr/bin/sudo').resolve(strict=True)
    if '/cargo/' not in str(sudo):
        sys.exit('this kit stages installed sudo-rs; use a full distro guest for another sudo implementation')
    pam = Path('/usr/lib/x86_64-linux-gnu/security/pam_permit.so').resolve(strict=True)
    destination.mkdir()  # Refuse stale staging evidence.
    files, queue = {}, [(sudo, Path('/usr/bin/sudo')), (pam, pam)]
    while queue:
        source, target = queue.pop()
        source = source.resolve(strict=True)
        if str(target) in files:
            continue
        if source.read_bytes()[:4] != b'\x7fELF':
            raise ValueError(f'not an installed ELF image: {source}')
        output = subprocess.run(['/usr/bin/ldd', str(source)], check=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True).stdout
        if 'not found' in output:
            raise ValueError(output)
        for path in re.findall(r'(?:=>\s+|^\s*)(/\S+)', output, re.MULTILINE):
            library = Path(path)
            resolved = library.resolve(strict=True)
            if resolved != source:
                queue.append((resolved, library))  # Keep the loader's SONAME pathname.
        staged = destination / str(target).lstrip('/')
        staged.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, staged)
        mode = 0o755 if target == Path('/usr/bin/sudo') else source.stat().st_mode & 0o777
        staged.chmod(mode)  # Only guest root sets the sudo setuid bit.
        files[str(target)] = dict(source=str(source), mode=mode,
                                  sha256=hashlib.sha256(staged.read_bytes()).hexdigest())
    (destination / 'manifest.json').write_text(json.dumps(files, indent=2) + '\n')
    print(json.dumps(files, indent=2))


if __name__ == '__main__':
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    main(Path(sys.argv[1]).absolute())
