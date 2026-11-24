#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Fetch pinned test tools into an explicit scratch directory; install nothing."""
import hashlib
from pathlib import Path
import sys
import tarfile
import urllib.request
import zipfile

TOOLS = [
 ('https://github.com/PowerShell/PowerShell/releases/download/v7.7.0/powershell-7.7.0-linux-x64.tar.gz', 'c89d9c682d2c403dfe726f3df948e359675235a5bd6fab535776de69729ca0cb', 'pwsh'),
 ('https://github.com/PowerShell/PSScriptAnalyzer/releases/download/1.25.0/PSScriptAnalyzer.1.25.0.nupkg', '14e634c828eb98efb9f40b2918ba90f139ed5eccdf663a2a747736d996995d60', 'modules/PSScriptAnalyzer/1.25.0'),
 # Gallery's published SHA512 was independently verified before pinning this SHA256.
 ('https://www.powershellgallery.com/api/v2/package/Pester/5.7.1', '4a27904c6814a5fbe4758f8e49861f6a1994aee77b71165a5c43c0371ba6c580', 'modules/Pester/5.7.1'),
]


def main():
    if len(sys.argv) != 2:
        raise SystemExit('usage: fetch-windows-test-tools.py SCRATCH_DIRECTORY')
    root = Path(sys.argv[1]).resolve()
    root.mkdir(parents=True, exist_ok=True)
    for url, digest, target in TOOLS:
        archive = root / (digest + ('.tar.gz' if target == 'pwsh' else '.zip'))
        if not archive.exists():
            with urllib.request.urlopen(url, timeout=300) as response:
                archive.write_bytes(response.read())
        if hashlib.sha256(archive.read_bytes()).hexdigest() != digest:
            raise SystemExit('SHA256 mismatch: ' + url)
        destination = root / target
        destination.mkdir(parents=True, exist_ok=True)
        if target == 'pwsh':
            with tarfile.open(archive) as source:
                source.extractall(destination, filter='data')
            (destination/'pwsh').chmod(0o755)
        else:
            with zipfile.ZipFile(archive) as source:
                source.extractall(destination)
        print('verified ' + url + ': ' + digest, flush=True)


if __name__ == '__main__':
    main()
