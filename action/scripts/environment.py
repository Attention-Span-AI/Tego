#!/usr/bin/python3
# SPDX-License-Identifier: Apache-2.0
"""Remove inherited code-loading hooks before entering a collector shell."""
import os
import sys

DROP = {'BASH_ENV', 'ENV', 'PROMPT_COMMAND', 'CDPATH', 'GLOBIGNORE',
        'SHELLOPTS', 'BASHOPTS', 'LD_PRELOAD', 'LD_LIBRARY_PATH',
        'PYTHONPATH', 'PYTHONHOME', 'PYTHONSTARTUP'}
clean = {key: value for key, value in os.environ.items()
         if key not in DROP and not key.startswith('BASH_FUNC_')}
clean['PATH'] = '/usr/bin:/bin'
os.execve('/bin/bash', ['/bin/bash', '--noprofile', '--norc', '-p', sys.argv[1],
                       '--tego-ci-clean', *sys.argv[2:]], clean)
