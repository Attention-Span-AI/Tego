#!/usr/bin/python3
# SPDX-License-Identifier: Apache-2.0
"""Put allowed values in execve's environment, never in an env(1) argv."""
import os
from pathlib import Path
import re
import sys
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from policy import BASE, forbidden

try:
    names = [n for n in re.split(r'[\s,]+', os.environ.get('IN_ENV_PASS', '')) if n]
    if any(not re.fullmatch('[A-Za-z_][A-Za-z0-9_]*', n) or forbidden(n) for n in names):
        raise ValueError('env-pass names a forbidden CI or startup variable')
    clean = {n: os.environ[n] for n in BASE | set(names) if n in os.environ}
    clean['HOME'] = os.environ.get('AGENT_HOME', os.environ.get('HOME', ''))
    clean['PATH'] = '/usr/local/bin:/usr/bin:/bin'
    clean.setdefault('XDG_RUNTIME_DIR', '/run/user/' + str(os.getuid()))
    clean['TEGO_CONFIG'] = os.environ['DIR'] + '/config.yaml'
    command = [os.environ['TEGO'], 'run', os.environ['CONTRACT'], '--tier',
               'cgroup' if os.environ['IN_USE_SUDO'] == 'true' else 'landlock',
               '--status-file', os.environ['DIR'] + '/status/run-status.json',
               '--', '/bin/bash', '--noprofile', '--norc', '-eo', 'pipefail', '-c', os.environ['IN_RUN']]
    if sys.argv[1:] != ['--direct-test']:
        if os.environ['IN_USE_SUDO'] == 'true':
            command = ['/usr/bin/sudo', '-n', '--preserve-env=' + ','.join(sorted(clean)), '--'] + command
        else:
            command = ['/usr/bin/systemd-run', '--user', '--scope', '--quiet', '--'] + command
    os.chdir(os.environ.get('GITHUB_WORKSPACE', os.getcwd()))
    os.execve(command[0], command, clean)
except (ValueError, KeyError, OSError) as error:
    print(str(error), file=sys.stderr)
    sys.exit(125)
