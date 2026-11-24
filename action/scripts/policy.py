#!/usr/bin/python3
# SPDX-License-Identifier: Apache-2.0
"""Checks compiled grants and Tego's canonical (already parsed) contract."""
import json
import os
from pathlib import Path
import re
import pwd
import subprocess
import sys

DENIED = {'ACTIONS_ID_TOKEN_REQUEST_URL', 'ACTIONS_ID_TOKEN_REQUEST_TOKEN',
          'ACTIONS_RUNTIME_TOKEN', 'ACTIONS_RUNTIME_URL', 'ACTIONS_CACHE_URL',
          'ACTIONS_RESULTS_URL', 'ACTIONS_CACHE_SERVICE_V2', 'GITHUB_TOKEN', 'GH_TOKEN',
          'SIGSTORE_ID_TOKEN', 'INPUT_TOKEN', 'INPUT_GITHUB_TOKEN'}
BASE = {'PATH', 'HOME', 'USER', 'LOGNAME', 'LANG', 'LC_ALL', 'TERM', 'TZ', 'CI', 'XDG_RUNTIME_DIR'}


def forbidden(name):
    return (name in DENIED or name.startswith(('ACTIONS_', 'INPUT_', 'GITHUB_', 'GH_', 'SIGSTORE_'))
            or name in {'BASH_ENV', 'ENV', 'SHELLOPTS', 'BASHOPTS', 'PYTHONPATH', 'PYTHONHOME',
                        'LD_PRELOAD', 'LD_LIBRARY_PATH', 'TEGO_CONFIG'})


def flags(text):
    # Only the trusted CLI's canonical YAML enters this function, never raw user YAML.
    # Its schema keys are fixed, booleans are literals, and multiline strings are indented.
    if text.startswith('{'):  # equivalent canonical values in offline fixtures
        data = json.loads(text)
    else:
        data = dict(re.findall(r'^([a-z_]+): ([^\n]+)$', text, re.M))
    for name in ['setuid', 'keep_descendants']:
        if str(data.get(name, '')).lower() == 'true':
            raise ValueError(f'{name}: true is refused in CI')
    if str(data.get('record', '')).strip('"\'') == 'off':
        raise ValueError('record: off is refused in CI')
    if data.get('tier') == 'observe':
        raise ValueError('record-only mode is refused in CI')


def overlaps(write, protected):
    w, p = Path(write).resolve(), Path(protected).resolve()
    return w == p or w in p.parents or p in w.parents or (w.exists() and p.exists() and os.path.samefile(w, p))


def environment_paths(path, home, cwd, xdg_config_home=None):
    # execvp treats empty/relative PATH entries as relative to the job cwd.
    # Include absent directories too: a grant could create them during the run.
    paths = ['/usr/bin', '/bin', '/usr/local/bin']
    for item in path.split(':'):
        paths.append(str(Path(item) if Path(item).is_absolute() else Path(cwd) / item))
    paths += [str(Path(home) / name) for name in
              ['.bashrc', '.profile', '.bash_profile', '.bash_login', '.bash_logout',
               '.bash_env', '.bash_aliases', '.inputrc', '.zshrc', '.zprofile', '.zshenv', '.jq',
               '.gitconfig', '.config/git', '.config/git/config']]
    if xdg_config_home:
        xdg = Path(xdg_config_home)
        if not xdg.is_absolute():
            xdg = Path(cwd) / xdg
        paths += [str(xdg / 'git'), str(xdg / 'git/config')]
    if any('\n' in p or '\r' in p for p in paths):
        raise ValueError('runner PATH or HOME contains a line break')
    return list(dict.fromkeys(paths))


def git_paths(repos, home):
    """Resolve the system, repository/worktree and included configuration files."""
    env = dict(os.environ, HOME=home)
    paths = ['/etc/gitconfig']
    for repo in repos:
        def git(*args, no_match=False):
            # Query the configured system path even when reads are disabled.
            # git var returns 1 under GIT_CONFIG_NOSYSTEM, without a path.
            command_env = dict(env, GIT_CONFIG_NOSYSTEM='0') if args[0] == 'var' else env
            result = subprocess.run(['/usr/bin/git', '-C', repo, *args], env=command_env,
                                    capture_output=True, text=True)
            if result.returncode and not (no_match and result.returncode == 1 and not result.stdout):
                raise ValueError(f'cannot resolve Git configuration paths in {repo!r}')
            return result.stdout

        paths.append(str(Path(repo) / '.git'))
        system_config = git('var', 'GIT_CONFIG_SYSTEM').removesuffix('\n')
        if system_config:
            paths.append(system_config)
        for key in ['GIT_CONFIG_SYSTEM', 'GIT_CONFIG_GLOBAL', 'GIT_CONFIG']:
            if env.get(key):
                paths.append(str(Path(repo) / env[key]))
        if (Path(repo) / '.git').exists():
            for args in [('--git-dir',), ('--git-common-dir',), ('--git-path', 'config'),
                         ('--git-path', 'config.worktree')]:
                paths.append(git('rev-parse', '--path-format=absolute', *args).removesuffix('\n'))
        # --name-only prevents configuration values from entering state or logs.
        # Include files can live outside HOME and the repository metadata.
        origins = git('config', '--null', '--list', '--name-only', '--show-origin', '--includes').split('\0')
        for origin in origins[:-1:2]:
            if origin.startswith('file:'):
                paths.append(str(Path(repo) / origin[5:]))
        # Origins alone omit empty or absent include targets. Read only include
        # path values; --path expands HOME/prefix the same way as Git. Relative
        # includes are anchored to their declaring file, not the job cwd.
        includes = git('config', '--null', '--path', '--show-origin', '--includes', '--get-regexp',
                       r'^include(if\..*)?\.path$', no_match=True).split('\0')
        if includes[-1] or len(includes) % 2 != 1:
            raise ValueError('invalid Git include path listing')
        for origin, entry in zip(includes[:-1:2], includes[1:-1:2]):
            _, separator, target = entry.partition('\n')
            if not separator or not target:
                raise ValueError('invalid Git include path')
            base = (Path(repo) / origin[5:]).parent if origin.startswith('file:') else Path(repo)
            paths.append(str(base / target))
    if any('\n' in p or '\r' in p for p in paths):
        raise ValueError('Git configuration path contains a line break')
    return list(dict.fromkeys(paths))


def check_runtime_writes(start, protected):
    # Minor 11 introduced complete runtime_grants disclosure. Before it, an
    # absent field cannot establish that no filesystem write grants were added.
    if not isinstance(start, dict):
        raise ValueError('invalid run_start for runtime grants')
    minor = start.get('record_minor')
    if type(minor) is not int or minor < 11:
        raise ValueError('runtime grants require record_minor 11 or later')
    grants = start.get('runtime_grants', [])
    if not isinstance(grants, list) or any(not isinstance(g, str) or not g for g in grants):
        raise ValueError('invalid runtime_grants list')
    if not isinstance(protected, list) or not protected or any(not isinstance(p, str) or not p for p in protected):
        raise ValueError('invalid pre-launch protected paths')
    for grant in grants:
        if not grant.startswith('fs.'):
            continue
        match = re.fullmatch(r'fs\.(?:codex_home|harness-state)\[(/[^\r\n\x00]*)\]', grant)
        if not match:
            raise ValueError(f'unknown or malformed runtime filesystem grant {grant!r}')
        try:
            check_writes({'fs': [{'kind': 'write', 'path': match[1]}]}, protected)
        except ValueError as error:
            raise ValueError(f'runtime grant {grant!r}: {error}') from error


def check_diagnostics(text):
    if re.search(r'\[path-shadow\]', text):
        raise ValueError('path-shadow is an error in CI: ' + text.strip())


def check_writes(table, protected):
    for row in table['fs']:
        if row['kind'] == 'write':
            for p in protected:
                if overlaps(row['path'], p):
                    raise ValueError(f'write entry {row["path"]!r} covers or overlaps protected path {str(p)!r}')


def augment(text, writes, reads=None):
    """Add rules to canonical block YAML without a second YAML implementation."""
    reads = writes if reads is None else reads
    lines = text.splitlines()
    if 'fs:' not in lines:
        lines += ['fs:']
    start = lines.index('fs:') + 1
    end = next((i for i in range(start, len(lines)) if lines[i] and not lines[i].startswith(' ')), len(lines))
    for key, paths in [('deny_read', reads), ('deny_write', writes)]:
        indexes = [i for i in range(start, end) if lines[i].startswith(f'  {key}:')]
        if not indexes:
            lines[end:end] = [f'  {key}:'] + ['    - ' + json.dumps(p) for p in paths]
            end += 1 + len(paths)
        else:
            i = indexes[0]
            if lines[i] not in [f'  {key}:', f'  {key}: []']:
                raise ValueError('unexpected canonical path list')
            lines[i] = f'  {key}:'
            lines[i + 1:i + 1] = ['    - ' + json.dumps(p) for p in paths]
            end += len(paths)
    return '\n'.join(lines) + '\n'


def main():
    if sys.argv[1] == 'environment-paths':
        paths = environment_paths(os.environ['JOB_PATH'], os.environ.get('AGENT_HOME', os.environ['HOME']),
                                  os.environ['GITHUB_WORKSPACE'], os.environ.get('XDG_CONFIG_HOME'))
        account_home = pwd.getpwuid(os.getuid()).pw_dir
        if not Path(account_home).is_absolute():
            raise ValueError('runner account has no absolute passwd home')
        paths += environment_paths('/usr/bin:/bin', account_home, os.environ['GITHUB_WORKSPACE'])
        paths.append(str(Path(account_home) / '.tego'))
        print('\n'.join(dict.fromkeys(paths)))
        return
    if sys.argv[1] == 'git-paths':
        print('\n'.join(git_paths(sys.argv[2:], os.environ.get('AGENT_HOME', os.environ['HOME']))))
        return
    if sys.argv[1] == 'save-paths':
        print(json.dumps(sys.argv[2:]))
        return
    if sys.argv[1] == 'runtime-writes':
        check_runtime_writes(json.loads(Path(sys.argv[2]).read_text()), json.loads(Path(sys.argv[3]).read_text()))
        return
    if sys.argv[1] == 'diagnostics':
        check_diagnostics(sys.stdin.read() if sys.argv[2] == '-' else Path(sys.argv[2]).read_text())
        return
    if sys.argv[1] == 'writes':
        check_writes(json.loads(Path(sys.argv[2]).read_text()), sys.argv[3:])
        return
    if sys.argv[1] == 'runner-root':
        roots = set()
        for proc in Path('/proc').glob('[0-9]*'):
            try:
                exe = (proc / 'exe').resolve(strict=True)
                if exe.name == 'Runner.Worker':
                    roots.add(str(exe.parent.parent))
            except (OSError, RuntimeError):
                continue
        if len(roots) != 1:
            raise ValueError('cannot identify one runner installation')
        print(roots.pop())
        return
    if sys.argv[1] == 'augment':
        text = Path(sys.argv[2]).read_text()
        flags(text)
        paths = sys.argv[3:]
        if '--read' in paths:
            split = paths.index('--read')
            writes, reads = paths[:split], paths[split + 1:]
        else:
            writes = reads = paths
        print(augment(text, writes, reads), end='')
        return
    text = Path(sys.argv[1]).read_text()
    flags(text)
    table = json.loads(Path(sys.argv[2]).read_text())
    check_writes(table, sys.argv[3:])
    if not DENIED <= set(table.get('env_deny') or []):
        raise ValueError('contract must extend tego/ci@1; its mandatory env denials are missing')
    for name in (table.get('env_set') or {}):
        if forbidden(name):
            raise ValueError('contract sets a forbidden CI variable')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, OSError) as error:
        print(str(error), file=sys.stderr)
        sys.exit(125)
