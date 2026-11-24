#!/usr/bin/python3
# SPDX-License-Identifier: Apache-2.0
"""Root-only advanced-scan acceptance fixture. Run only in a disposable guest."""
from decimal import Decimal
import ctypes
import fcntl
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import select
import shutil
import signal
import stat
import struct
import subprocess
import threading
import time

BASE = Path('/opt/scan-advanced')
OUT = BASE / 'evidence'
BINARY = BASE / 'tego'
CANARY = 'PUBLIC_IGNORED_VALUE_CANARY_SCAN3_48765'
PRIVATE_CANARY = 'PRIVATE_CONFIG_VALUE_CANARY_SCAN3_93571'
USER = pwd.getpwnam('tego')
UID, GID, HOME = USER.pw_uid, USER.pw_gid, Path(USER.pw_dir)
checks = []
failures = []
processes = []


def require(value, message):
    if not value:
        raise AssertionError(message)


def write(path, value, mode=0o600, owner=None):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value)
    path.chmod(mode)
    if owner:
        os.chown(path, *owner)


def remove(path):
    if path.is_symlink() or path.is_file() or path.exists() and not path.is_dir():
        path.unlink()
    elif path.is_dir():
        shutil.rmtree(path)


def controlled_dirs():
    for path in [HOME / '.config', HOME / '.config/systemd', HOME / '.config/systemd/user',
                 HOME / '.tego', HOME / '.tego/scan', HOME / 'scan-fixture']:
        path.mkdir(parents=True, exist_ok=True)
        path.chmod(0o700)
        os.chown(path, UID, GID)


def root_env():
    env = os.environ.copy()
    env.update(SUDO_UID=str(UID), SUDO_GID=str(GID), SUDO_USER='tego',
               TEGO_CONFIG='', TEGO_TEST_CHAIN_ANCHOR=str(HOME / 'scan-fixture/chain.log'),
               TEGO_TEST_OWN_LOG_HOME=str(HOME / 'scan-fixture/log-home'), TEGO_HINTS='off',
               GOMAXPROCS='2')
    return env


def task_status(pid):
    states = {}
    for task in sorted(Path(f'/proc/{pid}/task').iterdir()):
        values = {}
        for line in (task / 'status').read_text().splitlines():
            if ':' in line:
                key, value = line.split(':', 1)
                if key in ['Uid', 'Gid', 'Groups', 'CapInh', 'CapPrm', 'CapEff', 'CapAmb', 'NoNewPrivs']:
                    values[key] = value.split()
        states[task.name] = values
    return states


def scan(name, args=('--json',), credentials=False, env_extra=None, on_start=None):
    env = root_env()
    env.update(env_extra or {})
    command = [str(BINARY), 'scan', '--advanced', *args]
    start = time.monotonic()
    p = subprocess.Popen(command, cwd=HOME, env=env, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, preexec_fn=lambda: os.setgroups([0, 27, 54321]))
    try:
        if on_start:
            on_start(p.pid)
        # A small full pipe holds the real CLI after its permanent drop, so the root
        # observer can read every thread's kernel status before rendering completes.
        # AlmaLinux 9's Python 3.9 omits the name; Linux UAPI fixes it at 1031.
        fcntl.fcntl(p.stdout.fileno(), getattr(fcntl, 'F_SETPIPE_SZ', 1031), 4096)
        states = None
        if credentials:
            until = time.monotonic() + 15
            while time.monotonic() < until and p.poll() is None:
                try:
                    observed = task_status(p.pid)
                    if observed and all(v['Uid'] == [str(UID)] * 4 and v['Gid'] == [str(GID)] * 4 and not v['Groups'] and v['NoNewPrivs'] == ['1'] and all(v[c] == ['0000000000000000'] for c in ['CapInh','CapPrm','CapEff','CapAmb']) for v in observed.values()):
                        states = observed
                        break
                except FileNotFoundError:
                    pass
                time.sleep(0.001)
            require(states, 'could not observe real CLI threads after drop')
            for tid, values in states.items():
                require(values['Uid'] == [str(UID)] * 4, (tid, values))
                require(values['Gid'] == [str(GID)] * 4, (tid, values))
                require(not values['Groups'], (tid, values))
                for field in ['CapInh', 'CapPrm', 'CapEff', 'CapAmb']:
                    require(values[field] == ['0000000000000000'], (tid, values))
                require(values['NoNewPrivs'] == ['1'], (tid, values))
            (OUT / (name + '.threads.json')).write_text(json.dumps(states, indent=2) + '\n')
        try:
            stdout, stderr = p.communicate(timeout=25)
        except subprocess.TimeoutExpired:
            p.kill()
            stdout, stderr = p.communicate(timeout=5)
            raise AssertionError(f'{name}: hung past 25 seconds')
        elapsed = time.monotonic() - start
        (OUT / (name + '.stdout')).write_bytes(stdout)
        (OUT / (name + '.stderr')).write_bytes(stderr)
        (OUT / (name + '.command.json')).write_text(json.dumps({'argv':command, 'exit':p.returncode,
            'seconds':elapsed, 'groups_before':[0,27,54321], 'threads_after':len(states or {})}, indent=2)+'\n')
        require(all(c.encode() not in stdout + stderr for c in [CANARY,PRIVATE_CANARY]), name + ': private canary in stdout/stderr/footer')
        require(elapsed < 25, name + ': unbounded operation')
        if '--json' in args:
            data = json.loads(stdout)
            require(data['mode'] == 'advanced', name + ': wrong mode')
            return p.returncode, data
        return p.returncode, None
    finally:
        if p.poll() is None:
            p.kill()
            extra_out,extra_err=p.communicate(timeout=5)
            (OUT/(name+'.cleanup.stdout')).write_bytes(extra_out)
            (OUT/(name+'.cleanup.stderr')).write_bytes(extra_err)


def case(name, action):
    try:
        detail = action()
        checks.append({'name':name, 'result':'PASS', 'detail':detail})
        print('PASS', name, detail, flush=True)
    except Exception as error:
        failures.append({'name':name, 'error':repr(error)})
        print('FAIL', name, repr(error), flush=True)


def good_result():
    controlled_dirs()
    code, data = scan('baseline', credentials=True)
    require(code == 0, ('baseline exit', code))
    require(data['counts']['system_units'] >= 2 and data['counts']['cron_entries'] >= 3, ('fixed sources absent', data['counts']))
    require(any(i['kind']=='user_unit' for i in data['items']), 'recipient unit absent')
    foreign=[i['detail'] for i in data['items'] if i['kind']=='process' and i['detail']['uid']!=UID]
    require(foreign and all(i.get('cwd') is None for i in foreign), 'foreign folder retained')
    path = HOME / '.tego/scan/last.json'
    require(path.read_bytes() == (OUT/'baseline.stdout').read_bytes(), 'saved JSON differs')
    for p, mode in [(path,0o600),(path.parent,0o700)]:
        st = p.stat()
        require((st.st_uid,stat.S_IMODE(st.st_mode)) == (UID,mode), ('storage',str(p),st))
    other = subprocess.run(['runuser','-u','scan-peer','--','cat',str(path)], capture_output=True)
    require(other.returncode != 0, 'peer read saved result')
    return {'exit':code,'owner':UID,'file_mode':'0600','directory_mode':'0700','peer_exit':other.returncode}


def runtime_override_refusal():
    destination=HOME/'.tego/scan/last.json'
    before=hashlib.sha256(destination.read_bytes()).hexdigest()
    code,data=scan('runtime-override-refused',args=('--check','--json'),env_extra={'GODEBUG':'containermaxprocs=1'})
    require(code==125 and data['status']=='failed',('runtime override refusal',code,data['status']))
    require('scan-not-performed' in data['not_looked_at'],'runtime override did not refuse before collection')
    require(any(s['reason']=='unsupported' and s['state']=='not-read' for s in data['sources']),
            'runtime override refusal reason missing')
    require(before==hashlib.sha256(destination.read_bytes()).hexdigest(),'runtime override changed saved result')
    return {'exit':code,'reason':'unsupported','collection':'not performed','prior_result':'unchanged'}


def source_matrix():
    root_private = Path('/root/private.yaml')
    write(root_private, 'ledger_root: /root/' + PRIVATE_CANARY + '\n')
    unit_private = Path('/root/private-units')
    write(unit_private/'private.service','[Service]\nExecStart=/opt/scan-advanced/bin/codex '+PRIVATE_CANARY+'\n')
    private_file = Path('/root/private-unit.service')
    write(private_file, '[Service]\nExecStart=/opt/scan-advanced/bin/codex '+PRIVATE_CANARY+'\n')
    positions = [('unit-directory',HOME/'.config/systemd/user',unit_private),
        ('unit-file',HOME/'.config/systemd/user/hostile.service',private_file),
        ('drop-in',HOME/'.config/systemd/user/fixture.service.d/override.conf',private_file),
        ('crontab',Path('/var/spool/cron/crontabs/tego'),root_private),
        ('crontab-direct',Path('/var/spool/cron/tego'),root_private),
        ('recipient-config',HOME/'.tego/config.yaml',root_private)]
    details=[]
    for label,path,target in positions:
        for kind in ['link','fifo','device']:
            remove(path)
            path.parent.mkdir(parents=True,exist_ok=True)
            if str(path).startswith(str(HOME)):
                os.chown(path.parent,UID,GID)
            if kind == 'link': path.symlink_to(target)
            elif kind == 'fifo': os.mkfifo(path,0o600)
            else: os.mknod(path,stat.S_IFCHR|0o600,os.makedev(1,3))
            if kind != 'link': os.chown(path,UID,GID)
            else: os.lchown(path,UID,GID)
            code,data=scan(label+'-'+kind)
            require(code==0,(label,kind,code))
            if label == 'recipient-config':
                require(any(i['kind']=='process' and i['detail'].get('run_id') for i in data['items']), 'config case lacks live governed process')
                require(any(s['kind']=='meta' and s['state']=='not-read' and s['reason']=='io' and s.get('locator') is None for s in data['sources']), ('config not refused',kind,data['sources'][-3:]))
            else:
                rows=[s for s in data['sources'] if s.get('locator') == str(path)]
                require(rows and any(s['state']=='not-read' for s in rows),(label,kind,rows))
            details.append({'position':label,'kind':kind,'exit':code})
            remove(path)
            controlled_dirs()
            write(HOME/'.config/systemd/user/fixture.service','[Service]\nExecStart=/opt/scan-advanced/bin/codex '+CANARY+'\n',0o600,(UID,GID))
    return details



def audit_trace():
    events=[]
    for path in OUT.glob('advanced.trace.*'):
        for line in path.read_text().splitlines():
            match=re.match(r'(\d+\.\d+)\s+(.*)',line)
            if match:events.append((int(Decimal(match.group(1))*1000000000),path.name,match.group(2)))
    events.sort()
    credentials=[(at,thread,line) for at,thread,line in events if re.search(r'(setgroups|setresgid|setresuid|capset|PR_SET_NO_NEW_PRIVS|PR_CAP_AMBIENT)',line) and re.search(r'= 0(?:\s|$)',line)]
    require(credentials,'credential syscalls absent from trace')
    starts=[at for at,thread,line in events if line.startswith('setgroups(0,')]
    require(starts,'supplementary-group drop absent from trace')
    first_drop=min(starts)
    last_drop=max(at for at,thread,line in credentials)
    opens=[]
    held={}
    pending_closes={}
    recipient_before=[]
    for at,thread,line in events:
        if ('openat(' in line or 'openat2(' in line or 'openat resumed>' in line or 'openat2 resumed>' in line):
            row={'at_ns':at,'thread':thread,'phase':'before-drop' if at<first_drop else 'transition' if at<=last_drop else 'after-drop','call':line}
            opens.append(row)
            match=re.search(r'= (\d+)<([^>]+)>',line)
            if at<first_drop and match and match.group(2).startswith('/'):
                held[match.group(1)]=match.group(2)
            recipient_markers=[str(HOME/x) for x in ['.tego','.codex','.claude','.gemini','scan-fixture']]
            if at<=last_drop and any(marker in line for marker in recipient_markers):recipient_before.append(row)
        if at<first_drop:
            match=re.match(r'close\((\d+)',line)
            if match:
                if '<unfinished ...>' in line:pending_closes[thread]=match.group(1)
                elif '= 0' in line:held.pop(match.group(1),None)
            elif '<... close resumed>' in line:
                fd=pending_closes.pop(thread,None)
                require(fd is not None,('unpaired resumed close',thread,line))
                if '= 0' in line:held.pop(fd,None)
    summary={'first_credential_ns':first_drop,'last_credential_ns':last_drop,
        'source_descriptors_still_open_at_drop':held,'recipient_opens_before_drop_complete':recipient_before,'opens':opens}
    (OUT/'trace-open-audit.json').write_text(json.dumps(summary,indent=2)+'\n')
    require(not held,('source descriptors still open at drop',held))
    require(not recipient_before,('recipient opens before drop complete',recipient_before))
    require(any(str(HOME/'.tego/config.yaml') in row['call'] and row['phase']=='after-drop' for row in opens),'recipient config attempt absent after drop')
    return {'root_source_descriptors_at_drop':0,'recipient_opens_before_drop_complete':0,'open_attempts':len(opens)}


def canary_regression():
    config=HOME/'.tego/config.yaml'
    remove(config)
    config.symlink_to('/root/private.yaml')
    os.lchown(config,UID,GID)
    seen_run=False
    for name,args in [('canary-json',('--json',)),('canary-short',()),('canary-verbose',('-v',)),
                      ('canary-check',('--check',)),('canary-check-json',('--check','--json'))]:
        before=hashlib.sha256((HOME/'.tego/scan/last.json').read_bytes()).hexdigest()
        code,data=scan(name,args,credentials='--check' in args and '--json' in args)
        require(code in ([1,3] if '--check' in args else [0]),(name,code))
        if data:
            seen_run = seen_run or any(i['kind']=='process' and i['detail'].get('run_id') for i in data['items'])
        if '--check' in args:
            require(before==hashlib.sha256((HOME/'.tego/scan/last.json').read_bytes()).hexdigest(),name+': check saved')
    require(seen_run,'matching process in a real Tego run absent')
    for root in [OUT,HOME/'.tego',HOME/'scan-fixture/log-home']:
        if root.exists():
            for path in root.rglob('*'):
                if path.is_file() and not path.is_symlink():
                    require(all(c.encode() not in path.read_bytes() for c in [CANARY,PRIVATE_CANARY]), 'canary in output/cache/log '+str(path))
    trace=[str(x) for x in ['strace','-ff','-ttt','-yy','-s','256','-e',
        'trace=openat,openat2,close,read,readlinkat,execve,execveat,socket,connect,setgroups,setresgid,setresuid,capset,prctl,clone,clone3',
        '-o',OUT/'advanced.trace',BINARY,'scan','--advanced','--json']]
    traced=subprocess.run(trace,cwd=HOME,env=root_env(),capture_output=True,timeout=30,
        preexec_fn=lambda:os.setgroups([0,27,54321]))
    (OUT/'traced.stdout').write_bytes(traced.stdout)
    (OUT/'traced.stderr').write_bytes(traced.stderr)
    require(traced.returncode==0,('trace exit',traced.returncode,traced.stderr))
    require(all(c.encode() not in traced.stdout+traced.stderr for c in [CANARY,PRIVATE_CANARY]),'canary in traced output')
    for trace_path in OUT.glob('advanced.trace.*'):
        require(PRIVATE_CANARY.encode() not in trace_path.read_bytes(),'private config value in trace')
    trace_summary=audit_trace()
    config.unlink()
    return {'trace_audit':trace_summary,'canary_channels':['JSON','short','verbose','check','stdout','stderr','footer','saved result','log'],
            'matching_real_run':True}



def recipient_selected_paths():
    config=HOME/'.tego/config.yaml'
    remove(config)
    selected=HOME/'scan-fixture/env-config.yaml'
    selected.symlink_to('/root/private.yaml')
    os.lchown(selected,UID,GID)
    code,data=scan('environment-config-link',env_extra={'TEGO_CONFIG':str(selected)})
    require(code==0,('environment config',code))
    selected.unlink()
    private=Path('/root/private-ledger')
    private.mkdir(mode=0o700)
    original=json.loads((OUT/'baseline.stdout').read_text())
    run_ids=[i['detail']['run_id'] for i in original['items'] if i['kind']=='process' and i['detail'].get('run_id')]
    require(run_ids,'no real run for ledger-link check')
    for run_id in run_ids:write(private/run_id/'events.jsonl',PRIVATE_CANARY+'\n')
    linked=HOME/'scan-fixture/ledger-link'
    linked.symlink_to(private)
    os.lchown(linked,UID,GID)
    write(config,'ledger_root: '+str(linked)+'\n',0o600,(UID,GID))
    code,data=scan('recipient-ledger-link')
    require(code==0,('recipient ledger',code))
    probes=[s for s in data['sources'] if s['kind']=='meta' and str(linked) in (s.get('locator') or '')]
    require(probes and all(s['state']=='not-read' for s in probes),('root-only ledger not refused',probes))
    config.unlink();linked.unlink()
    return {'environment_config_exit':0,'root_only_ledger_exit':0,'record_probes':'not-read'}


def destination_matrix():
    destination=HOME/'.tego/scan'
    details=[]
    for kind in ['precreated-file','precreated-file-root','last-link','directory-not-owned','world-writable-parent','scan-link']:
        remove(destination)
        controlled_dirs()
        last=destination/'last.json'
        marker=Path('/root/destination-marker')
        write(marker,'private-destination-marker\n')
        if kind=='precreated-file': write(last,'old\n',0o644,(UID,GID))
        elif kind=='precreated-file-root': write(last,'root-old\n',0o600)
        elif kind=='last-link': last.symlink_to(marker); os.lchown(last,UID,GID)
        elif kind=='directory-not-owned': os.chown(destination,0,0)
        elif kind=='world-writable-parent': (HOME/'.tego').chmod(0o777)
        elif kind=='scan-link': remove(destination); destination.symlink_to('/root')
        code,data=scan('destination-'+kind)
        expected=0 if kind in ['precreated-file','last-link'] else 125
        require(code==expected,(kind,code,expected))
        require(marker.read_text()=='private-destination-marker\n',kind+': marker changed')
        if code==0:
            require(not last.is_symlink() and last.stat().st_uid==UID and stat.S_IMODE(last.stat().st_mode)==0o600,kind+': result unsafe')
        details.append({'kind':kind,'exit':code,'expected':expected})
        remove(destination)
        (HOME/'.tego').chmod(0o700)
        controlled_dirs()
    return details


def parent_replacement():
    target=HOME/'.config/systemd/user'
    saved=target.with_name('user-old')
    private=Path('/root/private-units')
    stop=threading.Event()
    count=[0]
    def swap():
        while not stop.is_set():
            try:
                target.rename(saved)
                target.symlink_to(private)
                count[0]+=1
                target.unlink()
                saved.rename(target)
            except FileNotFoundError: pass
    worker=threading.Thread(target=swap)
    worker.start()
    try:
        code,data=scan('parent-replacement')
        require(code==0,code)
    finally:
        stop.set();worker.join()
        if target.is_symlink(): target.unlink()
        if saved.exists() and not target.exists(): saved.rename(target)
    require(count[0]>0,'parent replacement never occurred')
    require(not any(i['kind']=='user_unit' and i['detail'].get('unit')=='private.service' for i in data['items']), 'private linked unit retained')
    require(not any(s['state']=='read' and '/root/private' in (s.get('locator') or '') for s in data['sources']), 'root-only private source read')
    return {'replacements':count[0],'exit':code}


def parent_replacement_during_open():
    target=HOME/'.config/systemd/user'
    original=target/'fixture.service'
    backup=target.with_name('user-permission-old')
    require(not backup.exists(),'permission-walk backup already exists')
    before=original.stat()
    libc=ctypes.CDLL(None,use_errno=True)
    libc.fanotify_init.argtypes=[ctypes.c_uint,ctypes.c_uint]
    libc.fanotify_init.restype=ctypes.c_int
    libc.fanotify_mark.argtypes=[ctypes.c_int,ctypes.c_uint,ctypes.c_uint64,ctypes.c_int,ctypes.c_char_p]
    libc.fanotify_mark.restype=ctypes.c_int
    fan=libc.fanotify_init(0x1|0x2|0x4,os.O_RDONLY|os.O_CLOEXEC)
    require(fan>=0,('fanotify_init',ctypes.get_errno()))
    expected_pid=[]
    details={}
    errors=[]
    def permit():
        event_fd=None
        allowed=False
        try:
            ready,_,_=select.select([fan],[],[],10)
            require(ready,'no actual unit data-open permission event in 10 seconds')
            event=os.read(fan,4096)
            require(len(event)>=24,('short fanotify event',len(event)))
            length,version,reserved,metadata_length,mask,event_fd,pid=struct.unpack_from('=IBBHQii',event)
            require(length>=24 and version==3 and metadata_length>=24 and mask&0x10000 and event_fd>=0,
                    ('unexpected fanotify event',length,version,metadata_length,mask,event_fd))
            require(expected_pid and pid==expected_pid[0],('permission event is not the real CLI',pid,expected_pid))
            before_credentials=task_status(pid)
            require(before_credentials and all(v['Uid']==['0']*4 for v in before_credentials.values()),
                    'fixed unit was not read during the root phase')
            pinned=os.fstat(event_fd)
            require((pinned.st_dev,pinned.st_ino)==(before.st_dev,before.st_ino),'permission event names another inode')
            target.rename(backup)
            target.symlink_to('/root/private-units')
            os.lchown(target,UID,GID)
            details.update(event_pid=pid,event_inode=pinned.st_ino,before_credentials=before_credentials,replaced_ns=time.monotonic_ns())
            os.write(fan,struct.pack('=iI',event_fd,1))
            allowed=True
            details['allowed_ns']=time.monotonic_ns()
        except Exception as error:
            errors.append(repr(error))
        finally:
            if event_fd is not None and event_fd>=0:
                if not allowed:
                    try:os.write(fan,struct.pack('=iI',event_fd,1))
                    except OSError as error:errors.append(repr(error))
                os.close(event_fd)
    worker=threading.Thread(target=permit)
    try:
        marked=libc.fanotify_mark(fan,0x1,0x10000,-100,os.fsencode(original))
        require(marked==0,('fanotify_mark',ctypes.get_errno()))
        worker.start()
        code,data=scan('parent-replacement-during-open',on_start=lambda pid:expected_pid.append(pid))
        worker.join(timeout=12)
        require(not worker.is_alive(),'permission observer did not terminate')
        require(not errors,('permission observer',errors))
        require(details.get('replaced_ns',0)<details.get('allowed_ns',0),'replacement was not before permission response')
        require(code==0,('parent replacement exit',code))
        require(not any(i['kind']=='user_unit' and i['detail'].get('unit') in ['fixture.service','private.service'] for i in data['items']),
                'changed or private unit retained after controlled parent replacement')
        refused=[s for s in data['sources'] if (s.get('locator') or '').startswith(str(target)) and
                 s['state']=='not-read' and s['reason'] in ['changed','symlink']]
        require(refused,('controlled parent replacement lacks changed/symlink refusal',data['sources'][-10:]))
        details.update(exit=code,refusals=refused)
        return details
    finally:
        os.close(fan)
        if worker.ident is not None:worker.join(timeout=12)
        if target.is_symlink():target.unlink()
        if backup.exists() and not target.exists():backup.rename(target)


def setup():
    require(os.geteuid()==0,'fixture must run as root in a guest')
    OUT.mkdir(parents=True,exist_ok=True)
    subprocess.run(['useradd','-m','scan-peer'],check=True)
    subprocess.run(['groupadd','-g','54321','scan-extra'],check=True)
    controlled_dirs()
    (BASE/'bin').mkdir(exist_ok=True)
    shutil.copyfile('/usr/bin/sleep',BASE/'bin/codex')
    (BASE/'bin/codex').chmod(0o755)
    # Keep one catalog match outside and one inside a real recipient Tego run.
    foreign=Path('/home/scan-peer/clients/PrivateAcquisition')
    foreign.mkdir(parents=True)
    os.chown(foreign,pwd.getpwnam('scan-peer').pw_uid,pwd.getpwnam('scan-peer').pw_gid)
    outside=subprocess.Popen(['runuser','-u','scan-peer','--',str(BASE/'bin/codex'),'1800'],cwd=foreign)
    processes.append(outside)
    write(HOME/'scan-fixture/run-config.yaml', 'ledger_root: '+str(HOME/'scan-fixture/runs')+'\n',(0o600),(UID,GID))
    write(HOME/'scan-fixture/agent.yaml','''version: 0
name: scan3-canary-run
command: [/opt/scan-advanced/bin/codex, "1800"]
tier: landlock
capture: off
record: full
fs:
  write: [/dev/null]
exec:
  allow: [/opt/scan-advanced/bin/codex]
net:
  allow: []
  dns: {mode: "off"}
env:
  pass: [PATH, HOME, LANG]
''',0o600,(UID,GID))
    runtime=f'/run/user/{UID}'
    env=dict(os.environ,HOME=str(HOME),USER='tego',XDG_RUNTIME_DIR=runtime,
        DBUS_SESSION_BUS_ADDRESS=f'unix:path={runtime}/bus',TEGO_CONFIG=str(HOME/'scan-fixture/run-config.yaml'),
        TEGO_TEST_CHAIN_ANCHOR=str(HOME/'scan-fixture/chain.log'),TEGO_TEST_OWN_LOG_HOME=str(HOME/'scan-fixture/log-home'))
    log=(OUT/'real-run.log').open('wb')
    command=['runuser','-u','tego','--','env',*[f'{k}={v}' for k,v in env.items()],
        'systemd-run','--user','--scope','--quiet','--',str(BINARY),'run',str(HOME/'scan-fixture/agent.yaml')]
    run=subprocess.Popen(command,cwd=HOME,stdout=log,stderr=subprocess.STDOUT)
    processes.append(run)
    until=time.monotonic()+30
    while time.monotonic()<until:
        if run.poll() is not None: raise AssertionError('real run ended: '+(OUT/'real-run.log').read_text())
        if list((HOME/'scan-fixture/runs').glob('r-*/events.jsonl')): break
        time.sleep(0.1)
    write(HOME/'.config/systemd/user/fixture.service','[Service]\nExecStart=/opt/scan-advanced/bin/codex '+CANARY+'\n',0o600,(UID,GID))
    write(Path('/etc/systemd/system/scan3-fixture.service'),'[Service]\nExecStart=/opt/scan-advanced/bin/codex '+CANARY+'\n',0o644)
    write(Path('/etc/systemd/system/scan3-fixture.timer'),'[Timer]\nUnit=scan3-fixture.service\nOnBootSec=7d\n',0o644)
    write(Path('/etc/cron.d/scan3-fixture'),'TOKEN='+CANARY+'\n0 0 * * * root /opt/scan-advanced/bin/codex '+CANARY+'\n',0o644)
    write(Path('/var/spool/cron/crontabs/tego'),'0 0 * * * /opt/scan-advanced/bin/codex '+CANARY+'\n',0o600,(UID,GID))
    write(Path('/var/spool/cron/tego'),'0 0 * * * /opt/scan-advanced/bin/codex '+CANARY+'\n',0o600,(UID,GID))


def main():
    setup()
    case('baseline-real-cli-threads-and-storage',good_result)
    case('runtime-positive-override-refusal',runtime_override_refusal)
    case('sources-link-fifo-device',source_matrix)
    case('exact-root-config-canary',canary_regression)
    case('recipient-config-and-ledger-paths',recipient_selected_paths)
    case('source-parent-replacement-concurrent',parent_replacement)
    case('source-parent-replacement-during-open',parent_replacement_during_open)
    case('hostile-destinations',destination_matrix)
    try:
        for p in processes:
            if p.poll() is None: p.terminate()
        for p in processes:
            try:p.wait(timeout=10)
            except subprocess.TimeoutExpired:p.kill();p.wait(timeout=5)
    finally:
        summary={'checks':checks,'failures':failures,'verdict':'PASS' if not failures else 'FAIL'}
        (OUT/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
        print(json.dumps(summary),flush=True)
    return 0 if not failures else 1


if __name__=='__main__':
    raise SystemExit(main())
