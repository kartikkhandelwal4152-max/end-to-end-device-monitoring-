"""Visible per-user auto-start enrollment. No remote downloads or elevation."""
import argparse
import getpass
import json
import os
from pathlib import Path
import platform
import plistlib
import re
import shutil
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--device')
    parser.add_argument('--server')
    parser.add_argument('--uninstall', action='store_true')
    args = parser.parse_args()
    system = platform.system()
    if system not in ('Windows','Darwin'):
        parser.error('Installer supports macOS/Windows; run agent.py directly on Linux.')
    root = Path.home()/'.sentinel'
    plist = Path.home()/'Library/LaunchAgents/com.sentinel.agent.plist'
    startup = Path(os.environ.get('APPDATA',str(Path.home())))/'Microsoft/Windows/Start Menu/Programs/Startup/sentinel.cmd'
    if args.uninstall:
        if system == 'Darwin' and plist.exists():
            subprocess.run(['launchctl','unload',str(plist)],check=False)
            plist.unlink()
        if system == 'Windows':
            startup.unlink(missing_ok=True)
            startup.with_suffix('.bat').unlink(missing_ok=True)
        print('Auto-start removed. Credentials/queues retained at',root)
        print('On Windows stop the running agent or sign out. Remove retained data separately when no longer needed.')
        return
    import psutil, requests
    from agent import validate_url
    device = args.device or os.environ.get('SENTINEL_DEVICE_ID') or input('Device ID: ').strip()
    endpoint = args.server or os.environ.get('SENTINEL_SERVER_URL') or input('HTTPS origin: ').strip()
    if not re.fullmatch(r'[A-Za-z0-9_-]{1,64}',device): parser.error('Invalid device ID.')
    validate_url(endpoint,False)
    token = os.environ.get('SENTINEL_DEVICE_TOKEN') or getpass.getpass('Device token (hidden): ')
    if not token: parser.error('Token required.')
    source=Path(__file__).resolve().parent
    for name in ('agent.py','agent_runner.py'):
        if not (source/name).is_file(): parser.error('Install from the complete local release.')
    root.mkdir(mode=0o700,parents=True,exist_ok=True)
    if system=='Windows':
        subprocess.run(['icacls',str(root),'/inheritance:r','/grant:r',getpass.getuser()+':(OI)(CI)F'],check=True)
    else: root.chmod(0o700)
    with os.fdopen(os.open(root/'agent.json',os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600),'w') as handle:
        json.dump({'device':device,'server':endpoint.rstrip('/'),'token':token},handle)
    for name in ('agent.py','agent_runner.py'):
        if (source/name).resolve() != (root/name).resolve(): shutil.copyfile(source/name,root/name)
        (root/name).chmod(0o600)
    if system=='Darwin':
        plist.parent.mkdir(parents=True,exist_ok=True)
        config={'Label':'com.sentinel.agent','ProgramArguments':[sys.executable,str(root/'agent_runner.py')],
                'RunAtLoad':True,'KeepAlive':True,'ThrottleInterval':30,
                'StandardOutPath':str(root/'agent.log'),'StandardErrorPath':str(root/'agent-error.log')}
        if plist.exists(): subprocess.run(['launchctl','unload',str(plist)],check=False)
        with plist.open('wb') as handle: plistlib.dump(config,handle)
        subprocess.run(['launchctl','load',str(plist)],check=True)
    else:
        startup.parent.mkdir(parents=True,exist_ok=True)
        interpreter=Path(sys.executable).with_name('pythonw.exe')
        if not interpreter.exists(): interpreter=Path(sys.executable)
        if any(c in str(interpreter)+str(root) for c in '%!\r\n'): parser.error('Unsupported special characters in install path.')
        startup.with_suffix('.bat').unlink(missing_ok=True)
        startup.write_text('@echo off\n"'+str(interpreter)+'" "'+str(root/'agent_runner.py')+'"\n')
        subprocess.Popen([str(interpreter),str(root/'agent_runner.py')])
    print('Per-user auto-start configured. Verify the heartbeat in the dashboard; enrollment does not prove delivery.')
    print('Uninstall: python install_agent.py --uninstall')

if __name__=='__main__': main()
