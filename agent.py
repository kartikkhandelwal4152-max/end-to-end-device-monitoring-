"""Foreground endpoint agent. Collect only on devices you administer."""
import argparse
from collections import deque
import getpass
import os
from pathlib import Path
import re
import time
from urllib.parse import urlparse
import uuid

import psutil
import requests


class AuthLog:
    """Tail newly appended OpenSSH failure lines; start at EOF, handle rotation."""
    def __init__(self, path=None):
        self.path = Path(path) if path else None
        self.file = None
        self.identity = None
        self.first = True
        self.partial = ''

    def read(self):
        if not self.path:
            return None, 'Login monitoring unavailable: no Linux OpenSSH auth log configured.'
        try:
            stat = self.path.stat()
            identity = (stat.st_dev, stat.st_ino)
            if self.file is None or identity != self.identity:
                if self.file:
                    self.file.close()
                self.file = self.path.open(errors='replace')
                if self.first:
                    self.file.seek(0, 2)
                self.first = False
                self.identity = identity
                self.partial = ''
            if stat.st_size < self.file.tell():
                self.file.seek(0)
                self.partial = ''
            text = self.partial + self.file.read(1024 * 1024)
            lines = text.split('\n')
            self.partial = lines.pop()
            # One failure representation only, to avoid counting PAM + sshd duplicates.
            count = sum(bool(re.search(r'sshd(?:\[\d+\])?:.*Failed (?:password|publickey) for ', line)) for line in lines)
            return count, None
        except (OSError, PermissionError):
            return None, 'Login log unavailable or unreadable.'


class Collector:
    def __init__(self, log=None):
        self.auth = AuthLog(log)
        self.last_io = psutil.net_io_counters()
        self.last_time = time.monotonic()
        psutil.cpu_percent()
        self.auth.read()  # Begin watching at startup, not first collection.

    def sample(self):
        warnings = []
        cpu = psutil.cpu_percent(interval=0.1)
        now = time.monotonic()
        io = psutil.net_io_counters()
        elapsed = max(now-self.last_time, 0.001)
        rate = max(0, (io.bytes_sent+io.bytes_recv-self.last_io.bytes_sent-self.last_io.bytes_recv)/elapsed)
        self.last_io, self.last_time = io, now
        try:
            connections = len(psutil.net_connections(kind='inet'))
            warnings.append('Connection count is limited by OS permissions; some connections may be omitted.')
        except (psutil.AccessDenied, OSError):
            connections = None
            warnings.append('Network connection inventory unavailable: insufficient OS permissions.')
        processes = []
        for process in psutil.process_iter(['pid', 'name'], ad_value=None):
            try:
                if len(processes) < 100:
                    processes.append({'pid': process.info['pid'], 'name': (process.info['name'] or 'unavailable')[:200]})
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        failures, warning = self.auth.read()
        if warning:
            warnings.append(warning)
        return {'sample_id': uuid.uuid4().hex, 'observed': time.time(), 'cpu': cpu,
                'ram': psutil.virtual_memory().percent, 'process_count': len(psutil.pids()),
                'connections': connections, 'bytes_per_second': rate,
                'failed_logins': failures, 'processes': processes, 'warnings': warnings}


def validate_url(url, local_http):
    parsed = urlparse(url)
    if parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path not in ('', '/'):
        raise ValueError('Use a server origin without credentials, path, query, or fragment.')
    if not parsed.hostname or parsed.scheme not in ('http', 'https'):
        raise ValueError('Expected an HTTPS server URL.')
    if parsed.scheme == 'http' and not (local_http and parsed.hostname in ('localhost', '127.0.0.1', '::1')):
        raise ValueError('HTTPS required; HTTP is permitted only for explicit loopback development.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--server', default='https://localhost')
    parser.add_argument('--device', required=True)
    parser.add_argument('--interval', type=float, default=10)
    parser.add_argument('--auth-log', help='Linux OpenSSH log, e.g. /var/log/auth.log')
    parser.add_argument('--ca', help='CA certificate bundle for a private HTTPS server')
    parser.add_argument('--allow-local-http', action='store_true')
    parser.add_argument('--once', action='store_true')
    args = parser.parse_args()
    try:
        validate_url(args.server, args.allow_local_http)
        if not 1 <= args.interval <= 300:
            raise ValueError('Interval must be between 1 and 300 seconds.')
    except ValueError as exc:
        parser.error(str(exc))
    token = os.environ.get('SENTINEL_DEVICE_TOKEN') or getpass.getpass('Device token: ')
    collector = Collector(args.auth_log)
    session = requests.Session()
    session.headers.update({'Authorization': 'Bearer '+token, 'X-Device-ID': args.device})
    queue = deque()
    print('Monitoring started. Ctrl+C stops the agent. No background service is installed.')
    try:
        while True:
            if len(queue) == 60:
                queue.popleft()
                print('Queue full: oldest sample dropped.')
            queue.append(collector.sample())
            while queue:
                if time.time()-queue[0]['observed'] > 540:
                    queue.popleft()
                    print('Stale buffered sample dropped after 9 minutes.')
                    continue
                try:
                    response = session.post(args.server.rstrip('/')+'/api/telemetry', json=queue[0],
                                            verify=args.ca or True, timeout=10, allow_redirects=False)
                    if response.status_code in (401, 403):
                        raise SystemExit('Authentication rejected; check device registration and token.')
                    if 300 <= response.status_code < 400:
                        raise SystemExit('Redirect refused; supply the exact HTTPS origin.')
                    if response.status_code in (400, 413):
                        queue.popleft()
                        print('Invalid sample rejected by server; dropped.')
                        continue
                    response.raise_for_status()
                    queue.popleft()
                    print('Telemetry delivered.')
                except requests.RequestException:
                    print('Server unavailable or TLS verification failed; preserving sample for retry.')
                    break
            if args.once:
                if queue:
                    raise SystemExit('Sample was not delivered; run continuously to retry.')
                return
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print('\nAgent stopped.')
    finally:
        session.close()


if __name__ == '__main__':
    main()
