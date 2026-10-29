"""Foreground endpoint agent. Collect only on devices you administer."""
import argparse
from collections import deque
import getpass
import os
from pathlib import Path
import platform
import re
import threading
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
        disk = None
        try:
            root = 'C:\\' if platform.system() == 'Windows' else '/'
            disk = round(psutil.disk_usage(root).percent, 1)
        except Exception:
            pass
        battery, is_plugged = None, None
        try:
            b = psutil.sensors_battery()
            if b:
                battery = round(b.percent, 1)
                is_plugged = bool(b.power_plugged)
        except Exception:
            pass
        uptime = None
        try:
            uptime = max(0, int(time.time() - psutil.boot_time()))
        except Exception:
            pass
        os_info = f"{platform.system()} {platform.release()}"
        hostname = (platform.node() or 'unknown')[:64]
        active_window = get_active_window()
        ip_address = get_local_ip()
        return {'sample_id': uuid.uuid4().hex, 'observed': time.time(), 'cpu': cpu,
                'ram': psutil.virtual_memory().percent, 'process_count': len(psutil.pids()),
                'connections': connections, 'bytes_per_second': rate,
                'failed_logins': failures, 'processes': processes, 'warnings': warnings,
                'disk': disk, 'battery': battery, 'is_plugged': is_plugged,
                'os_info': os_info, 'hostname': hostname, 'uptime': uptime,
                'active_window': active_window, 'ip_address': ip_address}


def get_local_ip():
    try:
        import socket
        addrs = psutil.net_if_addrs()
        for iface, addr_list in addrs.items():
            iface_lower = iface.lower()
            if 'loopback' in iface_lower or iface_lower.startswith('lo'):
                continue
            for a in addr_list:
                if getattr(a, 'family', None) == socket.AF_INET and not a.address.startswith('127.'):
                    return a.address
    except Exception:
        pass
    return None


def get_active_window():
    if platform.system() == 'Windows':
        try:
            import ctypes
            from ctypes import wintypes
            user32 = ctypes.windll.user32
            user32.GetForegroundWindow.restype = wintypes.HWND
            user32.GetWindowTextLengthW.argtypes = [wintypes.HWND]
            user32.GetWindowTextLengthW.restype = ctypes.c_int
            user32.GetWindowTextW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
            user32.IsWindowVisible.argtypes = [wintypes.HWND]
            user32.IsWindowVisible.restype = wintypes.BOOL

            # 1. Check foreground window
            fg_hwnd = user32.GetForegroundWindow()
            fg_title = None
            if fg_hwnd:
                length = user32.GetWindowTextLengthW(fg_hwnd)
                if length > 0:
                    buff = ctypes.create_unicode_buffer(length + 1)
                    user32.GetWindowTextW(fg_hwnd, buff, length + 1)
                    fg_title = buff.value.strip()

            browser_names = ('Chrome', 'Edge', 'Brave', 'Firefox', 'Opera')
            # If foreground is a browser, return immediately
            if fg_title and any(b in fg_title for b in browser_names):
                return fg_title[:200]

            # 2. If foreground is not a browser (e.g. PowerShell or Desktop), check open browser windows
            browser_windows = []
            WNDENUMPROC = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)

            def enum_cb(hwnd, lparam):
                if user32.IsWindowVisible(hwnd):
                    l = user32.GetWindowTextLengthW(hwnd)
                    if l > 0:
                        buf = ctypes.create_unicode_buffer(l + 1)
                        user32.GetWindowTextW(hwnd, buf, l + 1)
                        t = buf.value.strip()
                        if t and any(b in t for b in browser_names):
                            browser_windows.append(t)
                return True

            user32.EnumWindows(WNDENUMPROC(enum_cb), 0)

            # Pick browser window that has tab title (contains separator or web domain)
            for bw in browser_windows:
                if any(delim in bw for delim in (' - ', ' — ', ' | ', 'http', '.com', '.org', '.net', '.in', 'www.')):
                    return bw[:200]

            if browser_windows:
                return browser_windows[0][:200]

            if fg_title:
                return fg_title[:200]

        except Exception:
            pass
        return None

    elif platform.system() == 'Darwin':
        try:
            import subprocess
            script = 'tell application "System Events" to get name of first application process whose frontmost is true'
            out = subprocess.check_output(['osascript', '-e', script], timeout=2, text=True, stderr=subprocess.DEVNULL).strip()
            return out[:200] if out else None
        except Exception:
            return None
    return None


def trigger_popup(title, message):
    try:
        if platform.system() == 'Windows':
            import ctypes
            # MB_ICONWARNING (0x30) | MB_SETFOREGROUND (0x10000) | MB_SYSTEMMODAL (0x1000)
            ctypes.windll.user32.MessageBoxW(0, str(message), str(title), 0x30 | 0x10000 | 0x1000)
        elif platform.system() == 'Darwin':
            import subprocess
            subprocess.run(['osascript', '-e', f'display alert "{title}" message "{message}"'], timeout=20, stderr=subprocess.DEVNULL)
        else:
            import subprocess
            subprocess.run(['notify-send', str(title), str(message)], timeout=10, stderr=subprocess.DEVNULL)
    except Exception as e:
        print(f"[ACTIVE RESPONSE] Popup error: {e}")


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
    args.server = args.server.rstrip('/\\')
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
                    data = response.json()
                    queue.popleft()
                    print('Telemetry delivered.')
                    for cmd in data.get('commands', []):
                        action = cmd.get('action')
                        if action == 'kill_process':
                            target_pid = cmd.get('pid')
                            p_name = cmd.get('name', 'process')
                            try:
                                proc = psutil.Process(target_pid)
                                actual_name = proc.name()
                                proc.terminate()
                                print(f"[ACTIVE RESPONSE] Terminated process '{actual_name}' (PID {target_pid}) via remote command.")
                            except psutil.NoSuchProcess:
                                print(f"[ACTIVE RESPONSE] Process PID {target_pid} already stopped.")
                            except psutil.AccessDenied:
                                print(f"[ACTIVE RESPONSE] Access denied: cannot kill PID {target_pid} (insufficient privileges).")
                            except Exception as exc:
                                print(f"[ACTIVE RESPONSE] Failed to terminate PID {target_pid}: {exc}")
                        elif action in ('send_alert', 'show_alert'):
                            t = cmd.get('title', 'Sentinel Security Alert')
                            m = cmd.get('message', 'Security alert from administrator.')
                            print(f"[ACTIVE RESPONSE] Security alert received from admin: '{m}'")
                            threading.Thread(target=trigger_popup, args=(t, m), daemon=True).start()
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
