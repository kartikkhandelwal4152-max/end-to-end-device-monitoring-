"""Foreground endpoint agent. Collect only on devices you administer."""
import argparse
import math
from collections import deque
import getpass
import glob
import hashlib
import json
import os
from pathlib import Path
import platform
import random
import re
import shutil
import sqlite3
import tempfile
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


def redact_cmdline(cmd_list):
    """Redact sensitive arguments (passwords, tokens, keys) from process command lines."""
    if not cmd_list:
        return []
    redacted = []
    sensitive_pattern = re.compile(
        r'^(?:--?(?:password|passwd|pwd|token|api[_-]?key|secret|auth|bearer|pass|credential)[=\s:])(.*)$',
        re.IGNORECASE
    )
    for arg in cmd_list:
        arg_str = str(arg)
        m = sensitive_pattern.match(arg_str)
        if m:
            prefix = arg_str[:m.start(1)]
            redacted.append(f"{prefix}[REDACTED]")
        elif any(s in arg_str.lower() for s in ('password=', 'token=', 'api_key=', 'apikey=', 'secret=')):
            redacted.append("[REDACTED_SECRET]")
        else:
            redacted.append(arg_str[:150])
    return redacted


class Collector:
    def __init__(self, log=None, process_limit=100, enable_browser_history=False,
                 enable_active_window=False, domain_only_history=True, collect_cmdline=False):
        self.auth = AuthLog(log)
        self.process_limit = process_limit
        self.enable_browser_history = enable_browser_history
        self.enable_active_window = enable_active_window
        self.domain_only_history = domain_only_history
        self.collect_cmdline = collect_cmdline
        self.last_io = psutil.net_io_counters()
        self.last_time = time.monotonic()
        self.seen_windows = deque(maxlen=20)
        self.seen_history_visits = set()
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
        collected_pids = set()
        for process in psutil.process_iter(['pid', 'name', 'create_time', 'ppid', 'exe', 'cmdline'], ad_value=None):
            try:
                if len(processes) < self.process_limit:
                    info = process.info
                    pid = info['pid']
                    if pid in collected_pids:
                        continue
                    collected_pids.add(pid)
                    p_entry = {
                        'pid': pid,
                        'name': (info['name'] or 'unavailable')[:200]
                    }
                    if info.get('create_time') is not None:
                        p_entry['create_time'] = float(info['create_time'])
                    if info.get('ppid') is not None:
                        p_entry['ppid'] = int(info['ppid'])
                    if info.get('exe'):
                        p_entry['exe'] = str(info['exe'])[:250]
                    if self.collect_cmdline and info.get('cmdline'):
                        p_entry['cmdline'] = redact_cmdline(info['cmdline'])
                    processes.append(p_entry)
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

        active_window = None
        if self.enable_active_window:
            win_title = get_active_window()
            if win_title and any(delim in win_title for delim in (' - ', ' — ', ' | ', 'http', '.com', '.org', '.net', '.in', 'www.', 'Edge', 'Chrome', 'Firefox', 'Brave')):
                active_window = win_title
                if not self.seen_windows or self.seen_windows[-1].get('title') != active_window:
                    self.seen_windows.append({'url': active_window, 'title': active_window})

        combined_history = []
        if self.enable_browser_history:
            raw_history = get_recent_browser_history(limit=15, domain_only=self.domain_only_history)
            for item in raw_history:
                key = (item.get('domain') or item.get('url'), round(item.get('visit_time', 0), 1))
                if key not in self.seen_history_visits:
                    self.seen_history_visits.add(key)
                    combined_history.append(item)
            if len(self.seen_history_visits) > 2000:
                self.seen_history_visits = set(list(self.seen_history_visits)[-1000:])

        ip_address = get_local_ip()
        removable_drives = get_removable_drives()
        agent_hash = get_self_hash()
        return {'sample_id': uuid.uuid4().hex, 'observed': time.time(), 'cpu': cpu,
                'ram': psutil.virtual_memory().percent, 'process_count': len(psutil.pids()),
                'connections': connections, 'bytes_per_second': rate,
                'failed_logins': failures, 'processes': processes, 'warnings': warnings,
                'disk': disk, 'battery': battery, 'is_plugged': is_plugged,
                'os_info': os_info, 'hostname': hostname, 'uptime': uptime,
                'active_window': active_window, 'ip_address': ip_address,
                'browser_history': combined_history,
                'removable_drives': removable_drives,
                'agent_hash': agent_hash}


def get_self_hash():
    try:
        content = Path(__file__).resolve().read_bytes()
        return hashlib.sha256(content).hexdigest()[:16]
    except Exception:
        return 'unknown'


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


def get_removable_drives():
    drives = []
    try:
        for p in psutil.disk_partitions(all=True):
            opts = (p.opts or '').lower()
            mp = p.mountpoint
            if platform.system() == 'Windows':
                if 'removable' in opts or 'cdrom' in opts:
                    drives.append(p.device or mp)
            elif platform.system() == 'Darwin':
                if mp.startswith('/Volumes/') and not mp.startswith('/Volumes/Macintosh') and mp != '/':
                    drives.append(mp.replace('/Volumes/', ''))
            else:
                if mp.startswith('/media/') or mp.startswith('/run/media/') or 'removable' in opts:
                    drives.append(mp)
    except Exception:
        pass
    return sorted(list(set(drives)))


def extract_domain(raw_url):
    try:
        parsed = urlparse(raw_url if '://' in raw_url else 'http://' + raw_url)
        return (parsed.hostname or parsed.netloc or '').lower()
    except Exception:
        return ''


def get_recent_browser_history(limit=10, domain_only=True):
    candidates = []
    local_app_data = os.environ.get('LOCALAPPDATA', '')
    app_data = os.environ.get('APPDATA', '')
    if local_app_data:
        candidates.extend(glob.glob(os.path.join(local_app_data, 'Google/Chrome/User Data/*/History')))
        candidates.extend(glob.glob(os.path.join(local_app_data, 'Microsoft/Edge/User Data/*/History')))
        candidates.extend(glob.glob(os.path.join(local_app_data, 'BraveSoftware/Brave-Browser/User Data/*/History')))
    if app_data:
        candidates.extend(glob.glob(os.path.join(app_data, 'Mozilla/Firefox/Profiles/*/places.sqlite')))

    home = os.path.expanduser('~')
    candidates.extend(glob.glob(os.path.join(home, 'Library/Application Support/Google/Chrome/*/History')))
    candidates.extend(glob.glob(os.path.join(home, 'Library/Application Support/Microsoft Edge/*/History')))
    candidates.extend(glob.glob(os.path.join(home, 'Library/Application Support/BraveSoftware/Brave-Browser/*/History')))
    candidates.extend(glob.glob(os.path.join(home, 'Library/Application Support/Firefox/Profiles/*/places.sqlite')))
    candidates.extend(glob.glob(os.path.join(home, '.config/google-chrome/*/History')))
    candidates.extend(glob.glob(os.path.join(home, '.config/microsoft-edge/*/History')))
    candidates.extend(glob.glob(os.path.join(home, '.mozilla/firefox/*/places.sqlite')))

    history_items = []
    tmp_dir = tempfile.gettempdir()
    for db_path in candidates:
        if not os.path.isfile(db_path) or 'System Profile' in db_path:
            continue
        tmp_copy = os.path.join(tmp_dir, f'sentinel_h_{os.getpid()}_{os.path.basename(db_path)}')
        try:
            shutil.copyfile(db_path, tmp_copy)
            conn = sqlite3.connect(tmp_copy, timeout=2)
            cur = conn.cursor()
            if 'places.sqlite' in db_path:
                cur.execute('SELECT url, title, last_visit_date FROM moz_places WHERE last_visit_date IS NOT NULL ORDER BY last_visit_date DESC LIMIT ?', (limit,))
                for row in cur.fetchall():
                    raw_url = row[0]
                    if raw_url:
                        ts = float(row[2]) / 1000000.0 if row[2] else time.time()
                        domain = extract_domain(raw_url)
                        url_stored = f"https://{domain}/[path_redacted]" if domain_only and domain else raw_url[:250]
                        history_items.append({'domain': domain, 'url': url_stored, 'title': (row[1] or '')[:150], 'visit_time': ts})
            else:
                cur.execute('SELECT url, title, last_visit_time FROM urls WHERE last_visit_time IS NOT NULL ORDER BY last_visit_time DESC LIMIT ?', (limit,))
                for row in cur.fetchall():
                    raw_url = row[0]
                    if raw_url:
                        raw_ts = row[2]
                        if raw_ts and raw_ts > 11644473600000000:
                            ts = (raw_ts - 11644473600000000) / 1000000.0
                        else:
                            ts = time.time()
                        domain = extract_domain(raw_url)
                        url_stored = f"https://{domain}/[path_redacted]" if domain_only and domain else raw_url[:250]
                        history_items.append({'domain': domain, 'url': url_stored, 'title': (row[1] or '')[:150], 'visit_time': ts})
            conn.close()
        except Exception:
            pass
        finally:
            if os.path.exists(tmp_copy):
                try: os.remove(tmp_copy)
                except Exception: pass
        if len(history_items) >= limit:
            break
    return history_items[:limit]


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
            # Use AppleScript handler with arguments to avoid script injection; give up after 1s to prevent blocking
            apple_script = 'on run argv\n  display alert (item 1 of argv) message (item 2 of argv) giving up after 1\nend run'
            subprocess.run(['osascript', '-e', apple_script, str(title), str(message)], timeout=5, stderr=subprocess.DEVNULL, check=True)
        else:
            import subprocess
            subprocess.run(['notify-send', str(title), str(message)], timeout=10, stderr=subprocess.DEVNULL, check=True)
        return True
    except Exception as e:
        print("[ACTIVE RESPONSE] Notification utility failed.")
        return False


def safe_terminate_process(target_pid, expected_name=None, expected_create_time=None, expected_path=None):
    """Safely terminate a target process with PID reuse and protected process verification."""
    if type(target_pid) is not int or target_pid <= 0:
        return False, 'Invalid PID.'
    my_pid = os.getpid()
    parent_pid = os.getppid()
    if target_pid in (0, 1, 4, my_pid, parent_pid):
        return False, f"Refused: PID {target_pid} is a protected process (self/parent/system)."

    if not isinstance(expected_create_time, (int, float)) or isinstance(expected_create_time, bool) or not math.isfinite(expected_create_time) or expected_create_time <= 0 or not expected_name:
        return False, 'Process name and finite creation time are required.'

    if not psutil.pid_exists(target_pid):
        return True, f"Process PID {target_pid} already exited."

    try:
        proc = psutil.Process(target_pid)
    except psutil.NoSuchProcess:
        return True, f"Process PID {target_pid} already exited."
    except psutil.AccessDenied:
        return False, f"Access denied: insufficient privileges to inspect PID {target_pid}."

    try:
        actual_name = proc.name()
        actual_create_time = proc.create_time()
    except (psutil.NoSuchProcess, psutil.AccessDenied) as exc:
        return False, f"Failed to query process metadata for PID {target_pid}: {exc}"

    # Critical OS system processes protection list
    protected_names = {
        'system', 'idle', 'kernel_task', 'launchd', 'init', 'systemd',
        'csrss.exe', 'smss.exe', 'wininit.exe', 'services.exe', 'lsass.exe',
        'svchost.exe', 'explorer.exe', 'winlogon.exe'
    }
    if actual_name.lower() in protected_names:
        return False, f"Refused: '{actual_name}' is a protected system process."

    # Verify process creation time to protect against PID reuse
    if expected_create_time is not None:
        if abs(actual_create_time - expected_create_time) > 0.001:
            return False, (
                f"PID reuse detected: running process create_time ({actual_create_time:.2f}) "
                f"differs from expected ({expected_create_time:.2f}). Refusing termination."
            )

    # Verify process executable name
    if expected_name:
        clean_exp = os.path.basename(expected_name).lower().removesuffix('.exe')
        clean_act = os.path.basename(actual_name).lower().removesuffix('.exe')
        if clean_exp != clean_act:
            return False, f"Process identity mismatch: expected '{expected_name}' but found '{actual_name}'. Refusing termination."

    if expected_path:
        try:
            if os.path.normcase(os.path.realpath(proc.exe())) != os.path.normcase(os.path.realpath(expected_path)):
                return False, 'Process executable path mismatch.'
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return False, 'Cannot verify executable path.'

    # Attempt graceful termination followed by verified exit check
    try:
        proc.terminate()
        try:
            proc.wait(timeout=3.0)
            return True, f"Verified process exit: '{actual_name}' (PID {target_pid}) terminated successfully."
        except psutil.TimeoutExpired:
            proc.kill()
            try:
                proc.wait(timeout=2.0)
                return True, f"Verified process exit (forced kill): '{actual_name}' (PID {target_pid}) terminated."
            except psutil.TimeoutExpired:
                return False, f"Termination requested but process PID {target_pid} is still alive."
    except (psutil.NoSuchProcess, psutil.ZombieProcess):
        return True, f"Verified process exit: PID {target_pid} stopped."
    except psutil.AccessDenied:
        return False, f"Access denied: privilege elevation required to terminate PID {target_pid}."
    except Exception as exc:
        return False, f"Unexpected error terminating PID {target_pid}: {exc}"


class CommandReceiptStore:
    """Durable command journal; interrupted actions are not automatically repeated."""
    def __init__(self, filepath):
        self.path = Path(filepath)
        self._receipts = {}
        self._load()

    def _load(self):
        if self.path.exists():
            try:
                self._receipts = json.loads(self.path.read_text())
                for receipt in self._receipts.values():
                    if receipt.get('status') == 'executing':
                        receipt.update(status='failed', result='Interrupted action: outcome unknown; operator must inspect endpoint.', acked=False)
                self._save()
            except Exception as exc:
                raise RuntimeError('Command journal is unreadable; refusing remote actions.') from exc

    def _save(self):
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix('.tmp')
            with os.fdopen(os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), 'w') as handle:
                json.dump(self._receipts, handle)
                handle.flush()
                os.fsync(handle.fileno())
            tmp.replace(self.path)
            try:
                self.path.chmod(0o600)
            except Exception:
                pass
        except Exception as e:
            raise RuntimeError('Cannot persist command journal; remote action stopped.') from e

    def has(self, cmd_id):
        return str(cmd_id) in self._receipts

    def record(self, cmd_id, status, result):
        self._receipts[str(cmd_id)] = {
            'status': status,
            'result': str(result)[:500],
            'timestamp': time.time(),
            'acked': False
        }
        self._save()

    def get_unacked(self):
        unacked = []
        for cid, r in self._receipts.items():
            if not r.get('acked'):
                try:
                    num_id = int(cid)
                except ValueError:
                    num_id = cid
                unacked.append({'id': num_id, 'status': r['status'], 'result': r['result']})
        return unacked

    def mark_acked(self, cmd_id):
        cid = str(cmd_id)
        if cid in self._receipts:
            self._receipts[cid]['acked'] = True
            self._save()


class TelemetryDiskQueue:
    """Bounded, persistent disk-backed queue for telemetry samples with exponential backoff and jitter."""
    def __init__(self, db_path, max_samples=5000, max_retention=604800):
        self.db_path = Path(db_path)
        self.max_samples = max_samples
        self.max_retention = max_retention
        self.lock = threading.Lock()
        self.stats = {
            'enqueued': 0,
            'delivered': 0,
            'dropped_full': 0,
            'dropped_stale': 0
        }
        self._init_db()

    def _connect(self):
        conn = sqlite3.connect(str(self.db_path), timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        try:
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            try:
                self.db_path.parent.chmod(0o700)
            except Exception:
                pass
        except Exception:
            pass
        with self._connect() as db:
            db.execute('PRAGMA journal_mode=WAL')
            db.execute('''
                CREATE TABLE IF NOT EXISTS queue (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    sample_id TEXT UNIQUE NOT NULL,
                    observed REAL NOT NULL,
                    payload TEXT NOT NULL,
                    attempts INTEGER NOT NULL DEFAULT 0,
                    next_retry REAL NOT NULL,
                    created REAL NOT NULL
                )
            ''')
            db.execute('CREATE INDEX IF NOT EXISTS queue_next_retry ON queue(next_retry)')
        try:
            self.db_path.chmod(0o600)
        except Exception:
            pass

    def push(self, sample_dict):
        now = time.time()
        with self.lock, self._connect() as db:
            # Enforce max capacity: evict oldest
            count = db.execute('SELECT COUNT(*) FROM queue').fetchone()[0]
            if count >= self.max_samples:
                db.execute('DELETE FROM queue WHERE id = (SELECT id FROM queue ORDER BY id ASC LIMIT 1)')
                self.stats['dropped_full'] += 1
                print('[DISK QUEUE] Queue capacity reached: oldest sample dropped.')

            # Drop stale samples older than max_retention (default 7 days)
            stale_threshold = now - self.max_retention
            cur = db.execute('DELETE FROM queue WHERE observed < ?', (stale_threshold,))
            if cur.rowcount > 0:
                self.stats['dropped_stale'] += cur.rowcount
                print(f'[DISK QUEUE] Dropped {cur.rowcount} stale samples older than {self.max_retention}s.')

            sample_id = sample_dict.get('sample_id', uuid.uuid4().hex)
            observed = float(sample_dict.get('observed', now))
            db.execute(
                'INSERT OR REPLACE INTO queue (sample_id, observed, payload, attempts, next_retry, created) VALUES (?, ?, ?, 0, ?, ?)',
                (sample_id, observed, json.dumps(sample_dict), now, now)
            )
            self.stats['enqueued'] += 1

    def peek(self):
        """Get next deliverable sample ready for transmission."""
        now = time.time()
        with self.lock, self._connect() as db:
            row = db.execute(
                'SELECT id, sample_id, observed, payload, attempts FROM queue WHERE next_retry <= ? ORDER BY id ASC LIMIT 1',
                (now,)
            ).fetchone()
            if row:
                return {
                    'id': row['id'],
                    'sample_id': row['sample_id'],
                    'observed': row['observed'],
                    'payload': json.loads(row['payload']),
                    'attempts': row['attempts']
                }
            return None

    def pop(self, sample_id):
        """Remove successfully delivered sample."""
        with self.lock, self._connect() as db:
            db.execute('DELETE FROM queue WHERE sample_id = ?', (sample_id,))
            self.stats['delivered'] += 1

    def mark_failure(self, sample_id, error_str=None):
        """Apply exponential backoff with jitter on transmission failure."""
        now = time.time()
        with self.lock, self._connect() as db:
            row = db.execute('SELECT attempts FROM queue WHERE sample_id = ?', (sample_id,)).fetchone()
            if row:
                attempts = row['attempts'] + 1
                base_delay = min(120.0, 2.0 * (1.8 ** min(attempts, 8)))
                jitter = random.uniform(0.8, 1.2)
                delay = base_delay * jitter
                next_retry = now + delay
                db.execute(
                    'UPDATE queue SET attempts = ?, next_retry = ? WHERE sample_id = ?',
                    (attempts, next_retry, sample_id)
                )

    def size(self):
        with self.lock, self._connect() as db:
            return db.execute('SELECT COUNT(*) FROM queue').fetchone()[0]


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
    parser.add_argument('--device', default=None)
    parser.add_argument('--interval', type=float, default=10)
    parser.add_argument('--auth-log', help='Linux OpenSSH log, e.g. /var/log/auth.log')
    parser.add_argument('--ca', help='CA certificate bundle for a private HTTPS server')
    parser.add_argument('--allow-local-http', action='store_true')
    parser.add_argument('--once', action='store_true')
    parser.add_argument('--enable-browser-history', action='store_true', help='Opt-in to browser history collection (disabled by default)')
    parser.add_argument('--enable-active-window', action='store_true', help='Opt-in to active window title collection (disabled by default)')
    parser.add_argument('--full-urls', action='store_true', help='Collect full URLs rather than domain-only')
    parser.add_argument('--collect-cmdline', action='store_true', help='Collect redacted process command lines')
    parser.add_argument('--process-limit', type=int, default=100, help='Max process inventory per sample')
    parser.add_argument('--uninstall', action='store_true', help='Safely uninstall and remove local sentinel data directory (~/.sentinel)')
    args = parser.parse_args()

    if args.uninstall:
        target_dir = Path.home() / '.sentinel'
        if target_dir.exists():
            shutil.rmtree(target_dir, ignore_errors=True)
            print(f"Sentinel agent local data removed: {target_dir}")
        else:
            print("Sentinel agent directory not found; already clean.")
        return

    if not args.device:
        parser.error('--device is required when running the agent.')

    args.server = args.server.rstrip('/\\')
    try:
        validate_url(args.server, args.allow_local_http)
        if not 1 <= args.interval <= 300:
            raise ValueError('Interval must be between 1 and 300 seconds.')
    except ValueError as exc:
        parser.error(str(exc))
    token = os.environ.get('SENTINEL_DEVICE_TOKEN') or getpass.getpass('Device token: ')
    collector = Collector(
        log=args.auth_log,
        process_limit=args.process_limit,
        enable_browser_history=args.enable_browser_history,
        enable_active_window=args.enable_active_window,
        domain_only_history=not args.full_urls,
        collect_cmdline=args.collect_cmdline
    )
    session = requests.Session()
    session.headers.update({'Authorization': 'Bearer '+token, 'X-Device-ID': args.device})
    receipts_dir = Path.home() / '.sentinel' / hashlib.sha256(args.server.encode()).hexdigest()[:16]
    receipt_store = CommandReceiptStore(receipts_dir / f"receipts_{re.sub(r'[^A-Za-z0-9_-]', '', args.device)}.json")
    disk_queue = TelemetryDiskQueue(receipts_dir / f"telemetry_{re.sub(r'[^A-Za-z0-9_-]', '', args.device)}.db")
    print('Monitoring started. Ctrl+C stops the agent. Telemetry buffered in durable disk queue.')
    try:
        while True:
            sample = collector.sample()
            disk_queue.push(sample)
            while True:
                entry = disk_queue.peek()
                if not entry:
                    break
                try:
                    response = session.post(
                        args.server.rstrip('/') + '/api/telemetry',
                        json=entry['payload'],
                        verify=args.ca or True,
                        timeout=10,
                        allow_redirects=False
                    )
                    if response.status_code in (401, 403):
                        raise SystemExit('Authentication rejected; check device registration and token.')
                    if 300 <= response.status_code < 400:
                        raise SystemExit('Redirect refused; supply the exact HTTPS origin.')
                    if response.status_code in (400, 413):
                        disk_queue.pop(entry['sample_id'])
                        print('Invalid sample rejected by server; dropped.')
                        continue
                    response.raise_for_status()
                    data = response.json()
                    disk_queue.pop(entry['sample_id'])
                    print('Telemetry delivered.')

                    # Send any unacknowledged receipts
                    for unacked in receipt_store.get_unacked():
                        try:
                            ack_res = session.post(
                                args.server.rstrip('/') + f"/api/commands/{unacked['id']}/ack",
                                json={'status': unacked['status'], 'result': unacked['result']},
                                verify=args.ca or True,
                                timeout=5, allow_redirects=False
                            )
                            if ack_res.status_code == 200:
                                receipt_store.mark_acked(unacked['id'])
                        except Exception:
                            pass

                    # Process commands received from server
                    for cmd in data.get('commands', []):
                        cmd_id = cmd.get('id')
                        action = cmd.get('action')
                        if receipt_store.has(cmd_id):
                            continue
                        if not isinstance(cmd.get('expires_at'), (int, float)) or time.time() >= cmd['expires_at']:
                            receipt_store.record(cmd_id, 'failed', 'Command expired or missing expiry.')
                            continue
                        receipt_store.record(cmd_id, 'executing', 'Execution started; outcome not yet confirmed.')
                        if action == 'kill_process':
                            ok, msg = safe_terminate_process(
                                cmd.get('pid'),
                                expected_name=cmd.get('name'),
                                expected_create_time=cmd.get('create_time'),
                                expected_path=cmd.get('path')
                            )
                            status = 'succeeded' if ok else 'failed'
                            receipt_store.record(cmd_id, status, msg)
                            print(f"[ACTIVE RESPONSE] Command #{cmd_id} kill_process: {msg}")
                        elif action in ('send_alert', 'show_alert'):
                            t = cmd.get('title', 'Sentinel Security Alert')
                            m = cmd.get('message', 'Security alert from administrator.')
                            ok = trigger_popup(t, m)
                            receipt_store.record(cmd_id, 'succeeded' if ok else 'failed', 'Notification utility completed.' if ok else 'Notification utility failed; display unverified.')
                            print(f"[ACTIVE RESPONSE] Command #{cmd_id} send_alert: '{m}'")
                        else:
                            receipt_store.record(cmd_id, 'failed', f"Unsupported action: '{action}'")

                        # Immediately attempt to acknowledge
                        try:
                            rec = receipt_store._receipts.get(str(cmd_id))
                            if rec and not rec.get('acked'):
                                ack_res = session.post(
                                    args.server.rstrip('/') + f"/api/commands/{cmd_id}/ack",
                                    json={'status': rec['status'], 'result': rec['result']},
                                    verify=args.ca or True,
                                    timeout=5, allow_redirects=False
                                )
                                if ack_res.status_code == 200:
                                    receipt_store.mark_acked(cmd_id)
                        except Exception:
                            pass
                except requests.RequestException:
                    disk_queue.mark_failure(entry['sample_id'])
                    print('Server unavailable or TLS verification failed; preserving sample for retry.')
                    break
            if args.once:
                if disk_queue.size() > 0:
                    raise SystemExit('Sample was not delivered; run continuously to retry.')
                return
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print('\nAgent stopped.')
    finally:
        session.close()


if __name__ == '__main__':
    main()
