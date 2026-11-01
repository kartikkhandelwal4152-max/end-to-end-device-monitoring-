"""Sentinel Agent Watchdog Supervisor (Anti-Tamper & Auto-Restart).

Relaunches Sentinel agent automatically if terminated or killed.
Usage:
    python watchdog.py --device <DEVICE_ID> --server <SERVER_URL>
"""
import os
import signal
import subprocess
import sys
import time

def main():
    agent_script = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'agent.py')
    cmd = [sys.executable, agent_script] + sys.argv[1:]

    print("=" * 60)
    print("◈ SENTINEL WATCHDOG ACTIVE DEFENSE SUPERVISOR STARTED")
    print(f"◈ Supervised target: {agent_script}")
    print("◈ Self-Defense Policy: Instant auto-respawn on termination")
    print("=" * 60, flush=True)

    running_proc = None

    def handle_sigint(sig, frame):
        print("\n[WATCHDOG] Received shutdown signal. Terminating agent...", flush=True)
        if running_proc and running_proc.poll() is None:
            try:
                running_proc.terminate()
                running_proc.wait(timeout=3)
            except Exception:
                pass
        sys.exit(0)

    signal.signal(signal.SIGINT, handle_sigint)
    signal.signal(signal.SIGTERM, handle_sigint)

    restart_count = 0
    while True:
        try:
            print(f"[WATCHDOG] Launching Sentinel Agent (Execution #{restart_count + 1})...", flush=True)
            running_proc = subprocess.Popen(cmd)
            exit_code = running_proc.wait()

            # If agent exited cleanly via normal flag or system exit
            print(f"\n[WATCHDOG TAMPER DETECTED] Agent exited with code {exit_code}.", flush=True)
            restart_count += 1
            print(f"[WATCHDOG ACTIVE DEFENSE] Restarting agent in 2 seconds (Recovery #{restart_count})...\n", flush=True)
            time.sleep(2)
        except Exception as exc:
            print(f"[WATCHDOG ERROR] {exc}. Retrying in 3 seconds...", flush=True)
            time.sleep(3)

if __name__ == '__main__':
    main()
