"""Batch onboard devices to Sentinel backend. Run `python onboard.py --help`."""
import argparse
import getpass
import os
from pathlib import Path
import sys
import requests

def main():
    parser = argparse.ArgumentParser(description="Batch onboard devices to Sentinel")
    parser.add_argument(
        '--server',
        default=os.environ.get('SENTINEL_SERVER_URL', 'http://localhost:8000'),
        help="Backend server URL (defaults to SENTINEL_SERVER_URL or http://localhost:8000)"
    )
    parser.add_argument(
        '--admin-token',
        default=os.environ.get('SENTINEL_ADMIN_TOKEN'),
        help="Sentinel administrator token (or set SENTINEL_ADMIN_TOKEN env var; prompted if omitted)"
    )
    parser.add_argument(
        '--save-dir',
        type=Path,
        default=None,
        help="Optional directory to save individual restricted-permission agent config files"
    )
    parser.add_argument('devices', nargs='+', help="Device IDs to onboard (e.g. DEVICE-01 DEVICE-02 ...)")
    args = parser.parse_args()

    admin_token = args.admin_token
    if not admin_token:
        try:
            admin_token = getpass.getpass("Sentinel Admin Token: ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\nAborted.")
            sys.exit(1)
        if not admin_token:
            print("Error: Administrator token is required.", file=sys.stderr)
            sys.exit(1)

    server = args.server.rstrip('/')
    headers = {
        'Authorization': f'Bearer {admin_token}',
        'Content-Type': 'application/json'
    }

    print(f"\nOnboarding {len(args.devices)} device(s) to {server}...\n")
    print(f"{'Device ID':<20} | {'Status':<10} | {'Device Token / Error'}")
    print("-" * 75)

    results = []
    for device_id in args.devices:
        url = f"{server}/api/devices/register"
        try:
            res = requests.post(url, headers=headers, json={'device_id': device_id}, timeout=15)
            if res.status_code == 201:
                token = res.json().get('token')
                masked = token[:6] + '...' + token[-4:] if len(token) > 10 else '********'
                print(f"{device_id:<20} | {'SUCCESS':<10} | {masked}")
                results.append((device_id, token))
            elif res.status_code == 409:
                print(f"{device_id:<20} | {'EXISTS':<10} | Device already registered (use rotation to change token)")
            else:
                err = res.json().get('error', res.text)
                print(f"{device_id:<20} | {'FAILED':<10} | {err}")
        except Exception as e:
            print(f"{device_id:<20} | {'ERROR':<10} | {str(e)}")

    if args.save_dir and results:
        args.save_dir.mkdir(parents=True, exist_ok=True)
        for dev, tok in results:
            cfg_path = args.save_dir / f"{dev}.env"
            with cfg_path.open('w') as f:
                f.write(f'SENTINEL_DEVICE_ID="{dev}"\n')
                f.write(f'SENTINEL_SERVER_URL="{server}"\n')
                f.write(f'SENTINEL_DEVICE_TOKEN="{tok}"\n')
            cfg_path.chmod(0o600)
        print(f"\nDevice configs securely saved to {args.save_dir} with 0600 permissions.")
    elif results:
        print("\n" + "=" * 75)
        print("AGENT ENROLLMENT TOKENS (Transmit securely to authorized endpoints):")
        print("=" * 75)
        for dev, tok in results:
            print(f"Device: {dev}")
            print(f"Token:  {tok}")
            print(f"Run:    python agent.py --device {dev} --server {server}\n")

if __name__ == '__main__':
    main()
