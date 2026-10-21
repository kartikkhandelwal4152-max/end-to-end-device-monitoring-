"""Batch onboard devices to Sentinel backend. Run `python onboard.py --help`."""
import argparse
import sys
import requests

def main():
    parser = argparse.ArgumentParser(description="Batch onboard devices to Sentinel")
    parser.add_argument('--server', default='https://sentinel-backend-io5l.onrender.com', help="Backend server URL")
    parser.add_argument('--admin-token', required=True, help="Sentinel administrator token")
    parser.add_argument('devices', nargs='+', help="Device IDs to onboard (e.g. DEVICE-01 DEVICE-02 ...)")
    args = parser.parse_args()

    server = args.server.rstrip('/')
    headers = {
        'Authorization': f'Bearer {args.admin_token}',
        'Content-Type': 'application/json'
    }

    print(f"\nOnboarding {len(args.devices)} devices to {server}...\n")
    print(f"{'Device ID':<18} | {'Status':<10} | {'Device Token / Error'}")
    print("-" * 75)

    results = []
    for device_id in args.devices:
        url = f"{server}/api/devices/register"
        try:
            res = requests.post(url, headers=headers, json={'device_id': device_id}, timeout=15)
            if res.status_code == 201:
                token = res.json().get('token')
                print(f"{device_id:<18} | {'SUCCESS':<10} | {token}")
                results.append((device_id, token))
            else:
                err = res.json().get('error', res.text)
                print(f"{device_id:<18} | {'FAILED':<10} | {err}")
        except Exception as e:
            print(f"{device_id:<18} | {'ERROR':<10} | {str(e)}")

    if results:
        print("\n" + "=" * 75)
        print("READY-TO-USE COMMANDS FOR EACH AGENT:")
        print("=" * 75)
        for dev, tok in results:
            print(f"# Device: {dev}")
            print(f"python agent.py --device {dev} --server {server}")
            print(f"Device token: {tok}\n")

if __name__ == '__main__':
    main()
