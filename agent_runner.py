"""Read enrollment JSON as data, never as shell commands."""
import json
import os
from pathlib import Path
import sys
root = Path(__file__).resolve().parent
config = json.loads((root / 'agent.json').read_text())
os.environ['SENTINEL_DEVICE_TOKEN'] = config['token']
os.execv(sys.executable, [sys.executable, str(root/'agent.py'), '--device', config['device'], '--server', config['server']])
