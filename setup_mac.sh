#!/bin/bash
set -e

echo "===> Setting up Sentinel Agent Auto-Start for kartavya_Laptop..."

# Move to Downloads and ensure agent.py is present
cd "$HOME/Downloads"
curl -s -O https://raw.githubusercontent.com/kartikkhandelwal4152-max/end-to-end-device-monitoring-/main/agent.py

# Install dependencies if needed
pip3 install psutil requests >/dev/null 2>&1 || true

# Ensure LaunchAgents folder exists on macOS
mkdir -p "$HOME/Library/LaunchAgents"

# Create LaunchAgent plist
PLIST="$HOME/Library/LaunchAgents/com.sentinel.kartavya.plist"
cat << 'EOF' > "$PLIST"
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.sentinel.kartavya</string>
    <key>ProgramArguments</key>
    <array>
        <string>/bin/bash</string>
        <string>-c</string>
        <string>export SENTINEL_DEVICE_TOKEN="LulBkckumzh1a-NlbCQbRJCOfDGOc8h-zMZPxwxwOIY"; cd "$HOME/Downloads"; python3 agent.py --device kartavya_Laptop --server https://sentinel-backend-io5l.onrender.com</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardErrorPath</key>
    <string>/tmp/sentinel.err</string>
    <key>StandardOutPath</key>
    <string>/tmp/sentinel.out</string>
</dict>
</plist>
EOF

# Unload if previously loaded, then load fresh
launchctl unload "$PLIST" 2>/dev/null || true
launchctl load -w "$PLIST"

echo "===> SUCCESS! Sentinel Agent is running in background."
echo "===> It will now auto-start every time your MacBook turns on!"
