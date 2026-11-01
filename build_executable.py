"""Utility to compile Sentinel agent into a standalone executable.

Usage:
    python build_executable.py
Requires:
    pip install pyinstaller
"""
import subprocess
import sys

def build():
    print("◈ Building Sentinel Agent Standalone Executable with PyInstaller...")
    try:
        subprocess.check_call([
            sys.executable, "-m", "PyInstaller",
            "--onefile",
            "--name", "sentinel-agent",
            "--clean",
            "agent.py"
        ])
        print("\n✅ Build successful! The executable is located in: dist/sentinel-agent")
    except subprocess.CalledProcessError as e:
        print(f"\n❌ Build failed: {e}")
        print("Please ensure PyInstaller is installed: pip install pyinstaller")

if __name__ == '__main__':
    build()
