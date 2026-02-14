#!/usr/bin/env python3

import os
import pathlib
import subprocess
import shutil
import stat

HOME = pathlib.Path.home()
DESKTOP = HOME / "Desktop"

def section(title):
    print("\n" + "=" * 50)
    print(title)
    print("=" * 50)

def run(cmd):
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        return result.stdout.strip(), result.stderr.strip()
    except Exception as e:
        return "", str(e)

section("PATH CHECK")

print("Desktop path:", DESKTOP)

if DESKTOP.exists():
    print("✔ Desktop exists")
else:
    print("✘ Desktop missing")
    exit()

if DESKTOP.is_dir():
    print("✔ Is directory")
else:
    print("✘ Not a directory")

section("PERMISSION CHECK")

st = DESKTOP.stat()

owner_ok = (st.st_uid == os.getuid())

print("Owner UID:", st.st_uid)
print("Your UID:", os.getuid())

if owner_ok:
    print("✔ Ownership correct")
else:
    print("✘ Ownership mismatch → possible fix:")
    print(f"  sudo chown -R {os.getlogin()}:{os.getlogin()} {DESKTOP}")

perms = stat.filemode(st.st_mode)
print("Permissions:", perms)

if os.access(DESKTOP, os.R_OK):
    print("✔ Read access")
else:
    print("✘ No read access")

section("CONTENT CHECK")

try:
    items = list(DESKTOP.iterdir())
    print(f"Items found: {len(items)}")
    for i in items[:10]:
        print(" -", i)
except Exception as e:
    print("✘ Cannot list contents:", e)

section("DISK CHECK")

stdout, stderr = run("df -h ~")
print(stdout)

section("FILE MANAGER CHECK")

fm = shutil.which("nautilus") or shutil.which("dolphin") or shutil.which("thunar")

if fm:
    print("File manager found:", fm)
else:
    print("✘ No file manager detected")

section("XDG OPEN TEST")

stdout, stderr = run(f"xdg-open {DESKTOP}")

if stderr:
    print("xdg-open error:", stderr)
else:
    print("xdg-open command sent (may open window)")

section("PROCESS CHECK")

stdout, _ = run("ps aux | grep -E 'nautilus|dolphin|thunar' | grep -v grep")
print(stdout if stdout else "No file manager process running")

section("COMMON FIX SUGGESTIONS")

print("""
If Desktop won't open but script works:

1. Restart file manager:
   nautilus -q

2. Reset permissions:
   chmod 755 ~/Desktop

3. Recreate Desktop:
   mv ~/Desktop ~/Desktop_backup
   mkdir ~/Desktop

4. Check disk errors:
   sudo dmesg | grep -i error

""")

print("\nDone.")
