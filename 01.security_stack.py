Save as `ztd_01_security_stack.py`

```python
#!/usr/bin/env python3
"""
README
======
File: ztd_01_security_stack.py
Project: Zero Trust Desktop (ZTD)
Stage: 01 - Security Stack
Version: 0.1.2

Purpose
-------
Install and apply a clean, developer-safe baseline security stack for Debian/Ubuntu.

What this script does
---------------------
- Installs missing packages:
  - ufw
  - fail2ban
  - apparmor
  - apparmor-utils
  - apparmor-profiles
  - apparmor-profiles-extra
  - firejail
  - nftables
  - iptables
  - iproute2
- Enables:
  - apparmor
  - fail2ban
- Optionally applies:
  - UFW baseline:
      deny incoming
      allow outgoing
      allow OpenSSH (fallback: 22/tcp)
      enable UFW
- Optionally disables:
  - nginx
  - printing services (cups, cups-browsed)
- Emits:
  - human-readable stdout or JSON stdout
  - JSONL execution log on disk
  - status snapshot at the end

What this script does NOT do
----------------------------
- Does NOT mass-enforce AppArmor profiles
- Does NOT run firecfg
- Does NOT manage nftables/iptables rules directly
- Does NOT install persistent firewall packages
- Does NOT make risky developer-host changes by default

Design notes
------------
- Safe default behavior:
    install missing packages + enable apparmor/fail2ban
- Apply behavior:
    adds UFW baseline only
- Debian/Ubuntu only
- Requires sudo access

Recommended commands
--------------------
Install only:
    python3 ztd_01_security_stack.py --yes

Install + apply firewall baseline:
    python3 ztd_01_security_stack.py --yes --apply

Install + apply + disable printing:
    python3 ztd_01_security_stack.py --yes --apply --disable-printing
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import subprocess
import sys
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Iterable, List, Optional, Tuple


APP_NAME = "Zero Trust Desktop"
APP_ID = "ztd"
STAGE_NAME = "1. Security Stack"
STAGE_ID = "ztd_01_security_stack"
VERSION = "0.1.2"

HOME = Path.home()
STATE_DIR = HOME / ".local" / "state" / "zero-trust-desktop" / "ztd_01"
LOG_DIR = STATE_DIR / "log"
RUN_ID = datetime.now().strftime("%Y%m%d_%H%M%S")
LOG_FILE = LOG_DIR / f"{STAGE_ID}_{RUN_ID}.jsonl"

PKGS_STACK = [
    "ufw",
    "fail2ban",
    "apparmor",
    "apparmor-utils",
    "apparmor-profiles",
    "apparmor-profiles-extra",
    "firejail",
    "nftables",
    "iptables",
    "iproute2",
]


@dataclass
class Settings:
    yes: bool
    json_stdout: bool
    apply: bool
    apply_firewall: bool
    disable_nginx: bool
    disable_printing: bool
    firejail_basic: bool
    log_file: Path


@dataclass
class Event:
    ts: str
    level: str
    msg: str
    data: Optional[dict] = None


def now_ts() -> str:
    return datetime.now().isoformat(timespec="seconds")


def have(cmd: str) -> bool:
    return shutil.which(cmd) is not None


def emit(s: Settings, ev: Event) -> None:
    line = json.dumps(asdict(ev), ensure_ascii=False)

    if s.json_stdout:
        print(line)
    else:
        print(f"[{ev.ts}] {ev.level}: {ev.msg}")
        if ev.data:
            try:
                pretty = json.dumps(ev.data, ensure_ascii=False, indent=2, sort_keys=True)
                print(pretty)
            except Exception:
                print(str(ev.data))

    s.log_file.parent.mkdir(parents=True, exist_ok=True)
    with s.log_file.open("a", encoding="utf-8") as f:
        f.write(line + "\n")


def info(s: Settings, msg: str, data: Optional[dict] = None) -> None:
    emit(s, Event(ts=now_ts(), level="INFO", msg=msg, data=data))


def warn(s: Settings, msg: str, data: Optional[dict] = None) -> None:
    emit(s, Event(ts=now_ts(), level="WARN", msg=msg, data=data))


def error(s: Settings, msg: str, data: Optional[dict] = None) -> None:
    emit(s, Event(ts=now_ts(), level="ERROR", msg=msg, data=data))


def run(
    s: Settings,
    cmd: List[str],
    check: bool = True,
    env: Optional[dict] = None,
) -> Tuple[int, str, str]:
    info(s, "$ " + " ".join(cmd))
    merged_env = os.environ.copy()
    if env:
        merged_env.update(env)

    p = subprocess.run(
        cmd,
        text=True,
        capture_output=True,
        env=merged_env,
    )

    stdout = (p.stdout or "").strip()
    stderr = (p.stderr or "").strip()

    if stdout:
        info(s, "stdout", {"cmd": cmd, "stdout": stdout})
    if stderr:
        warn(s, "stderr", {"cmd": cmd, "stderr": stderr})

    if check and p.returncode != 0:
        error(
            s,
            "Command failed",
            {
                "rc": p.returncode,
                "cmd": cmd,
                "stdout": stdout,
                "stderr": stderr,
            },
        )
        raise RuntimeError(f"Command failed: {' '.join(cmd)} (rc={p.returncode})")

    return p.returncode, stdout, stderr


def sudo(
    s: Settings,
    cmd: List[str],
    check: bool = True,
    env: Optional[dict] = None,
) -> Tuple[int, str, str]:
    return run(s, ["sudo"] + cmd, check=check, env=env)


def require_debian_like(s: Settings) -> None:
    if not Path("/etc/os-release").exists():
        error(s, "Missing /etc/os-release; unsupported platform")
        raise SystemExit(2)

    if not have("apt-get") or not have("dpkg"):
        error(s, "Unsupported platform. Debian/Ubuntu with apt-get/dpkg required.")
        raise SystemExit(2)


def dpkg_installed(pkg: str) -> bool:
    p = subprocess.run(
        ["dpkg", "-s", pkg],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    return p.returncode == 0


def apt_update(s: Settings) -> None:
    sudo(s, ["apt-get", "update"], env={"DEBIAN_FRONTEND": "noninteractive"})


def apt_install_missing(s: Settings, pkgs: Iterable[str]) -> None:
    pkgs = list(pkgs)
    missing = [pkg for pkg in pkgs if not dpkg_installed(pkg)]

    for pkg in pkgs:
        if pkg in missing:
            info(s, f"Installing missing package: {pkg}")
        else:
            info(s, f"Already installed: {pkg}")

    if not missing:
        info(s, "All required packages already present")
        return

    cmd = ["apt-get", "install"]
    if s.yes:
        cmd.append("-y")
    cmd.extend(missing)

    sudo(s, cmd, env={"DEBIAN_FRONTEND": "noninteractive"})


def enable_core_services(s: Settings) -> None:
    info(s, "Enabling core services: apparmor, fail2ban")
    sudo(s, ["systemctl", "enable", "--now", "apparmor"], check=False)
    sudo(s, ["systemctl", "enable", "--now", "fail2ban"], check=False)


def apply_firewall_baseline_ufw(s: Settings) -> None:
    if not s.apply_firewall:
        warn(s, "Skipping firewall apply (use --apply or --apply-firewall)")
        return

    if not have("ufw"):
        warn(s, "ufw not found after install step")
        return

    info(s, "Applying UFW baseline")

    sudo(s, ["ufw", "default", "deny", "incoming"], check=False)
    sudo(s, ["ufw", "default", "allow", "outgoing"], check=False)

    rc, _, _ = sudo(s, ["ufw", "allow", "OpenSSH"], check=False)
    if rc != 0:
        warn(s, "OpenSSH app profile unavailable; falling back to 22/tcp")
        sudo(s, ["ufw", "allow", "22/tcp"], check=False)

    sudo(s, ["ufw", "--force", "enable"], check=False)


def firejail_basic_check(s: Settings) -> None:
    if not s.firejail_basic:
        info(s, "Firejail installed; no integration changes requested")
        return

    if not have("firejail"):
        warn(s, "firejail not found after install step")
        return

    info(s, "Running Firejail basic verification")
    rc, stdout, stderr = run(
        s,
        [
            "bash",
            "-lc",
            "firejail --version; "
            'if [ -d /etc/firejail ]; then echo "profiles_dir_present=yes"; '
            'else echo "profiles_dir_present=no"; fi'
        ],
        check=False,
    )

    info(
        s,
        "Firejail verification complete",
        {
            "rc": rc,
            "stdout": stdout,
            "stderr": stderr,
        },
    )


def disable_optional_services(s: Settings) -> None:
    if s.disable_nginx:
        info(s, "Disabling nginx if present")
        sudo(s, ["systemctl", "disable", "--now", "nginx"], check=False)

    if s.disable_printing:
        info(s, "Disabling printing services if present")
        sudo(s, ["systemctl", "disable", "--now", "cups", "cups-browsed"], check=False)


def collect_cmd_output(command: List[str]) -> str:
    p = subprocess.run(command, text=True, capture_output=True)
    out = (p.stdout or "").strip()
    err = (p.stderr or "").strip()
    if out:
        return out
    return err


def collect_shell_output(command: str) -> str:
    p = subprocess.run(["bash", "-lc", command], text=True, capture_output=True)
    out = (p.stdout or "").strip()
    err = (p.stderr or "").strip()
    if out:
        return out
    return err


def status_report(s: Settings) -> None:
    summary = {
        "app": APP_ID,
        "stage": STAGE_ID,
        "version": VERSION,
        "system": f"{platform.system()} {platform.release()}",
        "arch": platform.machine(),
        "python": sys.version.splitlines()[0],
        "log_file": str(s.log_file),
    }
    info(s, "Status report start", summary)

    if have("systemctl"):
        apparmor_active = collect_cmd_output(["systemctl", "is-active", "apparmor"])
        fail2ban_active = collect_cmd_output(["systemctl", "is-active", "fail2ban"])
        info(
            s,
            "Service state",
            {
                "apparmor": apparmor_active,
                "fail2ban": fail2ban_active,
            },
        )

    if have("aa-status"):
        aa_status = collect_shell_output("aa-status | head -n 40")
        info(s, "AppArmor status", {"output": aa_status or "no output"})

    if have("ufw"):
        ufw_status = collect_cmd_output(["ufw", "status", "verbose"])
        info(s, "UFW status", {"output": ufw_status or "no output"})

    if have("fail2ban-client"):
        fail2ban_status = collect_cmd_output(["fail2ban-client", "status"])
        info(s, "Fail2Ban status", {"output": fail2ban_status or "no output"})

    if have("ss"):
        ports = collect_shell_output("ss -tulnp | grep LISTEN || true")
        info(s, "Listening ports", {"output": ports or "no listening ports found"})

    if have("nft"):
        nft_lines = collect_shell_output("nft list ruleset 2>/dev/null | wc -l")
        info(s, "nftables presence", {"ruleset_lines": nft_lines or "0"})

    if have("iptables"):
        iptables_lines = collect_shell_output("iptables -S 2>/dev/null | wc -l")
        info(s, "iptables presence", {"rules_lines": iptables_lines or "0"})

    info(s, "Status report complete")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="ztd_01_security_stack.py")
    p.add_argument("--yes", action="store_true", help="Use non-interactive apt install (-y)")
    p.add_argument("--json", action="store_true", help="Emit JSON events to stdout")
    p.add_argument(
        "--apply",
        action="store_true",
        help="Apply safe baseline actions for this stage (currently UFW baseline only)",
    )
    p.add_argument(
        "--apply-firewall",
        action="store_true",
        help="Apply UFW baseline and enable UFW",
    )
    p.add_argument(
        "--firejail-basic",
        action="store_true",
        help="Run a non-invasive Firejail verification step",
    )
    p.add_argument(
        "--disable-nginx",
        action="store_true",
        help="Disable nginx if present",
    )
    p.add_argument(
        "--disable-printing",
        action="store_true",
        help="Disable cups/cups-browsed if present",
    )
    return p


def main() -> int:
    args = build_parser().parse_args()

    LOG_DIR.mkdir(parents=True, exist_ok=True)

    apply_firewall = bool(args.apply) or bool(args.apply_firewall)

    s = Settings(
        yes=bool(args.yes),
        json_stdout=bool(args.json),
        apply=bool(args.apply),
        apply_firewall=apply_firewall,
        disable_nginx=bool(args.disable_nginx),
        disable_printing=bool(args.disable_printing),
        firejail_basic=bool(args.firejail_basic),
        log_file=LOG_FILE,
    )

    require_debian_like(s)

    info(
        s,
        f"{APP_NAME} - {STAGE_NAME} start",
        {
            "version": VERSION,
            "run_id": RUN_ID,
            "log_file": str(s.log_file),
        },
    )

    info(s, "[1/7] apt update")
    apt_update(s)

    info(s, "[2/7] install security stack")
    apt_install_missing(s, PKGS_STACK)

    info(s, "[3/7] enable core services")
    enable_core_services(s)

    info(s, "[4/7] apply firewall baseline")
    apply_firewall_baseline_ufw(s)

    info(s, "[5/7] firejail verification")
    firejail_basic_check(s)

    info(s, "[6/7] optional service disables")
    disable_optional_services(s)

    info(s, "[7/7] status report")
    status_report(s)

    info(
        s,
        f"{STAGE_NAME} complete",
        {
            "log_file": str(s.log_file),
        },
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


"""
USAGE
=====
Save:
    ztd_01_security_stack.py

Make executable:
    chmod +x ztd_01_security_stack.py

Run install only:
    python3 ztd_01_security_stack.py --yes

Run install + apply firewall baseline:
    python3 ztd_01_security_stack.py --yes --apply

Run install + apply + firejail check:
    python3 ztd_01_security_stack.py --yes --apply --firejail-basic

Run install + apply + disable printing:
    python3 ztd_01_security_stack.py --yes --apply --disable-printing

Run JSON stdout mode:
    python3 ztd_01_security_stack.py --yes --apply --json

Log location:
    ~/.local/state/zero-trust-desktop/ztd_01/log/

Expected scope:
- Debian/Ubuntu only
- sudo required
- safe end-to-end stage 01 behavior
"""
```
