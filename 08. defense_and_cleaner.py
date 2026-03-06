#!/usr/bin/env python3
"""
README
======

Filename:
    ztd_08_defense_and_cleaner.py

Project:
    Zero Trust Desktop (ZTD)

Stage:
    08 — Defense + Cleaner

Purpose
-------

Stage 08 installs baseline defensive tooling, captures an auditable
security posture snapshot, optionally runs malware / integrity checks,
and optionally performs safe cleanup operations.

The script is designed to be:

    • Safe by default
    • Fully auditable
    • Idempotent
    • Location independent
    • Suitable for repeat rebuild workflows

Default Behavior
----------------

When run with no flags:

    1. Validates platform
    2. Runs apt update
    3. Installs missing defense packages
    4. Captures system snapshots
    5. Produces JSONL audit logs

No scans run.
No files are deleted.
No system state is modified beyond package installation.

Explicit Opt-In Operations
--------------------------

--run-clamav-scan <path>
    Run recursive ClamAV scan

--run-rkhunter
    Run rkhunter rootkit scan

--run-chkrootkit
    Run chkrootkit scan

--run-debsums
    Verify installed package integrity

--init-aide
    Initialize AIDE filesystem integrity database

--clean-safe
    Perform safe cleaning
        • apt cache cleanup
        • selected user cache directories
        • bounded journald vacuum

--bundle-evidence
    Create compressed tar.gz bundle of evidence artifacts

Installed Packages
------------------

clamav
rkhunter
chkrootkit
debsums
aide
auditd
audispd-plugins
psmisc
lsof

Output Locations
----------------

Logs:
    ~/.local/state/zero-trust-desktop/ztd_08/log/

Snapshots:
    ~/.local/state/zero-trust-desktop/ztd_08/snapshots/<timestamp>/

Evidence Bundle:
    ~/.local/state/zero-trust-desktop/ztd_08/snapshots/ztd_08_evidence_<timestamp>.tar.gz

Supported Platforms
-------------------

Debian / Ubuntu / Debian-derived Linux systems
"""

from __future__ import annotations

import argparse
import json
import platform
import random
import shutil
import subprocess
import sys
import tarfile
import time
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Tuple


# ---------------------------
# Ghost Protocol 00 (Topper)
# ---------------------------

def ghost_protocol(countdown: int = 5, rows: int = 10, cols: int = 64) -> None:
    green = "\033[0;32m"
    reset = "\033[0m"

    if not sys.stdout.isatty():
        return

    rows = max(1, int(rows))
    cols = max(1, int(cols))
    countdown = max(0, int(countdown))

    subprocess.run(["clear"], check=False)

    print(f"{green}Initializing Ghost Protocol… It will begin in {countdown} seconds.{reset}")
    time.sleep(0.6)

    for i in range(countdown, 0, -1):
        print(f"{green}{i}...{reset}")
        time.sleep(1)

    print(f"{green}Initializing Ghost Protocol...{reset}")
    time.sleep(0.3)

    for _ in range(rows):
        line = "".join(random.choice("01") for _ in range(cols))
        print(f"{green}{line}{reset}")

    print()


APP_NAME = "Zero Trust Desktop"
APP_ID = "ztd"
STAGE_NAME = "08. DEFENSE + CLEANER"
STAGE_ID = "ztd_08_defense_and_cleaner"
VERSION = "1.1.0"

HOME = Path.home()
STATE_DIR = HOME / ".local" / "state" / "zero-trust-desktop" / "ztd_08"
LOG_DIR = STATE_DIR / "log"
SNAP_DIR = STATE_DIR / "snapshots"
RUN_ID = datetime.now().strftime("%Y%m%d_%H%M%S")
LOG_FILE = LOG_DIR / f"{STAGE_ID}_{RUN_ID}.jsonl"
SNAPSHOT_ROOT = SNAP_DIR / RUN_ID

PKGS_DEFENSE = [
    "clamav",
    "rkhunter",
    "chkrootkit",
    "debsums",
    "aide",
    "auditd",
    "audispd-plugins",
    "psmisc",
    "lsof",
]


@dataclass
class Settings:
    yes: bool
    json_stdout: bool
    no_banner: bool

    run_clamav_path: Optional[str]
    run_rkhunter: bool
    run_chkrootkit: bool
    run_debsums: bool
    init_aide: bool

    clean_safe: bool
    bundle_evidence: bool

    log_file: Path
    snapshot_root: Path


@dataclass
class Event:
    ts: str
    level: str
    msg: str
    data: Optional[dict] = None


class AptSourceError(RuntimeError):
    pass


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
            print(json.dumps(ev.data, indent=2, ensure_ascii=False))

    s.log_file.parent.mkdir(parents=True, exist_ok=True)
    with s.log_file.open("a", encoding="utf-8") as f:
        f.write(line + "\n")


def info(s: Settings, msg: str, data: Optional[dict] = None) -> None:
    emit(s, Event(ts=now_ts(), level="INFO", msg=msg, data=data))


def warn(s: Settings, msg: str, data: Optional[dict] = None) -> None:
    emit(s, Event(ts=now_ts(), level="WARN", msg=msg, data=data))


def error(s: Settings, msg: str, data: Optional[dict] = None) -> None:
    emit(s, Event(ts=now_ts(), level="ERROR", msg=msg, data=data))


def run(s: Settings, cmd: List[str], check: bool = True) -> Tuple[int, str, str]:
    info(s, "$ " + " ".join(cmd))

    p = subprocess.run(cmd, text=True, capture_output=True)

    stdout = (p.stdout or "").strip()
    stderr = (p.stderr or "").strip()

    if stdout:
        info(s, "stdout", {"cmd": cmd, "stdout": stdout[:10000]})

    if stderr:
        info(s, "stderr", {"cmd": cmd, "stderr": stderr[:10000]})

    if check and p.returncode != 0:
        raise RuntimeError(
            json.dumps(
                {
                    "cmd": cmd,
                    "rc": p.returncode,
                    "stdout": stdout[:4000],
                    "stderr": stderr[:4000],
                },
                ensure_ascii=False,
            )
        )

    return p.returncode, p.stdout or "", p.stderr or ""


def sudo(s: Settings, cmd: List[str], check: bool = True) -> Tuple[int, str, str]:
    return run(s, ["sudo"] + cmd, check=check)


def require_debian_like(s: Settings) -> None:
    if not Path("/etc/os-release").exists():
        error(s, "Missing /etc/os-release")
        raise SystemExit(2)

    if not have("apt-get") or not have("dpkg"):
        error(s, "Debian/Ubuntu system required")
        raise SystemExit(2)


def dpkg_installed(pkg: str) -> bool:
    p = subprocess.run(
        ["dpkg", "-s", pkg],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return p.returncode == 0


def write_snapshot(name: str, content: str, root: Path) -> None:
    root.mkdir(parents=True, exist_ok=True)
    (root / name).write_text(content, encoding="utf-8", errors="ignore")


def cap(cmd: List[str]) -> str:
    p = subprocess.run(cmd, text=True, capture_output=True)
    return (p.stdout or p.stderr or "").strip()


def snapshot_apt_source_state(s: Settings) -> None:
    write_snapshot(
        "apt_sources_scan.txt",
        cap(
            [
                "bash",
                "-lc",
                "grep -RniE 'opera|deb\\.opera\\.com|opera-stable|Signed-By' /etc/apt/sources.list /etc/apt/sources.list.d 2>/dev/null || true",
            ]
        ) + "\n",
        s.snapshot_root,
    )

    write_snapshot(
        "apt_sources_list_d.txt",
        cap(
            [
                "bash",
                "-lc",
                "find /etc/apt/sources.list.d -maxdepth 1 -type f -printf '%f\n' 2>/dev/null | sort || true",
            ]
        ) + "\n",
        s.snapshot_root,
    )

    write_snapshot(
        "apt_policy_head.txt",
        cap(["bash", "-lc", "apt-cache policy 2>/dev/null | sed -n '1,220p' || true"]) + "\n",
        s.snapshot_root,
    )


def apt_update(s: Settings) -> None:
    try:
        sudo(s, ["apt-get", "update"])
    except RuntimeError as exc:
        details_raw = str(exc)
        try:
            details = json.loads(details_raw)
        except Exception:
            details = {"raw": details_raw}

        stderr = details.get("stderr", "")
        stdout = details.get("stdout", "")

        snapshot_apt_source_state(s)
        write_snapshot("apt_update_stdout.txt", stdout + "\n", s.snapshot_root)
        write_snapshot("apt_update_stderr.txt", stderr + "\n", s.snapshot_root)

        if "Conflicting values set for option Signed-By" in stderr:
            error(
                s,
                "APT source configuration conflict detected",
                {
                    "problem": "conflicting Signed-By values in apt source definitions",
                    "hint": "deduplicate or correct the conflicting repository entry before rerunning",
                    "stderr": stderr[:4000],
                    "snapshot_dir": str(s.snapshot_root),
                },
            )
            raise AptSourceError("APT source configuration conflict detected")

        error(
            s,
            "apt-get update failed",
            {
                "stderr": stderr[:4000],
                "snapshot_dir": str(s.snapshot_root),
            },
        )
        raise AptSourceError("apt-get update failed")


def apt_install_missing(s: Settings, pkgs: List[str]) -> None:
    missing = [p for p in pkgs if not dpkg_installed(p)]

    for pkg in pkgs:
        if pkg in missing:
            info(s, "Installing missing package", {"package": pkg})
        else:
            info(s, "Already installed", {"package": pkg})

    if not missing:
        return

    cmd = ["apt-get", "install"]
    if s.yes:
        cmd.append("-y")
    cmd.extend(missing)

    sudo(s, cmd)


def snapshots(s: Settings) -> None:
    info(s, "Capturing system snapshots", {"dir": str(s.snapshot_root)})

    write_snapshot(
        "system.txt",
        f"{platform.system()} {platform.release()} {platform.machine()}\n{sys.version}\n",
        s.snapshot_root,
    )

    if have("ss"):
        write_snapshot(
            "listening_ports.txt",
            cap(["bash", "-lc", "ss -tulnp | sed -n '1,240p' || true"]) + "\n",
            s.snapshot_root,
        )

    if have("last"):
        write_snapshot(
            "last_logins.txt",
            cap(["bash", "-lc", "last -n 30 || true"]) + "\n",
            s.snapshot_root,
        )

    if have("journalctl"):
        write_snapshot(
            "auth_signals.txt",
            cap(
                [
                    "bash",
                    "-lc",
                    "journalctl -b --no-pager | egrep -i 'ssh|sudo|polkit|authentication failure|fail2ban|apparmor' | tail -n 200 || true",
                ]
            ) + "\n",
            s.snapshot_root,
        )

    write_snapshot(
        "suid_files.txt",
        cap(
            [
                "bash",
                "-lc",
                "sudo find / -xdev -perm -4000 -type f 2>/dev/null | sed -n '1,400p' || true",
            ]
        ) + "\n",
        s.snapshot_root,
    )

    if have("systemctl"):
        write_snapshot(
            "enabled_services_head.txt",
            cap(
                [
                    "bash",
                    "-lc",
                    "systemctl list-unit-files --state=enabled --no-pager | sed -n '1,220p' || true",
                ]
            ) + "\n",
            s.snapshot_root,
        )

    info(s, "Snapshots complete")


def run_optional_scans(s: Settings) -> None:
    if s.run_clamav_path and have("clamscan"):
        info(s, "Running ClamAV scan", {"path": s.run_clamav_path})
        out = cap(["bash", "-lc", f"sudo clamscan -r -i -- '{s.run_clamav_path}' 2>&1 || true"])
        write_snapshot("clamscan.txt", out + "\n", s.snapshot_root)

    if s.run_rkhunter and have("rkhunter"):
        info(s, "Running rkhunter")
        out = cap(["bash", "-lc", "sudo rkhunter --check --sk 2>&1 || true"])
        write_snapshot("rkhunter.txt", out + "\n", s.snapshot_root)

    if s.run_chkrootkit and have("chkrootkit"):
        info(s, "Running chkrootkit")
        out = cap(["bash", "-lc", "sudo chkrootkit 2>&1 || true"])
        write_snapshot("chkrootkit.txt", out + "\n", s.snapshot_root)

    if s.run_debsums and have("debsums"):
        info(s, "Running debsums integrity check")
        out = cap(["bash", "-lc", "sudo debsums -s 2>&1 || true"])
        write_snapshot("debsums.txt", out + "\n", s.snapshot_root)

    if s.init_aide and have("aideinit"):
        info(s, "Initializing AIDE database")
        out = cap(["bash", "-lc", "sudo aideinit 2>&1 || true"])
        write_snapshot("aideinit.txt", out + "\n", s.snapshot_root)


def clean_safe(s: Settings) -> None:
    if not s.clean_safe:
        warn(s, "Safe cleaning skipped")
        return

    info(s, "Safe cleaning start")

    sudo(s, ["apt-get", "clean"], check=False)
    sudo(s, ["apt-get", "autoclean"], check=False)

    cache_dirs = [
        HOME / ".cache" / "pip",
        HOME / ".cache" / "thumbnails",
    ]

    for path in cache_dirs:
        if path.exists():
            for item in path.iterdir():
                try:
                    if item.is_dir():
                        shutil.rmtree(item)
                    else:
                        item.unlink()
                except Exception as exc:
                    warn(s, "Failed to remove cache item", {"path": str(item), "error": str(exc)})

    if have("journalctl"):
        sudo(s, ["journalctl", "--vacuum-time=14d"], check=False)
        sudo(s, ["journalctl", "--vacuum-size=200M"], check=False)

    info(s, "Safe cleaning complete")


def bundle_evidence(s: Settings) -> Optional[Path]:
    if not s.bundle_evidence:
        return None

    bundle = s.snapshot_root.parent / f"ztd_08_evidence_{RUN_ID}.tar.gz"
    info(s, "Creating evidence bundle", {"bundle": str(bundle)})

    with tarfile.open(bundle, "w:gz") as tf:
        if s.snapshot_root.exists():
            tf.add(s.snapshot_root, arcname=s.snapshot_root.name)
        if s.log_file.exists():
            tf.add(s.log_file, arcname=s.log_file.name)

    return bundle


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="ztd_08_defense_and_cleaner.py")

    p.add_argument("--yes", action="store_true", help="Non-interactive apt install")
    p.add_argument("--json", action="store_true", help="Emit JSON events to stdout")
    p.add_argument("--no-banner", action="store_true", help="Disable Ghost Protocol banner")

    p.add_argument("--run-clamav-scan", default=None, help="Run recursive ClamAV scan on a path")
    p.add_argument("--run-rkhunter", action="store_true", help="Run rkhunter")
    p.add_argument("--run-chkrootkit", action="store_true", help="Run chkrootkit")
    p.add_argument("--run-debsums", action="store_true", help="Run debsums integrity check")
    p.add_argument("--init-aide", action="store_true", help="Initialize AIDE database")

    p.add_argument("--clean-safe", action="store_true", help="Perform safe cleaning")
    p.add_argument("--bundle-evidence", action="store_true", help="Create evidence tar.gz bundle")

    return p


def main() -> int:
    args = build_parser().parse_args()

    s = Settings(
        yes=args.yes,
        json_stdout=args.json,
        no_banner=args.no_banner,
        run_clamav_path=args.run_clamav_scan,
        run_rkhunter=args.run_rkhunter,
        run_chkrootkit=args.run_chkrootkit,
        run_debsums=args.run_debsums,
        init_aide=args.init_aide,
        clean_safe=args.clean_safe,
        bundle_evidence=args.bundle_evidence,
        log_file=LOG_FILE,
        snapshot_root=SNAPSHOT_ROOT,
    )

    if not s.no_banner:
        ghost_protocol(5, 10, 64)

    require_debian_like(s)

    info(
        s,
        f"{APP_NAME} — {STAGE_NAME} start",
        {
            "version": VERSION,
            "script_path": str(Path(__file__).resolve()),
            "log": str(s.log_file),
            "snapshot_root": str(s.snapshot_root),
        },
    )

    try:
        info(s, "[1] apt update")
        apt_update(s)

        info(s, "[2] install defense packages")
        apt_install_missing(s, PKGS_DEFENSE)

        info(s, "[3] snapshots")
        snapshots(s)

        info(s, "[4] optional scans")
        run_optional_scans(s)

        info(s, "[5] optional cleaning")
        clean_safe(s)

        bundle = bundle_evidence(s)

        info(
            s,
            "Run summary",
            {
                "stage": STAGE_ID,
                "version": VERSION,
                "log": str(s.log_file),
                "snapshots": str(s.snapshot_root),
                "bundle": str(bundle) if bundle else None,
                "status": "success",
            },
        )

        info(s, "Stage complete")
        return 0

    except AptSourceError as exc:
        error(
            s,
            "Stage stopped due to apt source configuration problem",
            {
                "reason": str(exc),
                "action_required": "repair apt repository definitions and rerun",
                "snapshot_root": str(s.snapshot_root),
                "log": str(s.log_file),
            },
        )
        return 100

    except Exception as exc:
        error(
            s,
            "Unhandled failure",
            {
                "error_type": type(exc).__name__,
                "error": str(exc),
                "snapshot_root": str(s.snapshot_root),
                "log": str(s.log_file),
            },
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())


# =============================================================================
# USAGE
# =============================================================================
#
# Make executable
#   chmod +x ztd_08_defense_and_cleaner.py
#
# Safe baseline run
#   python3 ztd_08_defense_and_cleaner.py --yes
#
# Safe baseline run without banner
#   python3 ztd_08_defense_and_cleaner.py --yes --no-banner
#
# Run with safe cleaning
#   python3 ztd_08_defense_and_cleaner.py --yes --clean-safe
#
# Run malware scan
#   python3 ztd_08_defense_and_cleaner.py --yes --run-clamav-scan "$HOME"
#
# Rootkit + integrity audit
#   python3 ztd_08_defense_and_cleaner.py \
#       --yes \
#       --run-rkhunter \
#       --run-chkrootkit \
#       --run-debsums
#
# Create evidence bundle
#   python3 ztd_08_defense_and_cleaner.py --yes --bundle-evidence
#
# Full audit run
#   python3 ztd_08_defense_and_cleaner.py \
#       --yes \
#       --run-rkhunter \
#       --run-chkrootkit \
#       --run-debsums \
#       --bundle-evidence
#
# =============================================================================
