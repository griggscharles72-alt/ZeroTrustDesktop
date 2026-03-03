#!/usr/bin/env python3
"""
ZTD — 08. DEFENSE + CLEANER (SAFE / DEV-FRIENDLY / AUDITABLE)
Version: 0.8.0
Suite: Zero Trust Desktop (ZTD)
Stage: 08 (Defense posture + universal safe cleaning)

DEFAULT (SAFE)
  - Installs missing defense packages (idempotent; no removals)
  - Captures a defense posture report + evidence snapshots
  - Does NOT run heavy scans unless you opt in
  - Does NOT delete anything unless you opt in

APPLY FLAGS (EXPLICIT ONLY)
  --run-clamav-scan <path>     run clamscan on a path (can be slow)
  --run-rkhunter               run rkhunter check (noisy possible)
  --run-chkrootkit             run chkrootkit (noisy possible)
  --run-debsums                run debsums integrity check (can be slow)
  --init-aide                  initialize aide database (heavy; first-time)
  --clean-safe                 perform safe cleaning (apt caches + user caches)
  --bundle-evidence            create a tar.gz evidence bundle

OUTPUT
  - JSONL log: ~/.local/state/zero-trust-desktop/ztd_08/log/ztd_08_<ts>.jsonl
  - Snapshots: ~/.local/state/zero-trust-desktop/ztd_08/snapshots/<ts>/
  - Optional bundle: .../ztd_08_evidence_<ts>.tar.gz
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import subprocess
import sys
import tarfile
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Tuple


APP_NAME = "Zero Trust Desktop"
APP_ID = "ztd"
STAGE_NAME = "08. DEFENSE + CLEANER"
STAGE_ID = "ztd_08_defense_and_cleaner"
VERSION = "0.8.0"

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
    "psmisc",
    "lsof",
    "auditd",
    "audispd-plugins",
]


@dataclass
class Settings:
    yes: bool
    json_stdout: bool

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


def now_ts() -> str:
    return datetime.now().isoformat(timespec="seconds")


def have(cmd: str) -> bool:
    return shutil.which(cmd) is not None


def emit(s: Settings, ev: Event) -> None:
    if s.json_stdout:
        print(json.dumps(asdict(ev), ensure_ascii=False))
    else:
        print(f"[{ev.ts}] {ev.level}: {ev.msg}")

    s.log_file.parent.mkdir(parents=True, exist_ok=True)
    with s.log_file.open("a", encoding="utf-8") as f:
        f.write(json.dumps(asdict(ev), ensure_ascii=False) + "\n")


def info(s: Settings, msg: str, data: Optional[dict] = None) -> None:
    emit(s, Event(ts=now_ts(), level="INFO", msg=msg, data=data))


def warn(s: Settings, msg: str, data: Optional[dict] = None) -> None:
    emit(s, Event(ts=now_ts(), level="WARN", msg=msg, data=data))


def error(s: Settings, msg: str, data: Optional[dict] = None) -> None:
    emit(s, Event(ts=now_ts(), level="ERROR", msg=msg, data=data))


def run(s: Settings, cmd: List[str], check: bool = True) -> Tuple[int, str, str]:
    info(s, "$ " + " ".join(cmd))
    p = subprocess.run(cmd, text=True, capture_output=True)
    if check and p.returncode != 0:
        error(s, "Command failed", {"rc": p.returncode, "cmd": cmd, "stderr": (p.stderr or "").strip()})
        raise RuntimeError(f"Command failed: {' '.join(cmd)} (rc={p.returncode})")
    return p.returncode, p.stdout, p.stderr


def sudo(s: Settings, cmd: List[str], check: bool = True) -> Tuple[int, str, str]:
    return run(s, ["sudo"] + cmd, check=check)


def require_debian_like(s: Settings) -> None:
    if not (Path("/etc/os-release").exists() and have("apt-get") and have("dpkg")):
        error(s, "Unsupported platform. Debian/Ubuntu with apt-get/dpkg required.")
        raise SystemExit(2)


def dpkg_installed(pkg: str) -> bool:
    p = subprocess.run(["dpkg", "-s", pkg], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return p.returncode == 0


def apt_update(s: Settings) -> None:
    args = ["apt-get", "update"]
    if s.yes:
        args.append("-y")
    sudo(s, args)


def apt_install_missing(s: Settings, pkgs: List[str]) -> None:
    missing = [p for p in pkgs if not dpkg_installed(p)]
    for p in pkgs:
        info(s, f"Already installed: {p}" if p not in missing else f"Installing missing package: {p}")
    if not missing:
        return
    args = ["apt-get", "install"]
    if s.yes:
        args.append("-y")
    args += missing
    sudo(s, args)


def write_snapshot(name: str, content: str, root: Path) -> None:
    root.mkdir(parents=True, exist_ok=True)
    (root / name).write_text(content, encoding="utf-8", errors="ignore")


def cap(cmd: List[str]) -> str:
    p = subprocess.run(cmd, text=True, capture_output=True)
    return (p.stdout or p.stderr or "").strip()


def snapshots(s: Settings) -> None:
    info(s, "Capturing defense snapshots", {"dir": str(s.snapshot_root)})

    write_snapshot("system.txt", f"{platform.system()} {platform.release()} {platform.machine()}\n{sys.version}\n", s.snapshot_root)

    if have("ss"):
        write_snapshot("listening_ports.txt", cap(["bash", "-lc", "ss -tulnp | sed -n '1,240p' || true"]) + "\n", s.snapshot_root)

    if have("last"):
        write_snapshot("last_logins.txt", cap(["bash", "-lc", "last -n 30 || true"]) + "\n", s.snapshot_root)

    if have("journalctl"):
        # last boot auth-ish signals
        write_snapshot("auth_signals.txt", cap(["bash", "-lc", "journalctl -b --no-pager | egrep -i 'ssh|sudo|polkit|authentication failure|fail2ban|apparmor' | tail -n 200 || true"]) + "\n", s.snapshot_root)

    # SUID files snapshot (can take time but manageable)
    write_snapshot("suid_files.txt", cap(["bash", "-lc", "sudo find / -xdev -perm -4000 -type f 2>/dev/null | sed -n '1,400p' || true"]) + "\n", s.snapshot_root)

    # systemd persistence-ish
    if have("systemctl"):
        write_snapshot("enabled_services_head.txt", cap(["bash", "-lc", "systemctl list-unit-files --state=enabled --no-pager | sed -n '1,220p' || true"]) + "\n", s.snapshot_root)

    info(s, "Snapshot complete", {"dir": str(s.snapshot_root)})


def run_clamav(s: Settings) -> None:
    if not s.run_clamav_path:
        return
    if not have("clamscan"):
        warn(s, "clamscan not found")
        return
    target = s.run_clamav_path
    info(s, "Running clamscan (opt-in)", {"path": target})
    out = cap(["bash", "-lc", f"sudo clamscan -r --bell -i '{target}' 2>&1 || true"])
    write_snapshot("clamscan.txt", out + "\n", s.snapshot_root)


def run_rkhunter(s: Settings) -> None:
    if not s.run_rkhunter:
        return
    if not have("rkhunter"):
        warn(s, "rkhunter not found")
        return
    info(s, "Running rkhunter (opt-in)")
    out = cap(["bash", "-lc", "sudo rkhunter --check --sk 2>&1 || true"])
    write_snapshot("rkhunter.txt", out + "\n", s.snapshot_root)


def run_chkrootkit(s: Settings) -> None:
    if not s.run_chkrootkit:
        return
    if not have("chkrootkit"):
        warn(s, "chkrootkit not found")
        return
    info(s, "Running chkrootkit (opt-in)")
    out = cap(["bash", "-lc", "sudo chkrootkit 2>&1 || true"])
    write_snapshot("chkrootkit.txt", out + "\n", s.snapshot_root)


def run_debsums(s: Settings) -> None:
    if not s.run_debsums:
        return
    if not have("debsums"):
        warn(s, "debsums not found")
        return
    info(s, "Running debsums (opt-in; integrity check)")
    out = cap(["bash", "-lc", "sudo debsums -s 2>&1 || true"])
    write_snapshot("debsums.txt", out + "\n", s.snapshot_root)


def init_aide(s: Settings) -> None:
    if not s.init_aide:
        return
    if not have("aideinit"):
        warn(s, "aideinit not found")
        return
    info(s, "Initializing AIDE database (opt-in; heavy)")
    out = cap(["bash", "-lc", "sudo aideinit 2>&1 || true"])
    write_snapshot("aideinit.txt", out + "\n", s.snapshot_root)


def clean_safe(s: Settings) -> None:
    if not s.clean_safe:
        warn(s, "Skipping safe cleaner (use --clean-safe)")
        return

    info(s, "Safe cleaning start (no config deletion)")

    # apt cache cleanup
    sudo(s, ["apt-get", "clean"], check=False)
    sudo(s, ["apt-get", "autoclean"], check=False)

    # user cache cleanup (safe targets)
    user_cache = HOME / ".cache"
    thumbs = user_cache / "thumbnails"
    pip_cache = user_cache / "pip"

    for path in [thumbs, pip_cache]:
        if path.exists():
            info(s, "Cleaning user cache path", {"path": str(path)})
            # delete contents, keep directory
            sudo(s, ["bash", "-lc", f"rm -rf '{path}'/* 2>/dev/null || true"], check=False)

    # journal vacuum (bounded)
    if have("journalctl"):
        info(s, "Vacuuming journald logs (bounded)")
        sudo(s, ["journalctl", "--vacuum-time=14d"], check=False)
        sudo(s, ["journalctl", "--vacuum-size=200M"], check=False)

    info(s, "Safe cleaning complete")


def bundle_evidence(s: Settings) -> Optional[Path]:
    if not s.bundle_evidence:
        return None
    out = s.snapshot_root.parent / f"ztd_08_evidence_{RUN_ID}.tar.gz"
    info(s, "Creating evidence bundle", {"bundle": str(out)})

    with tarfile.open(out, "w:gz") as tf:
        tf.add(s.snapshot_root, arcname=s.snapshot_root.name)
        tf.add(s.log_file, arcname=s.log_file.name)

    return out


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="ztd_08_defense_and_cleaner.py")
    p.add_argument("--yes", action="store_true", help="Non-interactive apt (-y)")
    p.add_argument("--json", action="store_true", help="Emit JSON to stdout (log file always JSONL)")

    p.add_argument("--run-clamav-scan", default=None, help="Run clamscan against a path (opt-in)")
    p.add_argument("--run-rkhunter", action="store_true", help="Run rkhunter (opt-in)")
    p.add_argument("--run-chkrootkit", action="store_true", help="Run chkrootkit (opt-in)")
    p.add_argument("--run-debsums", action="store_true", help="Run debsums integrity check (opt-in)")
    p.add_argument("--init-aide", action="store_true", help="Initialize AIDE DB (opt-in)")

    p.add_argument("--clean-safe", action="store_true", help="Perform safe cleaning (opt-in)")
    p.add_argument("--bundle-evidence", action="store_true", help="Create evidence tar.gz (opt-in)")
    return p


def main() -> int:
    args = build_parser().parse_args()

    s = Settings(
        yes=bool(args.yes),
        json_stdout=bool(args.json),

        run_clamav_path=(str(args.run_clamav_scan).strip() if args.run_clamav_scan else None),
        run_rkhunter=bool(args.run_rkhunter),
        run_chkrootkit=bool(args.run_chkrootkit),
        run_debsums=bool(args.run_debsums),
        init_aide=bool(args.init_aide),

        clean_safe=bool(args.clean_safe),
        bundle_evidence=bool(args.bundle_evidence),

        log_file=LOG_FILE,
        snapshot_root=SNAPSHOT_ROOT,
    )

    require_debian_like(s)
    info(s, f"{APP_NAME} — {STAGE_NAME} start", {"version": VERSION, "log": str(s.log_file)})

    info(s, "[1] apt update")
    apt_update(s)

    info(s, "[2] install defense packages (idempotent)")
    apt_install_missing(s, PKGS_DEFENSE)

    info(s, "[3] snapshots")
    snapshots(s)

    info(s, "[4] optional scans (explicit only)")
    run_clamav(s)
    run_rkhunter(s)
    run_chkrootkit(s)
    run_debsums(s)
    init_aide(s)

    info(s, "[5] optional safe cleaning (explicit only)")
    clean_safe(s)

    bundle = bundle_evidence(s)

    info(
        s,
        "Run summary",
        {
            "stage": STAGE_ID,
            "version": VERSION,
            "log": str(s.log_file),
            "snapshot_dir": str(s.snapshot_root),
            "bundle": str(bundle) if bundle else None,
        },
    )
    info(s, f"{STAGE_NAME} complete")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
