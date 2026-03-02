#!/usr/bin/env python3
"""
ZTD — 1. Security Stack (INSTALL + APPLY)
Version: 0.1.1
Suite: Zero Trust Desktop (ZTD)
Stage: 1

PURPOSE
  One-and-done security stack installer + optional baseline apply for Ubuntu/Debian:
    - Installs (if missing): ufw, fail2ban, apparmor (+ utils/profiles), firejail,
      plus firewall tooling (nftables/iptables packages where applicable)
    - Enables: apparmor + fail2ban
    - Optionally applies:
        - UFW baseline (deny incoming / allow outgoing / allow OpenSSH / enable)
        - AppArmor enforce for /etc/apparmor.d/* (with dev-friendly exceptions)
        - Firejail “basic” integration (install only by default; optional)
        - Optional service disables (nginx, printing)

DEFAULTS (SAFE)
  - Installs packages + enables apparmor/fail2ban
  - DOES NOT change firewall defaults or enforce all AppArmor profiles unless --apply is used

ONE COMMAND (recommended)
  python3 ztd_01_security_stack.py --yes --apply

OPTIONAL
  python3 ztd_01_security_stack.py --yes --apply --firejail-basic
  python3 ztd_01_security_stack.py --yes --apply --disable-printing --disable-nginx

NOTES
  - Debian/Ubuntu only (apt-get/dpkg).
  - Firewall control plane is UFW. iptables/nftables are installed + reported, not managed directly.
"""

from __future__ import annotations

import argparse
import json
import platform
import shutil
import subprocess
import sys
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import Iterable, List, Optional, Tuple


APP_NAME = "Zero Trust Desktop"
APP_ID = "ztd"
STAGE_NAME = "1. Security Stack"
STAGE_ID = "ztd_01_security_stack"
VERSION = "0.1.1"

HOME = Path.home()
STATE_DIR = HOME / ".local" / "state" / "zero-trust-desktop" / "ztd_01"
LOG_DIR = STATE_DIR / "log"
RUN_ID = datetime.now().strftime("%Y%m%d_%H%M%S")
LOG_FILE = LOG_DIR / f"{STAGE_ID}_{RUN_ID}.jsonl"

# Packages (Ubuntu/Debian)
PKGS_STACK = [
    # Firewall (control plane: UFW)
    "ufw",
    # Brute-force protection
    "fail2ban",
    # MAC
    "apparmor",
    "apparmor-utils",
    "apparmor-profiles",
    "apparmor-profiles-extra",
    # Sandbox
    "firejail",
    # Tooling (reporting / compatibility)
    "nftables",
    "iptables",
    "iproute2",
]

# Some distros ship iptables via alternatives; keep these best-effort installs.
PKGS_STACK_OPTIONAL = [
    "iptables-persistent",  # optional persistence if present
    "netfilter-persistent", # service used by iptables-persistent
]

@dataclass
class Settings:
    yes: bool
    json_stdout: bool

    apply: bool
    enforce_apparmor: bool
    apply_firewall: bool

    # AppArmor exceptions (dev friendly)
    aa_complain_code: bool
    aa_complain_python: bool

    # Firejail
    firejail_basic: bool

    # Optional disables
    disable_nginx: bool
    disable_printing: bool

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


def apt_install_missing(s: Settings, pkgs: Iterable[str], best_effort: bool = False) -> None:
    pkgs = list(pkgs)
    missing = [p for p in pkgs if not dpkg_installed(p)]
    for p in pkgs:
        info(s, f"Already installed: {p}" if p not in missing else f"Installing missing package: {p}")
    if not missing:
        return
    args = ["apt-get", "install"]
    if s.yes:
        args.append("-y")
    args += missing
    sudo(s, args, check=not best_effort)


def enable_core_services(s: Settings) -> None:
    info(s, "Enabling services: apparmor, fail2ban")
    sudo(s, ["systemctl", "enable", "--now", "apparmor"], check=False)
    sudo(s, ["systemctl", "enable", "--now", "fail2ban"], check=False)


def apply_firewall_baseline_ufw(s: Settings) -> None:
    if not s.apply_firewall:
        warn(s, "Skipping firewall apply (use --apply or --apply-firewall)")
        return
    if not have("ufw"):
        warn(s, "ufw not found")
        return

    info(s, "Applying UFW baseline: deny incoming / allow outgoing / allow OpenSSH / enable")
    sudo(s, ["ufw", "default", "deny", "incoming"], check=False)
    sudo(s, ["ufw", "default", "allow", "outgoing"], check=False)
    sudo(s, ["ufw", "allow", "OpenSSH"], check=False)
    sudo(s, ["ufw", "--force", "enable"], check=False)


def apparmor_enforce_all(s: Settings) -> None:
    if not s.enforce_apparmor:
        warn(s, "Skipping AppArmor enforce (use --apply or --enforce-apparmor)")
        return
    if not have("aa-enforce"):
        warn(s, "aa-enforce not found (apparmor-utils missing?)")
        return
    info(s, "Applying AppArmor enforce to /etc/apparmor.d/* (best-effort)")
    sudo(s, ["bash", "-lc", "aa-enforce /etc/apparmor.d/* 2>/dev/null || true"], check=False)


def apparmor_complain_exceptions(s: Settings) -> None:
    if not have("aa-complain"):
        warn(s, "aa-complain not found (apparmor-utils missing?)")
        return

    # Dev-friendly exceptions; ON by default
    if s.aa_complain_code:
        info(s, "Setting AppArmor complain mode for code* profiles (best-effort)")
        sudo(s, ["bash", "-lc", "aa-complain /etc/apparmor.d/code* 2>/dev/null || true"], check=False)

    if s.aa_complain_python:
        info(s, "Setting AppArmor complain mode for python* profiles (best-effort)")
        sudo(s, ["bash", "-lc", "aa-complain /etc/apparmor.d/python* 2>/dev/null || true"], check=False)


def firejail_basic_setup(s: Settings) -> None:
    if not s.firejail_basic:
        info(s, "Firejail installed (no policy changes applied). Use --firejail-basic to apply basic integration.")
        return
    if not have("firejail"):
        warn(s, "firejail not found")
        return

    # "Basic" here means: ensure it runs + show profiles; no forced global changes.
    info(s, "Firejail basic setup (non-invasive): verifying binary + showing profile count")
    p = subprocess.run(["bash", "-lc", "firejail --version && ls -1 /etc/firejail 2>/dev/null | wc -l"],
                       text=True, capture_output=True)
    out = (p.stdout or p.stderr).strip()
    if out:
        print(out)

    # Optional: some systems provide firecfg to integrate symlinks. This IS a behavior change.
    # We'll only run it if present, because it can affect launching behavior of apps.
    if have("firecfg"):
        info(s, "Running firecfg (behavior change) to integrate Firejail with desktop launchers")
        sudo(s, ["firecfg"], check=False)
    else:
        warn(s, "firecfg not found; skipping integration (this is OK)")


def disable_optional_services(s: Settings) -> None:
    if s.disable_nginx:
        info(s, "Disabling nginx (best-effort)")
        sudo(s, ["systemctl", "disable", "--now", "nginx"], check=False)

    if s.disable_printing:
        info(s, "Disabling printing services (cups, cups-browsed) (best-effort)")
        sudo(s, ["systemctl", "disable", "--now", "cups", "cups-browsed"], check=False)


def status_report(s: Settings) -> None:
    info(
        s,
        "Status report",
        {
            "app": APP_ID,
            "stage": STAGE_ID,
            "version": VERSION,
            "system": f"{platform.system()} {platform.release()}",
            "arch": platform.machine(),
            "python": sys.version.splitlines()[0],
            "log": str(s.log_file),
        },
    )

    # AppArmor
    if have("aa-status"):
        info(s, "--- AppArmor (aa-status | head -n 30) ---")
        p = subprocess.run(["bash", "-lc", "aa-status | head -n 30"], text=True, capture_output=True)
        out = (p.stdout or p.stderr).strip()
        if out:
            print(out)
    else:
        warn(s, "aa-status not found")

    # Firewall
    if have("ufw"):
        info(s, "--- Firewall (ufw status verbose) ---")
        p = subprocess.run(["ufw", "status", "verbose"], text=True, capture_output=True)
        out = (p.stdout or p.stderr).strip()
        if out:
            print(out)
    else:
        warn(s, "ufw not found")

    # Fail2Ban
    if have("fail2ban-client"):
        info(s, "--- Fail2Ban (fail2ban-client status) ---")
        p = subprocess.run(["fail2ban-client", "status"], text=True, capture_output=True)
        out = (p.stdout or p.stderr).strip()
        if out:
            print(out)
    elif have("systemctl"):
        info(s, "--- Fail2Ban (systemctl is-active fail2ban) ---")
        p = subprocess.run(["systemctl", "is-active", "fail2ban"], text=True, capture_output=True)
        out = (p.stdout or p.stderr).strip()
        if out:
            print(out)

    # Ports
    if have("ss"):
        info(s, "--- Listening Ports (ss -tulnp | grep LISTEN) ---")
        p = subprocess.run(["bash", "-lc", "ss -tulnp | grep LISTEN || true"], text=True, capture_output=True)
        out = (p.stdout or p.stderr).strip()
        if out:
            print(out)

    # nftables / iptables presence (report-only)
    if have("nft"):
        info(s, "--- nftables present (rule count summary) ---")
        p = subprocess.run(["bash", "-lc", "nft list ruleset 2>/dev/null | wc -l"], text=True, capture_output=True)
        out = (p.stdout or p.stderr).strip()
        if out:
            print(f"nft ruleset lines: {out}")
    if have("iptables"):
        info(s, "--- iptables present (rule count summary) ---")
        p = subprocess.run(["bash", "-lc", "iptables -S 2>/dev/null | wc -l"], text=True, capture_output=True)
        out = (p.stdout or p.stderr).strip()
        if out:
            print(f"iptables rules lines: {out}")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="ztd_01_security_stack.py")
    p.add_argument("--yes", action="store_true", help="Non-interactive apt (-y)")
    p.add_argument("--json", action="store_true", help="Emit JSON to stdout (log file always JSONL)")

    # One-switch apply (what you asked for)
    p.add_argument("--apply", action="store_true",
                   help="Apply baseline: UFW baseline + AppArmor enforce (plus dev exceptions)")

    # Fine-grained overrides
    p.add_argument("--apply-firewall", action="store_true", help="Apply UFW baseline and enable UFW")
    p.add_argument("--enforce-apparmor", action="store_true", help="Enforce /etc/apparmor.d/* (best-effort)")

    # Dev-friendly AppArmor exceptions (ON by default)
    p.add_argument("--no-complain-code", action="store_true", help="Do NOT set complain for code* profiles")
    p.add_argument("--no-complain-python", action="store_true", help="Do NOT set complain for python* profiles")

    # Firejail
    p.add_argument("--firejail-basic", action="store_true",
                   help="Apply basic firejail integration (runs firecfg if available)")

    # Optional disables
    p.add_argument("--disable-nginx", action="store_true", help="Disable nginx if present")
    p.add_argument("--disable-printing", action="store_true", help="Disable cups/cups-browsed if present")

    return p


def main() -> int:
    args = build_parser().parse_args()

    LOG_DIR.mkdir(parents=True, exist_ok=True)

    # If --apply is set, turn on baseline actions
    apply_firewall = bool(args.apply_firewall) or bool(args.apply)
    enforce_apparmor = bool(args.enforce_apparmor) or bool(args.apply)

    s = Settings(
        yes=bool(args.yes),
        json_stdout=bool(args.json),

        apply=bool(args.apply),
        enforce_apparmor=enforce_apparmor,
        apply_firewall=apply_firewall,

        aa_complain_code=not bool(args.no_complain_code),
        aa_complain_python=not bool(args.no_complain_python),

        firejail_basic=bool(args.firejail_basic),

        disable_nginx=bool(args.disable_nginx),
        disable_printing=bool(args.disable_printing),

        log_file=LOG_FILE,
    )

    require_debian_like(s)

    info(s, f"{APP_NAME} — {STAGE_NAME} start", {"version": VERSION, "log": str(s.log_file)})

    info(s, "[1] apt update")
    apt_update(s)

    info(s, "[2] install security stack (install-if-missing)")
    apt_install_missing(s, PKGS_STACK)
    # Optional packages (don’t fail if absent in repo)
    apt_install_missing(s, PKGS_STACK_OPTIONAL, best_effort=True)

    info(s, "[3] enable core services")
    enable_core_services(s)

    info(s, "[4] AppArmor modes")
    apparmor_enforce_all(s)
    apparmor_complain_exceptions(s)

    info(s, "[5] firewall baseline (UFW)")
    apply_firewall_baseline_ufw(s)

    info(s, "[6] firejail")
    firejail_basic_setup(s)

    info(s, "[7] optional disables")
    disable_optional_services(s)

    status_report(s)
    info(s, f"{STAGE_NAME} complete", {"log": str(s.log_file)})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
