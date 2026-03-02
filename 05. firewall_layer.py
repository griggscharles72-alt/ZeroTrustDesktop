#!/usr/bin/env python3
"""
ZTD — 05. FIREWALL LAYER (DEV-SAFE / AUTHORITY SNAPSHOTS)
Version: 0.5.0
Suite: Zero Trust Desktop (ZTD)
Stage: 05 (Firewall Authority + Observability)

GOAL
  Define a clean firewall layer without breaking development:
    - Install firewall tooling (nftables, ufw, iptables) idempotently
    - Snapshot the REAL authority state (nft + ufw + iptables) to disk
    - Optional: apply a conservative UFW baseline (explicit flag only)
    - Optional: install persistence tooling (explicit flag only)

REALITY MODEL (Ubuntu/Debian)
  - nftables is the kernel authority.
  - UFW is a frontend (often backed by nft/iptables depending on system).
  - iptables may be nft-backed ("iptables-nft") or legacy ("iptables-legacy").
  - This layer treats iptables as compatibility/visibility unless you explicitly choose otherwise.

SAFETY MODEL
  - Default run DOES NOT enforce/lock down anything.
  - Default run: installs missing packages + writes snapshots + prints a report.
  - Behavior-changing operations are explicit flags:
      --apply-ufw-baseline         sets ufw defaults + enables ufw (can change connectivity)
      --install-iptables-persistent installs persistence package (no rule flush)
      --save-iptables              saves current iptables rules via netfilter-persistent (if available)

USAGE
  Safe (install + snapshot only):
    python3 "05. firewall_layer.py" --yes

  Apply conservative UFW baseline (deny incoming / allow outgoing / allow OpenSSH / enable):
    python3 "05. firewall_layer.py" --yes --apply-ufw-baseline

  Optional persistence (explicit):
    python3 "05. firewall_layer.py" --yes --install-iptables-persistent --save-iptables

OUTPUT
  - JSONL log: ~/.local/state/zero-trust-desktop/ztd_05/log/ztd_05_<ts>.jsonl
  - Snapshots: ~/.local/state/zero-trust-desktop/ztd_05/snapshots/<ts>/
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
STAGE_NAME = "05. FIREWALL LAYER"
STAGE_ID = "ztd_05_firewall_layer"
VERSION = "0.5.0"

HOME = Path.home()
STATE_DIR = HOME / ".local" / "state" / "zero-trust-desktop" / "ztd_05"
LOG_DIR = STATE_DIR / "log"
SNAP_DIR = STATE_DIR / "snapshots"
RUN_ID = datetime.now().strftime("%Y%m%d_%H%M%S")
LOG_FILE = LOG_DIR / f"{STAGE_ID}_{RUN_ID}.jsonl"
SNAPSHOT_ROOT = SNAP_DIR / RUN_ID

# Keep the base minimal + deterministic
PKGS_FIREWALL = [
    "nftables",
    "ufw",
    "iptables",
    "conntrack",
]

PKGS_PERSIST = [
    "iptables-persistent",  # provides netfilter-persistent
]


@dataclass
class Settings:
    yes: bool
    json_stdout: bool

    apply_ufw_baseline: bool
    install_iptables_persistent: bool
    save_iptables: bool

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
    # stdout
    if s.json_stdout:
        print(json.dumps(asdict(ev), ensure_ascii=False))
    else:
        print(f"[{ev.ts}] {ev.level}: {ev.msg}")

    # JSONL log file (always)
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
        error(
            s,
            "Command failed",
            {"rc": p.returncode, "cmd": cmd, "stderr": (p.stderr or "").strip()},
        )
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


def apt_install_missing(s: Settings, pkgs: Iterable[str]) -> None:
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
    sudo(s, args)


def write_snapshot_file(s: Settings, name: str, content: str) -> Path:
    s.snapshot_root.mkdir(parents=True, exist_ok=True)
    path = s.snapshot_root / name
    path.write_text(content, encoding="utf-8", errors="ignore")
    return path


def capture_cmd(s: Settings, name: str, cmd: List[str]) -> None:
    # best-effort capture
    try:
        _, out, err = run(s, cmd, check=False)
        blob = out if out.strip() else err
        write_snapshot_file(s, name, blob.strip() + "\n")
    except Exception as e:
        warn(s, f"Snapshot capture failed: {name}", {"error": str(e)})


def snapshot_all(s: Settings) -> None:
    info(
        s,
        "Snapshot start",
        {
            "snapshot_dir": str(s.snapshot_root),
            "system": f"{platform.system()} {platform.release()}",
            "arch": platform.machine(),
            "python": sys.version.splitlines()[0],
        },
    )

    # Authority snapshots
    if have("nft"):
        capture_cmd(s, "nft_list_ruleset.txt", ["sudo", "nft", "list", "ruleset"])
    else:
        write_snapshot_file(s, "nft_list_ruleset.txt", "nft not found\n")

    if have("ufw"):
        capture_cmd(s, "ufw_status_verbose.txt", ["sudo", "ufw", "status", "verbose"])
    else:
        write_snapshot_file(s, "ufw_status_verbose.txt", "ufw not found\n")

    if have("iptables-save"):
        capture_cmd(s, "iptables_save.txt", ["sudo", "iptables-save"])
    else:
        write_snapshot_file(s, "iptables_save.txt", "iptables-save not found\n")

    # Backend diagnostics (helpful when iptables is nft-backed)
    if have("update-alternatives"):
        capture_cmd(s, "iptables_alternatives.txt", ["bash", "-lc", "update-alternatives --display iptables || true"])
    else:
        write_snapshot_file(s, "iptables_alternatives.txt", "update-alternatives not found\n")

    if have("iptables"):
        capture_cmd(s, "iptables_version.txt", ["bash", "-lc", "iptables --version 2>&1 || true"])
    else:
        write_snapshot_file(s, "iptables_version.txt", "iptables not found\n")

    # Listening ports snapshot (visibility)
    if have("ss"):
        capture_cmd(s, "ss_listen.txt", ["bash", "-lc", "ss -tulnp | sed -n '1,200p'"])
    else:
        write_snapshot_file(s, "ss_listen.txt", "ss not found\n")

    # Quick sysctl hints (not applying anything here)
    capture_cmd(s, "sysctl_net.txt", ["bash", "-lc", "sysctl net.ipv4.ip_forward net.ipv4.conf.all.rp_filter net.ipv4.conf.default.rp_filter 2>/dev/null || true"])

    info(s, "Snapshot complete", {"snapshot_dir": str(s.snapshot_root)})


def apply_ufw_baseline(s: Settings) -> None:
    if not s.apply_ufw_baseline:
        warn(s, "Skipping UFW baseline (use --apply-ufw-baseline to apply)")
        return
    if not have("ufw"):
        warn(s, "ufw not found; cannot apply baseline")
        return

    info(s, "Applying conservative UFW baseline (deny incoming / allow outgoing / allow OpenSSH / enable)")
    # NOTE: No reset. No app deletions. Minimal change.
    sudo(s, ["ufw", "default", "deny", "incoming"], check=False)
    sudo(s, ["ufw", "default", "allow", "outgoing"], check=False)
    sudo(s, ["ufw", "allow", "OpenSSH"], check=False)
    sudo(s, ["ufw", "--force", "enable"], check=False)


def install_persistence(s: Settings) -> None:
    if not s.install_iptables_persistent:
        return
    info(s, "Installing iptables persistence tooling (iptables-persistent)")
    apt_install_missing(s, PKGS_PERSIST)


def save_iptables_rules(s: Settings) -> None:
    if not s.save_iptables:
        return
    # netfilter-persistent is provided by iptables-persistent
    if not have("netfilter-persistent"):
        warn(s, "netfilter-persistent not found (install with --install-iptables-persistent)")
        return
    info(s, "Saving current iptables rules via netfilter-persistent (best-effort)")
    sudo(s, ["netfilter-persistent", "save"], check=False)


def report_summary(s: Settings) -> None:
    info(
        s,
        "Run summary",
        {
            "app": APP_ID,
            "stage": STAGE_ID,
            "version": VERSION,
            "log": str(s.log_file),
            "snapshot_dir": str(s.snapshot_root),
            "apply_ufw_baseline": s.apply_ufw_baseline,
            "install_iptables_persistent": s.install_iptables_persistent,
            "save_iptables": s.save_iptables,
        },
    )


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog='05. firewall_layer.py')
    p.add_argument("--yes", action="store_true", help="Non-interactive apt (-y)")
    p.add_argument("--json", action="store_true", help="Emit JSON to stdout (log file always JSONL)")

    # Behavior-changing flags (explicit only)
    p.add_argument("--apply-ufw-baseline", action="store_true", help="Apply conservative UFW baseline + enable ufw")
    p.add_argument("--install-iptables-persistent", action="store_true", help="Install iptables-persistent (adds netfilter-persistent)")
    p.add_argument("--save-iptables", action="store_true", help="Save current iptables rules via netfilter-persistent (requires persistence pkg)")
    return p


def main() -> int:
    args = build_parser().parse_args()

    s = Settings(
        yes=bool(args.yes),
        json_stdout=bool(args.json),

        apply_ufw_baseline=bool(args.apply_ufw_baseline),
        install_iptables_persistent=bool(args.install_iptables_persistent),
        save_iptables=bool(args.save_iptables),

        log_file=LOG_FILE,
        snapshot_root=SNAPSHOT_ROOT,
    )

    require_debian_like(s)

    info(s, f"{APP_NAME} — {STAGE_NAME} start", {"version": VERSION, "log": str(s.log_file)})

    info(s, "[1] apt update")
    apt_update(s)

    info(s, "[2] install firewall tooling (idempotent)")
    apt_install_missing(s, PKGS_FIREWALL)

    info(s, "[3] snapshot BEFORE any optional apply")
    snapshot_all(s)

    info(s, "[4] optional applies")
    install_persistence(s)
    apply_ufw_baseline(s)
    save_iptables_rules(s)

    info(s, "[5] snapshot AFTER optional apply")
    snapshot_all(s)

    report_summary(s)
    info(s, f"{STAGE_NAME} complete", {"log": str(s.log_file), "snapshot_dir": str(s.snapshot_root)})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
