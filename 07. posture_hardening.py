#!/usr/bin/env python3
"""
ZTD — 07. POSTURE HARDENING (REPORT-FIRST / EXPLICIT APPLY)
Version: 0.7.0
Suite: Zero Trust Desktop (ZTD)
Stage: 07 (OS hygiene: sysctl + updates + logs + time + ssh)

DEFAULT (SAFE)
  - No system changes.
  - Produces a posture report + snapshots.

APPLY FLAGS (EXPLICIT ONLY)
  --apply-sysctl              write /etc/sysctl.d/99-ztd-hardening.conf and reload sysctl
  --apply-journald            set persistent journald storage + size caps
  --apply-unattended-upgrades install/enable unattended-upgrades (security updates)
  --apply-timesync            ensure time sync service enabled (systemd-timesyncd)
  --apply-ssh                 apply conservative SSH hardening (PermitRootLogin no)
  --ssh-keys-only             ONLY if used with --apply-ssh: disable PasswordAuthentication

NOTES
  - Debian/Ubuntu only.
  - Backups are created before editing system files.
  - This layer does NOT touch firewall rules.

OUTPUT
  - JSONL log: ~/.local/state/zero-trust-desktop/ztd_07/log/ztd_07_<ts>.jsonl
  - Snapshots: ~/.local/state/zero-trust-desktop/ztd_07/snapshots/<ts>/
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
from typing import Dict, List, Optional, Tuple


APP_NAME = "Zero Trust Desktop"
APP_ID = "ztd"
STAGE_NAME = "07. POSTURE HARDENING"
STAGE_ID = "ztd_07_posture_hardening"
VERSION = "0.7.0"

HOME = Path.home()
STATE_DIR = HOME / ".local" / "state" / "zero-trust-desktop" / "ztd_07"
LOG_DIR = STATE_DIR / "log"
SNAP_DIR = STATE_DIR / "snapshots"
RUN_ID = datetime.now().strftime("%Y%m%d_%H%M%S")
LOG_FILE = LOG_DIR / f"{STAGE_ID}_{RUN_ID}.jsonl"
SNAPSHOT_ROOT = SNAP_DIR / RUN_ID

# Targets
SYSCTL_FILE = Path("/etc/sysctl.d/99-ztd-hardening.conf")
JOURNALD_CONF = Path("/etc/systemd/journald.conf")
SSHD_CONF = Path("/etc/ssh/sshd_config")

PKGS_UPDATES = ["unattended-upgrades"]
PKGS_SSH = ["openssh-server"]

# Conservative, dev-safe sysctl baseline
SYSCTL_BASELINE: Dict[str, str] = {
    # Basic hardening
    "net.ipv4.tcp_syncookies": "1",
    "net.ipv4.icmp_echo_ignore_broadcasts": "1",
    "net.ipv4.conf.all.accept_source_route": "0",
    "net.ipv4.conf.default.accept_source_route": "0",
    "net.ipv4.conf.all.accept_redirects": "0",
    "net.ipv4.conf.default.accept_redirects": "0",
    "net.ipv4.conf.all.send_redirects": "0",
    "net.ipv4.conf.default.send_redirects": "0",
    "net.ipv4.conf.all.log_martians": "1",
    "net.ipv4.conf.default.log_martians": "1",
    # Keep routing OFF by default (dev-safe)
    "net.ipv4.ip_forward": "0",
}


@dataclass
class Settings:
    yes: bool
    json_stdout: bool

    apply_sysctl: bool
    apply_journald: bool
    apply_unattended: bool
    apply_timesync: bool
    apply_ssh: bool
    ssh_keys_only: bool

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


def write_snapshot_file(s: Settings, name: str, content: str) -> Path:
    s.snapshot_root.mkdir(parents=True, exist_ok=True)
    path = s.snapshot_root / name
    path.write_text(content, encoding="utf-8", errors="ignore")
    return path


def capture_cmd(s: Settings, name: str, cmd: List[str]) -> None:
    try:
        _, out, err = run(s, cmd, check=False)
        txt = (out or err or "").strip()
        write_snapshot_file(s, name, (txt + "\n") if txt else "no-output\n")
    except Exception as e:
        warn(s, f"Snapshot capture failed: {name}", {"error": str(e)})


def backup_file_once(s: Settings, path: Path) -> Optional[Path]:
    if not path.exists():
        return None
    bdir = s.snapshot_root / "backups"
    bdir.mkdir(parents=True, exist_ok=True)
    backup = bdir / f"{path.name}.bak"
    if backup.exists():
        return backup
    backup.write_text(path.read_text(encoding="utf-8", errors="ignore"), encoding="utf-8")
    return backup


def snapshots(s: Settings) -> None:
    info(s, "Snapshot start", {"snapshot_dir": str(s.snapshot_root)})
    capture_cmd(s, "uname.txt", ["uname", "-a"])
    if have("lsb_release"):
        capture_cmd(s, "lsb_release.txt", ["lsb_release", "-a"])
    if have("sysctl"):
        capture_cmd(s, "sysctl_subset.txt", ["bash", "-lc", "sysctl " + " ".join(SYSCTL_BASELINE.keys()) + " 2>/dev/null || true"])
    if have("systemctl"):
        capture_cmd(s, "timesync_status.txt", ["bash", "-lc", "timedatectl status 2>/dev/null || true"])
        capture_cmd(s, "journald_status.txt", ["bash", "-lc", "systemctl is-active systemd-journald 2>/dev/null || true"])
        capture_cmd(s, "unattended_status.txt", ["bash", "-lc", "systemctl is-enabled unattended-upgrades 2>/dev/null || true"])
        capture_cmd(s, "ssh_status.txt", ["bash", "-lc", "systemctl is-active ssh 2>/dev/null || systemctl is-active sshd 2>/dev/null || true"])
    if JOURNALD_CONF.exists():
        write_snapshot_file(s, "journald_conf_head.txt", "\n".join(JOURNALD_CONF.read_text(encoding="utf-8", errors="ignore").splitlines()[:220]) + "\n")
    if SSHD_CONF.exists():
        write_snapshot_file(s, "sshd_config_head.txt", "\n".join(SSHD_CONF.read_text(encoding="utf-8", errors="ignore").splitlines()[:260]) + "\n")
    info(s, "Snapshot complete", {"snapshot_dir": str(s.snapshot_root)})


def apply_sysctl(s: Settings) -> None:
    if not s.apply_sysctl:
        warn(s, "Skipping sysctl apply (use --apply-sysctl)")
        return
    if not have("sysctl"):
        warn(s, "sysctl not found")
        return

    info(s, "Applying sysctl baseline", {"file": str(SYSCTL_FILE)})
    # Backup existing if present
    if SYSCTL_FILE.exists():
        backup_file_once(s, SYSCTL_FILE)

    # Build content deterministically
    lines = [
        "# Managed by ZTD Stage 07",
        f"# {STAGE_ID} {VERSION} {RUN_ID}",
        "",
    ]
    for k in sorted(SYSCTL_BASELINE.keys()):
        lines.append(f"{k} = {SYSCTL_BASELINE[k]}")
    content = "\n".join(lines) + "\n"

    # Write via sudo tee to avoid permission issues
    sudo(s, ["bash", "-lc", f"cat > '{SYSCTL_FILE}' <<'EOF'\n{content}EOF"], check=True)
    sudo(s, ["sysctl", "--system"], check=False)


def apply_journald(s: Settings) -> None:
    if not s.apply_journald:
        warn(s, "Skipping journald apply (use --apply-journald)")
        return
    if not JOURNALD_CONF.exists():
        warn(s, "journald.conf not found")
        return

    info(s, "Applying journald persistence + caps", {"file": str(JOURNALD_CONF)})
    backup_file_once(s, JOURNALD_CONF)

    # Minimal edits: append drop-in style markers at end (idempotent by replace block)
    block_start = "# --- ZTD Stage 07 begin ---"
    block_end = "# --- ZTD Stage 07 end ---"
    desired = [
        block_start,
        "Storage=persistent",
        "SystemMaxUse=200M",
        "RuntimeMaxUse=100M",
        "MaxRetentionSec=1month",
        "Compress=yes",
        block_end,
        "",
    ]

    current = JOURNALD_CONF.read_text(encoding="utf-8", errors="ignore").splitlines()
    out: List[str] = []
    in_block = False
    for line in current:
        if line.strip() == block_start:
            in_block = True
            continue
        if line.strip() == block_end:
            in_block = False
            continue
        if not in_block:
            out.append(line)

    out.extend(desired)
    new_text = "\n".join(out) + "\n"
    sudo(s, ["bash", "-lc", f"cat > '{JOURNALD_CONF}' <<'EOF'\n{new_text}EOF"], check=True)

    # Restart journald best-effort
    sudo(s, ["systemctl", "restart", "systemd-journald"], check=False)


def apply_unattended(s: Settings) -> None:
    if not s.apply_unattended:
        warn(s, "Skipping unattended-upgrades apply (use --apply-unattended-upgrades)")
        return

    info(s, "Installing/enabling unattended-upgrades (security updates)")
    apt_install_missing(s, PKGS_UPDATES)

    # Enable service best-effort
    sudo(s, ["systemctl", "enable", "--now", "unattended-upgrades"], check=False)

    # Run reconfigure non-interactively best-effort (some systems require debconf)
    sudo(s, ["bash", "-lc", "DEBIAN_FRONTEND=noninteractive dpkg-reconfigure -f noninteractive unattended-upgrades >/dev/null 2>&1 || true"], check=False)


def apply_timesync(s: Settings) -> None:
    if not s.apply_timesync:
        warn(s, "Skipping time sync apply (use --apply-timesync)")
        return

    # Prefer systemd-timesyncd (usually present)
    if have("timedatectl"):
        info(s, "Enabling NTP via timedatectl (systemd-timesyncd)")
        sudo(s, ["timedatectl", "set-ntp", "true"], check=False)

    # Ensure service enabled if present
    if have("systemctl"):
        sudo(s, ["systemctl", "enable", "--now", "systemd-timesyncd"], check=False)


def _set_sshd_key_value(lines: List[str], key: str, value: str) -> List[str]:
    """
    Replace or append 'key value' in sshd_config, preserving other lines.
    Very conservative: does not try to parse Match blocks. For advanced use, add later.
    """
    key_lower = key.lower()
    replaced = False
    out: List[str] = []
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            out.append(line)
            continue
        parts = stripped.split()
        if parts and parts[0].lower() == key_lower:
            out.append(f"{key} {value}")
            replaced = True
        else:
            out.append(line)
    if not replaced:
        out.append(f"{key} {value}")
    return out


def apply_ssh(s: Settings) -> None:
    if not s.apply_ssh:
        warn(s, "Skipping SSH apply (use --apply-ssh)")
        return

    info(s, "Installing SSH server if missing + applying conservative hardening")
    apt_install_missing(s, PKGS_SSH)

    if not SSHD_CONF.exists():
        warn(s, "sshd_config not found")
        return

    backup_file_once(s, SSHD_CONF)
    lines = SSHD_CONF.read_text(encoding="utf-8", errors="ignore").splitlines()

    # Conservative defaults
    lines = _set_sshd_key_value(lines, "PermitRootLogin", "no")

    if s.ssh_keys_only:
        lines = _set_sshd_key_value(lines, "PasswordAuthentication", "no")
    else:
        # dev-safe: keep password auth enabled unless explicitly keys-only
        lines = _set_sshd_key_value(lines, "PasswordAuthentication", "yes")

    lines = _set_sshd_key_value(lines, "X11Forwarding", "no")
    lines = _set_sshd_key_value(lines, "MaxAuthTries", "3")

    new_text = "\n".join(lines) + "\n"
    sudo(s, ["bash", "-lc", f"cat > '{SSHD_CONF}' <<'EOF'\n{new_text}EOF"], check=True)

    # Restart service best-effort
    if have("systemctl"):
        sudo(s, ["systemctl", "restart", "ssh"], check=False)
        sudo(s, ["systemctl", "restart", "sshd"], check=False)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="07. posture_hardening.py")
    p.add_argument("--yes", action="store_true", help="Non-interactive apt (-y)")
    p.add_argument("--json", action="store_true", help="Emit JSON to stdout (log file always JSONL)")

    p.add_argument("--apply-sysctl", action="store_true", help="Apply sysctl baseline")
    p.add_argument("--apply-journald", action="store_true", help="Enable persistent journald + caps")
    p.add_argument("--apply-unattended-upgrades", action="store_true", help="Enable unattended upgrades (security)")
    p.add_argument("--apply-timesync", action="store_true", help="Enable time sync")
    p.add_argument("--apply-ssh", action="store_true", help="Apply conservative SSH hardening")
    p.add_argument("--ssh-keys-only", action="store_true", help="Use with --apply-ssh: disable PasswordAuthentication")

    return p


def main() -> int:
    args = build_parser().parse_args()

    s = Settings(
        yes=bool(args.yes),
        json_stdout=bool(args.json),

        apply_sysctl=bool(args.apply_sysctl),
        apply_journald=bool(args.apply_journald),
        apply_unattended=bool(args.apply_unattended_upgrades),
        apply_timesync=bool(args.apply_timesync),
        apply_ssh=bool(args.apply_ssh),
        ssh_keys_only=bool(args.ssh_keys_only),

        log_file=LOG_FILE,
        snapshot_root=SNAPSHOT_ROOT,
    )

    require_debian_like(s)

    info(s, f"{APP_NAME} — {STAGE_NAME} start", {"version": VERSION, "log": str(s.log_file)})
    info(s, "Snapshot BEFORE")
    snapshots(s)

    info(s, "[1] apt update (safe)")
    apt_update(s)

    info(s, "[2] optional applies (explicit flags only)")
    apply_sysctl(s)
    apply_journald(s)
    apply_unattended(s)
    apply_timesync(s)
    apply_ssh(s)

    info(s, "Snapshot AFTER")
    snapshots(s)

    info(
        s,
        "Run summary",
        {
            "app": APP_ID,
            "stage": STAGE_ID,
            "version": VERSION,
            "system": f"{platform.system()} {platform.release()}",
            "arch": platform.machine(),
            "log": str(s.log_file),
            "snapshot_dir": str(s.snapshot_root),
            "applied": {
                "sysctl": s.apply_sysctl,
                "journald": s.apply_journald,
                "unattended_upgrades": s.apply_unattended,
                "timesync": s.apply_timesync,
                "ssh": s.apply_ssh,
                "ssh_keys_only": s.ssh_keys_only,
            },
        },
    )

    info(s, f"{STAGE_NAME} complete", {"log": str(s.log_file), "snapshot_dir": str(s.snapshot_root)})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
