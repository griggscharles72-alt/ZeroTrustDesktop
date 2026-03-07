#!/usr/bin/env python3
"""
README
======

Filename:
    07_posture_hardening.py

Run it with:

chmod +x 07_posture_hardening.py
./07_posture_hardening.py

And if you want the apply pass:

chmod +x 07_posture_hardening.py
./07_posture_hardening.py --yes --apply-sysctl --apply-journald --apply-timesync

This is the right update for what your last run exposed.

Purpose:
    Zero Trust Desktop (ZTD) Stage 07.
    Produce a posture report first, then optionally apply conservative,
    explicit hardening for a Debian/Ubuntu developer workstation.

Design goals:
    - Safe by default: no system changes unless apply flags are provided
    - Snapshot before and after
    - Idempotent behavior
    - Conservative, dev-safe defaults
    - Clear logging to JSONL
    - Backups created before modifying live system files
    - Stronger safety around config writes and SSH validation
    - Cleaner snapshot execution with less shell noise

What this stage can manage:
    - sysctl hardening baseline
    - persistent journald storage and caps
    - unattended security upgrades
    - time synchronization
    - conservative SSH hardening

What this stage does NOT do:
    - firewall rule changes
    - destructive package removals
    - aggressive kernel/network tuning
    - legacy distro support outside Debian/Ubuntu style systems

System requirements:
    - Debian / Ubuntu / Debian-derived Linux
    - python3
    - sudo
    - apt-get
    - dpkg
    - systemd-based system for journald/timesync behavior
    - Internet access if installing packages

Default behavior:
    - Validate platform
    - Create snapshot directory
    - Capture posture snapshots before changes
    - Run apt-get update
    - Apply nothing unless explicit apply flags are passed
    - Capture posture snapshots after execution
    - Write JSONL log and on-disk snapshots

Outputs:
    - JSONL log:
        ~/.local/state/zero-trust-desktop/ztd_07/log/ztd_07_posture_hardening_<timestamp>.jsonl
    - Snapshots:
        ~/.local/state/zero-trust-desktop/ztd_07/snapshots/<timestamp>/

Examples:
    Report only:
        python3 07_posture_hardening.py

    Apply sysctl + journald + time sync:
        python3 07_posture_hardening.py --yes --apply-sysctl --apply-journald --apply-timesync

    Apply unattended upgrades:
        python3 07_posture_hardening.py --yes --apply-unattended-upgrades

    Apply SSH hardening but keep password authentication:
        python3 07_posture_hardening.py --yes --apply-ssh

    Apply SSH hardening and require keys only:
        python3 07_posture_hardening.py --yes --apply-ssh --ssh-keys-only

Safety notes:
    - --ssh-keys-only can lock you out if you do not already have a working key-based login.
    - SSH config is validated before live replacement.
    - Journald is configured using a drop-in file instead of rewriting the base config.
    - Existing managed files are backed up into the run snapshot directory.
"""

from __future__ import annotations

import argparse
import json
import platform
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple


APP_NAME = "Zero Trust Desktop"
APP_ID = "ztd"
STAGE_NAME = "07. POSTURE HARDENING"
STAGE_ID = "ztd_07_posture_hardening"
VERSION = "0.8.1"

HOME = Path.home()
STATE_DIR = HOME / ".local" / "state" / "zero-trust-desktop" / "ztd_07"
LOG_DIR = STATE_DIR / "log"
SNAP_DIR = STATE_DIR / "snapshots"
RUN_ID = datetime.now().strftime("%Y%m%d_%H%M%S")
LOG_FILE = LOG_DIR / f"{STAGE_ID}_{RUN_ID}.jsonl"
SNAPSHOT_ROOT = SNAP_DIR / RUN_ID

# Targets
SYSCTL_FILE = Path("/etc/sysctl.d/99-ztd-hardening.conf")
JOURNALD_DROPIN_DIR = Path("/etc/systemd/journald.conf.d")
JOURNALD_DROPIN_FILE = JOURNALD_DROPIN_DIR / "99-ztd-hardening.conf"
JOURNALD_MAIN_CONF = Path("/etc/systemd/journald.conf")
SSHD_CONF = Path("/etc/ssh/sshd_config")

PKGS_UPDATES = ["unattended-upgrades"]
PKGS_SSH = ["openssh-server"]

# Conservative, dev-safe sysctl baseline
SYSCTL_BASELINE: Dict[str, str] = {
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
    "net.ipv4.ip_forward": "0",
}

IGNORABLE_STDERR_PATTERNS = [
    "flatpak: error while loading shared libraries: libappstream.so.5",
]


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


def cleaned_env() -> Dict[str, str]:
    env = dict(__import__("os").environ)
    for key in [
        "BASH_ENV",
        "ENV",
        "PROMPT_COMMAND",
        "PYTHONSTARTUP",
        "LD_PRELOAD",
        "LD_LIBRARY_PATH",
    ]:
        env.pop(key, None)
    env["LC_ALL"] = "C"
    env["LANG"] = "C"
    return env


def is_ignorable_stderr(stderr: str) -> bool:
    s = (stderr or "").strip()
    if not s:
        return True
    return any(pattern in s for pattern in IGNORABLE_STDERR_PATTERNS)


def filter_stderr(stderr: str) -> str:
    s = (stderr or "").strip()
    if not s:
        return ""
    lines = []
    for line in s.splitlines():
        if any(pattern in line for pattern in IGNORABLE_STDERR_PATTERNS):
            continue
        lines.append(line)
    return "\n".join(lines).strip()


def emit(s: Settings, ev: Event) -> None:
    if s.json_stdout:
        print(json.dumps(asdict(ev), ensure_ascii=False))
    else:
        print(f"[{ev.ts}] {ev.level}: {ev.msg}")
        if ev.data:
            print(json.dumps(ev.data, indent=2, ensure_ascii=False))

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
    p = subprocess.run(
        cmd,
        text=True,
        capture_output=True,
        env=cleaned_env(),
    )
    stdout = (p.stdout or "").strip()
    stderr_raw = (p.stderr or "").strip()
    stderr = filter_stderr(stderr_raw)

    if stdout:
        info(s, "stdout", {"cmd": cmd, "stdout": stdout[:12000]})

    if stderr:
        level = "ERROR" if check and p.returncode != 0 else "INFO"
        emit(s, Event(ts=now_ts(), level=level, msg="stderr", data={"cmd": cmd, "stderr": stderr[:12000]}))

    if check and p.returncode != 0:
        raise RuntimeError(f"Command failed: {' '.join(cmd)} (rc={p.returncode})")
    return p.returncode, p.stdout or "", stderr_raw


def sudo(s: Settings, cmd: List[str], check: bool = True) -> Tuple[int, str, str]:
    return run(s, ["sudo"] + cmd, check=check)


def require_debian_like(s: Settings) -> None:
    if not Path("/etc/os-release").exists():
        error(s, "Unsupported platform: /etc/os-release missing")
        raise SystemExit(2)

    if not have("apt-get") or not have("dpkg"):
        error(s, "Unsupported platform: apt-get/dpkg required")
        raise SystemExit(2)

    os_release = Path("/etc/os-release").read_text(encoding="utf-8", errors="ignore").lower()
    if "debian" not in os_release and "ubuntu" not in os_release:
        warn(s, "OS does not explicitly identify as Debian/Ubuntu; continuing best-effort")


def dpkg_installed(pkg: str) -> bool:
    p = subprocess.run(
        ["dpkg", "-s", pkg],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=cleaned_env(),
    )
    return p.returncode == 0


def apt_update(s: Settings) -> None:
    sudo(s, ["apt-get", "update"])


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
        _, out, err_raw = run(s, cmd, check=False)
        stderr = filter_stderr(err_raw)
        txt = ((out or "").strip() + ("\n" + stderr if stderr else "")).strip()
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
    info(s, "Backed up file", {"source": str(path), "backup": str(backup)})
    return backup


def write_root_file_via_temp(
    s: Settings,
    target: Path,
    content: str,
    mode: str = "0644",
    create_parent: bool = False,
) -> None:
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False) as tf:
        tf.write(content)
        temp_path = Path(tf.name)

    try:
        if create_parent:
            sudo(s, ["mkdir", "-p", str(target.parent)])
        sudo(s, ["install", "-m", mode, str(temp_path), str(target)])
    finally:
        try:
            temp_path.unlink(missing_ok=True)
        except Exception:
            pass


def safe_read_text(path: Path, default: str = "") -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return default


def systemctl_query(s: Settings, args: List[str]) -> str:
    if not have("systemctl"):
        return "systemctl-not-found"
    try:
        rc, out, err_raw = run(s, ["systemctl"] + args, check=False)
        stderr = filter_stderr(err_raw)
        text = (out or "").strip() or stderr.strip()
        if not text:
            return f"rc={rc}"
        return text
    except Exception as e:
        return f"error: {e}"


def snapshots(s: Settings) -> None:
    info(s, "Snapshot start", {"snapshot_dir": str(s.snapshot_root)})

    capture_cmd(s, "uname.txt", ["uname", "-a"])
    capture_cmd(s, "os_release.txt", ["cat", "/etc/os-release"])

    if have("lsb_release"):
        capture_cmd(s, "lsb_release.txt", ["lsb_release", "-a"])

    if have("sysctl"):
        capture_cmd(s, "sysctl_subset.txt", ["sysctl"] + sorted(SYSCTL_BASELINE.keys()))

    if have("systemctl"):
        capture_cmd(s, "systemctl_failed.txt", ["systemctl", "--failed", "--no-pager", "--no-legend"])
        capture_cmd(s, "journald_status.txt", ["systemctl", "is-active", "systemd-journald"])
        capture_cmd(s, "unattended_status.txt", ["systemctl", "is-enabled", "unattended-upgrades"])
        capture_cmd(s, "timesync_service_status.txt", ["systemctl", "is-enabled", "systemd-timesyncd"])

        ssh_status = "\n".join(
            [
                f"ssh={systemctl_query(s, ['is-active', 'ssh'])}",
                f"sshd={systemctl_query(s, ['is-active', 'sshd'])}",
            ]
        ).strip() + "\n"
        write_snapshot_file(s, "ssh_service_status.txt", ssh_status)

    if have("timedatectl"):
        capture_cmd(s, "timedatectl_status.txt", ["timedatectl", "status"])

    if JOURNALD_MAIN_CONF.exists():
        write_snapshot_file(
            s,
            "journald_main_conf_head.txt",
            "\n".join(safe_read_text(JOURNALD_MAIN_CONF).splitlines()[:220]) + "\n",
        )

    if JOURNALD_DROPIN_FILE.exists():
        write_snapshot_file(
            s,
            "journald_dropin.txt",
            safe_read_text(JOURNALD_DROPIN_FILE),
        )

    if SSHD_CONF.exists():
        write_snapshot_file(
            s,
            "sshd_config_head.txt",
            "\n".join(safe_read_text(SSHD_CONF).splitlines()[:260]) + "\n",
        )

    if have("journalctl"):
        capture_cmd(s, "journal_disk_usage.txt", ["journalctl", "--disk-usage"])

    info(s, "Snapshot complete", {"snapshot_dir": str(s.snapshot_root)})


def apply_sysctl(s: Settings) -> None:
    if not s.apply_sysctl:
        warn(s, "Skipping sysctl apply (use --apply-sysctl)")
        return
    if not have("sysctl"):
        warn(s, "sysctl not found")
        return

    info(s, "Applying sysctl baseline", {"file": str(SYSCTL_FILE)})
    if SYSCTL_FILE.exists():
        backup_file_once(s, SYSCTL_FILE)

    lines = [
        "# Managed by ZTD Stage 07",
        f"# Stage: {STAGE_ID}",
        f"# Version: {VERSION}",
        f"# Run ID: {RUN_ID}",
        "",
    ]
    for key in sorted(SYSCTL_BASELINE):
        lines.append(f"{key} = {SYSCTL_BASELINE[key]}")
    content = "\n".join(lines) + "\n"

    write_root_file_via_temp(s, SYSCTL_FILE, content, mode="0644")
    sudo(s, ["sysctl", "--system"], check=False)


def apply_journald(s: Settings) -> None:
    if not s.apply_journald:
        warn(s, "Skipping journald apply (use --apply-journald)")
        return

    info(s, "Applying journald persistence + caps via drop-in", {"file": str(JOURNALD_DROPIN_FILE)})
    if JOURNALD_DROPIN_FILE.exists():
        backup_file_once(s, JOURNALD_DROPIN_FILE)

    content = "\n".join(
        [
            "# Managed by ZTD Stage 07",
            f"# Stage: {STAGE_ID}",
            f"# Version: {VERSION}",
            f"# Run ID: {RUN_ID}",
            "[Journal]",
            "Storage=persistent",
            "SystemMaxUse=200M",
            "RuntimeMaxUse=100M",
            "MaxRetentionSec=1month",
            "Compress=yes",
            "",
        ]
    )

    write_root_file_via_temp(s, JOURNALD_DROPIN_FILE, content, mode="0644", create_parent=True)
    sudo(s, ["systemctl", "restart", "systemd-journald"], check=False)


def apply_unattended(s: Settings) -> None:
    if not s.apply_unattended:
        warn(s, "Skipping unattended-upgrades apply (use --apply-unattended-upgrades)")
        return

    info(s, "Installing/enabling unattended-upgrades")
    apt_install_missing(s, PKGS_UPDATES)
    sudo(s, ["systemctl", "enable", "--now", "unattended-upgrades"], check=False)
    sudo(
        s,
        [
            "bash",
            "-lc",
            "DEBIAN_FRONTEND=noninteractive dpkg-reconfigure -f noninteractive unattended-upgrades >/dev/null 2>&1 || true",
        ],
        check=False,
    )


def apply_timesync(s: Settings) -> None:
    if not s.apply_timesync:
        warn(s, "Skipping time sync apply (use --apply-timesync)")
        return

    if have("timedatectl"):
        info(s, "Enabling NTP via timedatectl")
        sudo(s, ["timedatectl", "set-ntp", "true"], check=False)
    else:
        warn(s, "timedatectl not found")

    if have("systemctl"):
        sudo(s, ["systemctl", "enable", "--now", "systemd-timesyncd"], check=False)


def _set_sshd_key_value(lines: List[str], key: str, value: str) -> List[str]:
    key_lower = key.lower()
    replaced = False
    out: List[str] = []

    for line in lines:
        stripped = line.strip()

        if stripped.lower().startswith("match "):
            out.append(line)
            continue

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


def validate_sshd_config(s: Settings, candidate_text: str) -> bool:
    sshd_bin = shutil.which("sshd")
    if not sshd_bin:
        warn(s, "sshd binary not found; cannot validate sshd_config")
        return False

    with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False) as tf:
        tf.write(candidate_text)
        temp_path = tf.name

    try:
        rc, _, err_raw = run(s, [sshd_bin, "-t", "-f", temp_path], check=False)
        stderr = filter_stderr(err_raw)
        if rc != 0:
            error(s, "sshd_config validation failed", {"stderr": stderr})
            return False
        return True
    finally:
        try:
            Path(temp_path).unlink(missing_ok=True)
        except Exception:
            pass


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
    lines = safe_read_text(SSHD_CONF).splitlines()

    lines = _set_sshd_key_value(lines, "PermitRootLogin", "no")
    lines = _set_sshd_key_value(lines, "X11Forwarding", "no")
    lines = _set_sshd_key_value(lines, "MaxAuthTries", "3")

    if s.ssh_keys_only:
        lines = _set_sshd_key_value(lines, "PasswordAuthentication", "no")
    else:
        lines = _set_sshd_key_value(lines, "PasswordAuthentication", "yes")

    new_text = "\n".join(lines) + "\n"

    if not validate_sshd_config(s, new_text):
        raise RuntimeError("Refusing to replace live sshd_config because validation failed")

    write_root_file_via_temp(s, SSHD_CONF, new_text, mode="0600")

    if have("systemctl"):
        sudo(s, ["systemctl", "restart", "ssh"], check=False)
        sudo(s, ["systemctl", "restart", "sshd"], check=False)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="07_posture_hardening.py")
    p.add_argument("--yes", action="store_true", help="Pass -y to apt-get install operations")
    p.add_argument("--json", action="store_true", help="Emit JSON events to stdout")

    p.add_argument("--apply-sysctl", action="store_true", help="Apply sysctl baseline")
    p.add_argument("--apply-journald", action="store_true", help="Enable persistent journald + caps")
    p.add_argument("--apply-unattended-upgrades", action="store_true", help="Enable unattended security upgrades")
    p.add_argument("--apply-timesync", action="store_true", help="Enable time synchronization")
    p.add_argument("--apply-ssh", action="store_true", help="Apply conservative SSH hardening")
    p.add_argument("--ssh-keys-only", action="store_true", help="Use only with --apply-ssh; disable PasswordAuthentication")

    return p


def main() -> int:
    args = build_parser().parse_args()

    if args.ssh_keys_only and not args.apply_ssh:
        print("ERROR: --ssh-keys-only requires --apply-ssh", file=sys.stderr)
        return 2

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

    info(
        s,
        f"{APP_NAME} — {STAGE_NAME} start",
        {
            "version": VERSION,
            "script": str(Path(__file__).resolve()),
            "log": str(s.log_file),
            "snapshot_dir": str(s.snapshot_root),
        },
    )

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
            "managed_files": {
                "sysctl": str(SYSCTL_FILE),
                "journald_dropin": str(JOURNALD_DROPIN_FILE),
                "sshd_config": str(SSHD_CONF),
            },
        },
    )

    info(s, f"{STAGE_NAME} complete", {"log": str(s.log_file), "snapshot_dir": str(s.snapshot_root)})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


"""
INSTRUCTIONS
============

FILE LOCATION
-------------
Recommended filename:
    07_posture_hardening.py

Recommended repo placement:
    Put this file in the root of your ZTD repo or in the exact stage location
    you are using for the rest of the suite.

MAKE EXECUTABLE
---------------
chmod +x 07_posture_hardening.py

RUN
---
Report only:
    ./07_posture_hardening.py

Run with Python:
    python3 07_posture_hardening.py

Apply sysctl:
    ./07_posture_hardening.py --yes --apply-sysctl

Apply journald:
    ./07_posture_hardening.py --yes --apply-journald

Apply unattended security updates:
    ./07_posture_hardening.py --yes --apply-unattended-upgrades

Apply time sync:
    ./07_posture_hardening.py --yes --apply-timesync

Apply SSH hardening:
    ./07_posture_hardening.py --yes --apply-ssh

Apply SSH hardening with keys only:
    ./07_posture_hardening.py --yes --apply-ssh --ssh-keys-only

Apply everything:
    ./07_posture_hardening.py --yes --apply-sysctl --apply-journald --apply-unattended-upgrades --apply-timesync --apply-ssh

JSON STDOUT MODE
----------------
Machine-readable stdout:
    ./07_posture_hardening.py --json
    ./07_posture_hardening.py --yes --apply-sysctl --json

WHERE OUTPUT GOES
-----------------
JSONL logs:
    ~/.local/state/zero-trust-desktop/ztd_07/log/

Snapshots:
    ~/.local/state/zero-trust-desktop/ztd_07/snapshots/

NOTES
-----
- This script is safe to run from any directory.
- It uses absolute paths for managed system files.
- It writes user-state output under ~/.local/state/zero-trust-desktop/ztd_07/.
- SSH config is validated before live replacement.
- Do NOT use --ssh-keys-only unless key-based login already works.
- Journald is managed with a drop-in file:
      /etc/systemd/journald.conf.d/99-ztd-hardening.conf
  instead of rewriting the distro-owned base config.
- This version avoids most shell-wrapper noise during snapshots.
- Known ignorable Flatpak loader stderr is filtered from logs and snapshots.

QUICK VERIFY
------------
Check snapshots created:
    ls -lah ~/.local/state/zero-trust-desktop/ztd_07/snapshots/

Check latest log:
    ls -lah ~/.local/state/zero-trust-desktop/ztd_07/log/

Check sysctl file:
    sudo cat /etc/sysctl.d/99-ztd-hardening.conf

Check journald drop-in:
    sudo cat /etc/systemd/journald.conf.d/99-ztd-hardening.conf

Check SSH config:
    sudo grep -E '^(PermitRootLogin|PasswordAuthentication|X11Forwarding|MaxAuthTries) ' /etc/ssh/sshd_config

TROUBLESHOOTING
---------------
If apt update fails:
    - verify internet connectivity
    - verify sudo access
    - rerun the command and inspect the JSONL log

If SSH service restart fails:
    - inspect:
        sudo systemctl status ssh
        sudo systemctl status sshd
    - inspect current config:
        sudo sshd -t

If journald settings do not appear active:
    - inspect:
        sudo systemctl status systemd-journald
        journalctl --disk-usage

END
"""
