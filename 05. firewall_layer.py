#!/usr/bin/env python3
"""
README
======

Filename:
    05_firewall_layer.py

Purpose:
    Zero Trust Desktop (ZTD) — Stage 05 Firewall Layer.

    Professional-grade, dev-safe firewall authority layer for Debian/Ubuntu.
    This version follows the current script standard:
        - README at top
        - integrated signature/topper support
        - best-effort execution by default
        - instructions block at bottom
        - rerunnable from any directory
        - install/check behavior instead of blind enforcement

What this script does:
    - Verifies platform compatibility
    - Verifies sudo access
    - Optionally refreshes apt metadata
    - Installs missing firewall tooling idempotently
    - Captures authoritative firewall snapshots before and after any changes
    - Optionally applies a conservative UFW baseline
    - Optionally installs persistence tooling
    - Optionally saves current iptables rules
    - Writes structured JSONL logs and a run manifest

Core safety principles:
    - Safe by default
    - No enforcement unless explicitly requested
    - No blind firewall reset
    - No rule flush
    - No destructive changes
    - SSH safety checks before enabling UFW
    - Continue section-by-section where possible
    - Runnable from any directory

Important lockout protection:
    If you use --apply-ufw-baseline, the script attempts to avoid lockout by:
        - Detecting active SSH listeners
        - Allowing OpenSSH profile if available
        - Allowing detected TCP SSH ports explicitly
        - Allowing loopback
        - Refusing to enable UFW if no SSH allowance can be confirmed unless you force it

Default behavior:
    - Validate platform
    - Validate sudo access
    - Optionally apt-get update
    - Install missing firewall packages
    - Snapshot BEFORE state
    - Perform optional operations
    - Snapshot AFTER state
    - Write manifest + summary

Behavior-changing flags:
    --apply-ufw-baseline
        Apply conservative UFW policy and enable UFW.

    --install-iptables-persistent
        Install iptables-persistent package.

    --save-iptables
        Save current iptables rules with netfilter-persistent if available.

Outputs:
    Logs:
        ~/.local/state/zero-trust-desktop/ztd_05/log/

    Run root:
        ~/.local/state/zero-trust-desktop/ztd_05/runs/<timestamp>/

    Snapshots:
        ~/.local/state/zero-trust-desktop/ztd_05/runs/<timestamp>/before/
        ~/.local/state/zero-trust-desktop/ztd_05/runs/<timestamp>/after/

Supported systems:
    - Debian
    - Ubuntu
    - Debian-derived systems with apt-get + dpkg
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import random
import re
import shutil
import subprocess
import sys
import time
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Callable, Iterable, Optional, Sequence


# =========================================================
# SCRIPT IDENTITY
# =========================================================

APP_NAME = "Zero Trust Desktop"
APP_ID = "ztd"
STAGE_NAME = "05. FIREWALL LAYER"
STAGE_ID = "ztd_05_firewall_layer"
VERSION = "1.0.0"

SCRIPT_NAME = Path(__file__).name
SCRIPT_SIGNATURE = "SABLE // ZTD FIREWALL AUTHORITY LAYER"
OPERATOR_NAME = "ELLIOT"


# =========================================================
# PATHS / STATE
# =========================================================

HOME = Path.home()
STATE_DIR = HOME / ".local" / "state" / "zero-trust-desktop" / "ztd_05"
LOG_DIR = STATE_DIR / "log"
RUNS_DIR = STATE_DIR / "runs"

RUN_ID = datetime.now().strftime("%Y%m%d_%H%M%S")
RUN_ROOT = RUNS_DIR / RUN_ID
BEFORE_DIR = RUN_ROOT / "before"
AFTER_DIR = RUN_ROOT / "after"
META_FILE = RUN_ROOT / "run_manifest.json"
LOG_FILE = LOG_DIR / f"{STAGE_ID}_{RUN_ID}.jsonl"

DEFAULT_CMD_TIMEOUT = 900
MAX_LOG_SNIPPET = 16000

PKGS_FIREWALL = [
    "nftables",
    "ufw",
    "iptables",
    "conntrack",
    "iproute2",
]

PKGS_PERSIST = [
    "iptables-persistent",
]


# =========================================================
# TOPPER / SIGNATURE
# =========================================================

ANSI_RESET = "\033[0m"
ANSI_BOLD = "\033[1m"
ANSI_DIM = "\033[2m"
ANSI_GREEN = "\033[32m"
ANSI_BRIGHT_GREEN = "\033[92m"
ANSI_HIDE_CURSOR = "\033[?25l"
ANSI_SHOW_CURSOR = "\033[?25h"
ANSI_ALTSCREEN_ON = "\033[?1049h"
ANSI_ALTSCREEN_OFF = "\033[?1049l"
ANSI_CLEAR = "\033[2J\033[H"


def _is_safe_interactive_terminal() -> bool:
    try:
        if os.name != "posix":
            return False
        if not sys.stdout.isatty():
            return False
        if not sys.stdin.isatty():
            return False
        term = os.environ.get("TERM", "").strip().lower()
        if not term or term == "dumb":
            return False
        return True
    except Exception:
        return False


def _write(text: str) -> None:
    sys.stdout.write(text)
    sys.stdout.flush()


def _term_size() -> tuple[int, int]:
    try:
        size = shutil.get_terminal_size(fallback=(100, 30))
        return max(40, size.columns), max(16, size.lines)
    except Exception:
        return 100, 30


def _center(text: str, width: int) -> str:
    if len(text) >= width:
        return text[:width]
    return (" " * ((width - len(text)) // 2)) + text


@contextmanager
def _terminal_overlay():
    entered = False
    try:
        _write(ANSI_ALTSCREEN_ON)
        _write(ANSI_HIDE_CURSOR)
        _write(ANSI_CLEAR)
        entered = True
        yield
    finally:
        try:
            if entered:
                _write(ANSI_RESET)
                _write(ANSI_SHOW_CURSOR)
                _write(ANSI_ALTSCREEN_OFF)
            else:
                _write(ANSI_RESET + ANSI_SHOW_CURSOR)
        except Exception:
            pass


def run_script_signature_topper(
    total_seconds: float = 4.0,
    countdown: int = 1,
    title: str = "ZERO TRUST DESKTOP",
    operator_name: str = OPERATOR_NAME,
    operator_signature: str = SCRIPT_SIGNATURE,
    script_name: str = SCRIPT_NAME,
    script_version: str = VERSION,
) -> None:
    """
    Safe integrated signature topper.
    Skips automatically in unsafe/non-interactive terminal environments.
    """
    if not _is_safe_interactive_terminal():
        return

    width, _height = _term_size()
    total_seconds = max(2.0, total_seconds)
    countdown = max(1, countdown)

    try:
        with _terminal_overlay():
            print()
            print(_center(f"{ANSI_BRIGHT_GREEN}{ANSI_BOLD}{title}{ANSI_RESET}", width))
            print()
            rows = [
                f"operator : {operator_name}",
                f"signature: {operator_signature}",
                f"script   : {script_name}",
                f"version  : {script_version}",
            ]
            border = "─" * 56
            print(_center(f"{ANSI_GREEN}┌{border}┐{ANSI_RESET}", width))
            for row in rows:
                padded = row[:56].ljust(56)
                print(_center(f"{ANSI_GREEN}│{ANSI_RESET}{padded}{ANSI_GREEN}│{ANSI_RESET}", width))
            print(_center(f"{ANSI_GREEN}└{border}┘{ANSI_RESET}", width))
            time.sleep(min(1.2, total_seconds / 2))

            for i in range(countdown, 0, -1):
                _write("\033[H" + ANSI_CLEAR)
                print()
                print(_center(f"{ANSI_BRIGHT_GREEN}{ANSI_BOLD}{title}{ANSI_RESET}", width))
                print()
                print(_center(f"{ANSI_GREEN}system arm in {i}...{ANSI_RESET}", width))
                time.sleep(1.0)

    except KeyboardInterrupt:
        raise
    except Exception:
        try:
            _write(ANSI_RESET + ANSI_SHOW_CURSOR)
        except Exception:
            pass


# =========================================================
# DATA CLASSES
# =========================================================

@dataclass
class Settings:
    yes: bool
    json_stdout: bool
    apply_ufw_baseline: bool
    install_iptables_persistent: bool
    save_iptables: bool
    skip_apt_update: bool
    force_ufw_enable: bool
    strict: bool
    no_topper: bool
    log_file: Path
    run_root: Path
    before_dir: Path
    after_dir: Path
    meta_file: Path
    timeout_seconds: int = DEFAULT_CMD_TIMEOUT


@dataclass
class Event:
    ts: str
    level: str
    msg: str
    data: Optional[dict] = None


# =========================================================
# LOGGING / HELPERS
# =========================================================

def now_ts() -> str:
    return datetime.now().isoformat(timespec="seconds")


def have(cmd: str) -> bool:
    return shutil.which(cmd) is not None


def emit(settings: Settings, ev: Event) -> None:
    if settings.json_stdout:
        print(json.dumps(asdict(ev), ensure_ascii=False))
    else:
        if ev.data is None:
            print(f"[{ev.ts}] {ev.level}: {ev.msg}")
        else:
            print(f"[{ev.ts}] {ev.level}: {ev.msg} :: {json.dumps(ev.data, ensure_ascii=False)}")

    settings.log_file.parent.mkdir(parents=True, exist_ok=True)
    with settings.log_file.open("a", encoding="utf-8") as f:
        f.write(json.dumps(asdict(ev), ensure_ascii=False) + "\n")


def info(settings: Settings, msg: str, data: Optional[dict] = None) -> None:
    emit(settings, Event(ts=now_ts(), level="INFO", msg=msg, data=data))


def warn(settings: Settings, msg: str, data: Optional[dict] = None) -> None:
    emit(settings, Event(ts=now_ts(), level="WARN", msg=msg, data=data))


def error(settings: Settings, msg: str, data: Optional[dict] = None) -> None:
    emit(settings, Event(ts=now_ts(), level="ERROR", msg=msg, data=data))


def clip_text(text: str, limit: int = MAX_LOG_SNIPPET) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n... [truncated, original_length={len(text)}]"


def write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8", errors="ignore")


def write_manifest(settings: Settings) -> None:
    settings.run_root.mkdir(parents=True, exist_ok=True)
    payload = {
        "app_name": APP_NAME,
        "app_id": APP_ID,
        "stage_name": STAGE_NAME,
        "stage_id": STAGE_ID,
        "version": VERSION,
        "run_id": RUN_ID,
        "created_at": now_ts(),
        "script_name": SCRIPT_NAME,
        "script_signature": SCRIPT_SIGNATURE,
        "log_file": str(settings.log_file),
        "run_root": str(settings.run_root),
        "before_dir": str(settings.before_dir),
        "after_dir": str(settings.after_dir),
        "system": {
            "platform": platform.platform(),
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
            "python": sys.version.splitlines()[0],
        },
        "flags": {
            "yes": settings.yes,
            "json_stdout": settings.json_stdout,
            "apply_ufw_baseline": settings.apply_ufw_baseline,
            "install_iptables_persistent": settings.install_iptables_persistent,
            "save_iptables": settings.save_iptables,
            "skip_apt_update": settings.skip_apt_update,
            "force_ufw_enable": settings.force_ufw_enable,
            "strict": settings.strict,
            "no_topper": settings.no_topper,
        },
    }
    write_text(settings.meta_file, json.dumps(payload, indent=2, ensure_ascii=False) + "\n")


def run(
    settings: Settings,
    cmd: Sequence[str],
    *,
    check: bool = True,
    timeout: Optional[int] = None,
) -> subprocess.CompletedProcess[str]:
    cmd = list(cmd)
    timeout = settings.timeout_seconds if timeout is None else timeout

    info(settings, "$ " + " ".join(cmd), {"timeout_seconds": timeout})

    try:
        proc = subprocess.run(
            cmd,
            text=True,
            capture_output=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        error(settings, "Command timed out", {"cmd": cmd, "timeout_seconds": timeout})
        raise RuntimeError(f"Command timed out: {' '.join(cmd)}") from exc
    except Exception as exc:
        error(settings, "Command execution exception", {"cmd": cmd, "error": str(exc)})
        raise

    stdout = (proc.stdout or "").strip()
    stderr = (proc.stderr or "").strip()

    if stdout:
        info(settings, "stdout", {"cmd": cmd, "stdout": clip_text(stdout)})
    if stderr:
        warn(settings, "stderr", {"cmd": cmd, "stderr": clip_text(stderr)})

    if check and proc.returncode != 0:
        error(
            settings,
            "Command failed",
            {"rc": proc.returncode, "cmd": cmd, "stderr": clip_text(stderr)},
        )
        raise RuntimeError(f"Command failed: {' '.join(cmd)} (rc={proc.returncode})")

    return proc


def sudo(
    settings: Settings,
    cmd: Sequence[str],
    *,
    check: bool = True,
    timeout: Optional[int] = None,
) -> subprocess.CompletedProcess[str]:
    return run(settings, ["sudo", *cmd], check=check, timeout=timeout)


def best_effort_block(settings: Settings, label: str, fn: Callable[[], None]) -> bool:
    try:
        fn()
        return True
    except Exception as exc:
        error(settings, f"{label} failed", {"error": str(exc)})
        if settings.strict:
            raise
        warn(settings, f"{label} continuing in best-effort mode")
        return False


# =========================================================
# PLATFORM / PACKAGE MANAGEMENT
# =========================================================

def require_debian_like(settings: Settings) -> None:
    if not Path("/etc/os-release").exists():
        error(settings, "Unsupported platform: /etc/os-release not found")
        raise SystemExit(2)
    if not have("apt-get") or not have("dpkg"):
        error(settings, "Unsupported platform: apt-get/dpkg required")
        raise SystemExit(2)


def validate_sudo(settings: Settings) -> None:
    info(settings, "Validating sudo access")
    sudo(settings, ["-v"], check=True, timeout=120)


def dpkg_installed(pkg: str) -> bool:
    proc = subprocess.run(
        ["dpkg", "-s", pkg],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return proc.returncode == 0


def apt_update(settings: Settings) -> None:
    if settings.skip_apt_update:
        warn(settings, "Skipping apt update by request (--skip-apt-update)")
        return

    cmd = ["apt-get", "update"]
    if settings.yes:
        cmd.append("-y")
    sudo(settings, cmd, check=True)


def apt_install_missing(settings: Settings, pkgs: Iterable[str]) -> list[str]:
    pkgs = list(pkgs)
    missing = [pkg for pkg in pkgs if not dpkg_installed(pkg)]

    for pkg in pkgs:
        if pkg in missing:
            info(settings, f"Installing missing package: {pkg}")
        else:
            info(settings, f"Already installed: {pkg}")

    if not missing:
        return []

    env = os.environ.copy()
    env["DEBIAN_FRONTEND"] = "noninteractive"

    cmd = ["sudo", "apt-get", "install"]
    if settings.yes:
        cmd.append("-y")
    cmd.extend(missing)

    info(settings, "Installing missing packages", {"packages": missing})

    proc = subprocess.run(
        cmd,
        text=True,
        capture_output=True,
        timeout=settings.timeout_seconds,
        env=env,
    )

    stdout = (proc.stdout or "").strip()
    stderr = (proc.stderr or "").strip()

    if stdout:
        info(settings, "stdout", {"cmd": cmd, "stdout": clip_text(stdout)})
    if stderr:
        warn(settings, "stderr", {"cmd": cmd, "stderr": clip_text(stderr)})

    if proc.returncode != 0:
        raise RuntimeError(f"Package install failed for: {', '.join(missing)}")

    return missing


# =========================================================
# SNAPSHOTS
# =========================================================

def capture_cmd(settings: Settings, out_dir: Path, filename: str, cmd: Sequence[str]) -> None:
    try:
        proc = run(settings, cmd, check=False)
        stdout = proc.stdout or ""
        stderr = proc.stderr or ""
        blob = stdout if stdout.strip() else stderr
        if not blob.strip():
            blob = f"(no output)\nreturn_code={proc.returncode}\n"
        write_text(out_dir / filename, blob.rstrip() + "\n")
    except Exception as exc:
        warn(settings, f"Snapshot capture failed: {filename}", {"error": str(exc)})
        write_text(out_dir / filename, f"snapshot capture failed: {exc}\n")


def snapshot_all(settings: Settings, out_dir: Path, label: str) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)

    info(
        settings,
        f"Snapshot start: {label}",
        {
            "snapshot_dir": str(out_dir),
            "system": f"{platform.system()} {platform.release()}",
            "arch": platform.machine(),
            "python": sys.version.splitlines()[0],
        },
    )

    if have("nft"):
        capture_cmd(settings, out_dir, "nft_list_ruleset.txt", ["sudo", "nft", "list", "ruleset"])
    else:
        write_text(out_dir / "nft_list_ruleset.txt", "nft not found\n")

    if have("ufw"):
        capture_cmd(settings, out_dir, "ufw_status_verbose.txt", ["sudo", "ufw", "status", "verbose"])
        capture_cmd(settings, out_dir, "ufw_app_list.txt", ["bash", "-lc", "sudo ufw app list 2>&1 || true"])
    else:
        write_text(out_dir / "ufw_status_verbose.txt", "ufw not found\n")
        write_text(out_dir / "ufw_app_list.txt", "ufw not found\n")

    if have("iptables-save"):
        capture_cmd(settings, out_dir, "iptables_save.txt", ["sudo", "iptables-save"])
    else:
        write_text(out_dir / "iptables_save.txt", "iptables-save not found\n")

    if have("ip6tables-save"):
        capture_cmd(settings, out_dir, "ip6tables_save.txt", ["sudo", "ip6tables-save"])
    else:
        write_text(out_dir / "ip6tables_save.txt", "ip6tables-save not found\n")

    if have("update-alternatives"):
        capture_cmd(
            settings,
            out_dir,
            "iptables_alternatives.txt",
            ["bash", "-lc", "update-alternatives --display iptables 2>&1 || true"],
        )
        capture_cmd(
            settings,
            out_dir,
            "ip6tables_alternatives.txt",
            ["bash", "-lc", "update-alternatives --display ip6tables 2>&1 || true"],
        )
    else:
        write_text(out_dir / "iptables_alternatives.txt", "update-alternatives not found\n")
        write_text(out_dir / "ip6tables_alternatives.txt", "update-alternatives not found\n")

    if have("iptables"):
        capture_cmd(settings, out_dir, "iptables_version.txt", ["bash", "-lc", "iptables --version 2>&1 || true"])
    else:
        write_text(out_dir / "iptables_version.txt", "iptables not found\n")

    if have("nft"):
        capture_cmd(settings, out_dir, "nft_version.txt", ["bash", "-lc", "nft --version 2>&1 || true"])
    else:
        write_text(out_dir / "nft_version.txt", "nft not found\n")

    if have("ss"):
        capture_cmd(settings, out_dir, "ss_listen.txt", ["bash", "-lc", "ss -tulnp | sed -n '1,300p'"])
        capture_cmd(settings, out_dir, "ss_established.txt", ["bash", "-lc", "ss -tnp state established | sed -n '1,300p'"])
    else:
        write_text(out_dir / "ss_listen.txt", "ss not found\n")
        write_text(out_dir / "ss_established.txt", "ss not found\n")

    capture_cmd(
        settings,
        out_dir,
        "sysctl_net.txt",
        [
            "bash",
            "-lc",
            (
                "sysctl "
                "net.ipv4.ip_forward "
                "net.ipv4.conf.all.rp_filter "
                "net.ipv4.conf.default.rp_filter "
                "net.ipv6.conf.all.disable_ipv6 "
                "2>/dev/null || true"
            ),
        ],
    )

    capture_cmd(
        settings,
        out_dir,
        "packages_firewall.txt",
        ["bash", "-lc", "dpkg -l nftables ufw iptables conntrack iptables-persistent iproute2 2>/dev/null || true"],
    )

    info(settings, f"Snapshot complete: {label}", {"snapshot_dir": str(out_dir)})


# =========================================================
# UFW SAFETY
# =========================================================

def detect_ssh_listener_ports(settings: Settings) -> list[int]:
    ports = set()

    if have("ss"):
        try:
            proc = run(settings, ["bash", "-lc", "ss -tlnp 2>/dev/null | sed -n '1,300p'"], check=False, timeout=60)
            text = (proc.stdout or "") + "\n" + (proc.stderr or "")
            for line in text.splitlines():
                if "sshd" in line.lower():
                    matches = re.findall(r":(\d+)\s", line + " ")
                    for match in matches:
                        port = int(match)
                        if 1 <= port <= 65535:
                            ports.add(port)
        except Exception as exc:
            warn(settings, "Failed to inspect ssh listener ports", {"error": str(exc)})

    sshd_config = Path("/etc/ssh/sshd_config")
    if sshd_config.exists():
        try:
            for raw in sshd_config.read_text(encoding="utf-8", errors="ignore").splitlines():
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                if line.lower().startswith("port "):
                    value = line.split(None, 1)[1].strip()
                    if value.isdigit():
                        port = int(value)
                        if 1 <= port <= 65535:
                            ports.add(port)
        except Exception as exc:
            warn(settings, "Failed to parse sshd_config", {"error": str(exc)})

    if not ports:
        ports.add(22)

    result = sorted(ports)
    info(settings, "Detected SSH listener ports", {"ports": result})
    return result


def can_resolve_openssh_profile(settings: Settings) -> bool:
    if not have("ufw"):
        return False
    try:
        proc = run(settings, ["bash", "-lc", "sudo ufw app info OpenSSH 2>&1 || true"], check=False, timeout=60)
        text = ((proc.stdout or "") + "\n" + (proc.stderr or "")).lower()
        return "openssh" in text
    except Exception:
        return False


def ufw_allow_rule(settings: Settings, rule: list[str]) -> bool:
    try:
        sudo(settings, ["ufw", *rule], check=False, timeout=120)
        return True
    except Exception as exc:
        warn(settings, "Failed UFW allow rule", {"rule": rule, "error": str(exc)})
        return False


def apply_ufw_baseline(settings: Settings) -> None:
    if not settings.apply_ufw_baseline:
        warn(settings, "Skipping UFW baseline (use --apply-ufw-baseline to apply)")
        return

    if not have("ufw"):
        warn(settings, "ufw not found; cannot apply baseline")
        return

    ssh_ports = detect_ssh_listener_ports(settings)
    openssh_profile_ok = can_resolve_openssh_profile(settings)
    allowed_any_ssh = False

    info(
        settings,
        "Applying conservative UFW baseline with SSH safety protections",
        {
            "incoming_default": "deny",
            "outgoing_default": "allow",
            "ssh_ports_detected": ssh_ports,
            "openssh_profile_available": openssh_profile_ok,
        },
    )

    ufw_allow_rule(settings, ["allow", "in", "on", "lo"])
    ufw_allow_rule(settings, ["allow", "out", "on", "lo"])

    if openssh_profile_ok:
        if ufw_allow_rule(settings, ["allow", "OpenSSH"]):
            allowed_any_ssh = True

    for port in ssh_ports:
        if ufw_allow_rule(settings, ["allow", f"{port}/tcp"]):
            allowed_any_ssh = True

    if not allowed_any_ssh and not settings.force_ufw_enable:
        warn(
            settings,
            "Refusing to enable UFW because no SSH-safe allowance could be confirmed. Use --force-ufw-enable to override."
        )
        return

    sudo(settings, ["ufw", "default", "deny", "incoming"], check=False)
    sudo(settings, ["ufw", "default", "allow", "outgoing"], check=False)
    sudo(settings, ["ufw", "--force", "enable"], check=False)

    status = run(settings, ["sudo", "ufw", "status", "verbose"], check=False, timeout=60)
    status_text = ((status.stdout or "") + "\n" + (status.stderr or "")).lower()
    if "status: active" in status_text:
        info(settings, "UFW enable confirmed")
    else:
        warn(settings, "UFW status could not be confirmed as active")


# =========================================================
# OPTIONAL PERSISTENCE
# =========================================================

def install_persistence(settings: Settings) -> None:
    if not settings.install_iptables_persistent:
        warn(settings, "Skipping iptables persistence install")
        return
    info(settings, "Installing iptables persistence tooling")
    apt_install_missing(settings, PKGS_PERSIST)


def save_iptables_rules(settings: Settings) -> None:
    if not settings.save_iptables:
        warn(settings, "Skipping iptables save")
        return
    if not have("netfilter-persistent"):
        warn(settings, "netfilter-persistent not found; install with --install-iptables-persistent")
        return
    info(settings, "Saving current iptables rules via netfilter-persistent")
    sudo(settings, ["netfilter-persistent", "save"], check=False)


# =========================================================
# SUMMARY / PARSER
# =========================================================

def report_summary(settings: Settings) -> None:
    info(
        settings,
        "Run summary",
        {
            "app": APP_ID,
            "stage": STAGE_ID,
            "version": VERSION,
            "script_name": SCRIPT_NAME,
            "script_signature": SCRIPT_SIGNATURE,
            "log_file": str(settings.log_file),
            "run_root": str(settings.run_root),
            "before_dir": str(settings.before_dir),
            "after_dir": str(settings.after_dir),
            "apply_ufw_baseline": settings.apply_ufw_baseline,
            "install_iptables_persistent": settings.install_iptables_persistent,
            "save_iptables": settings.save_iptables,
            "skip_apt_update": settings.skip_apt_update,
            "force_ufw_enable": settings.force_ufw_enable,
            "strict": settings.strict,
        },
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="05_firewall_layer.py")
    parser.add_argument("--yes", action="store_true", help="Pass -y to apt-get")
    parser.add_argument("--json", action="store_true", help="Emit JSON events to stdout")
    parser.add_argument("--apply-ufw-baseline", action="store_true", help="Apply conservative UFW baseline and enable ufw")
    parser.add_argument("--install-iptables-persistent", action="store_true", help="Install iptables-persistent package")
    parser.add_argument("--save-iptables", action="store_true", help="Save current iptables rules via netfilter-persistent")
    parser.add_argument("--skip-apt-update", action="store_true", help="Do not run apt-get update")
    parser.add_argument("--force-ufw-enable", action="store_true", help="Force UFW enable even if SSH-safe allowance cannot be confirmed")
    parser.add_argument("--strict", action="store_true", help="Stop immediately on section failure instead of best-effort continuation")
    parser.add_argument("--no-topper", action="store_true", help="Disable integrated signature topper")
    return parser


# =========================================================
# MAIN
# =========================================================

def main() -> int:
    args = build_parser().parse_args()

    settings = Settings(
        yes=bool(args.yes),
        json_stdout=bool(args.json),
        apply_ufw_baseline=bool(args.apply_ufw_baseline),
        install_iptables_persistent=bool(args.install_iptables_persistent),
        save_iptables=bool(args.save_iptables),
        skip_apt_update=bool(args.skip_apt_update),
        force_ufw_enable=bool(args.force_ufw_enable),
        strict=bool(args.strict),
        no_topper=bool(args.no_topper),
        log_file=LOG_FILE,
        run_root=RUN_ROOT,
        before_dir=BEFORE_DIR,
        after_dir=AFTER_DIR,
        meta_file=META_FILE,
    )

    settings.run_root.mkdir(parents=True, exist_ok=True)
    settings.before_dir.mkdir(parents=True, exist_ok=True)
    settings.after_dir.mkdir(parents=True, exist_ok=True)
    settings.log_file.parent.mkdir(parents=True, exist_ok=True)

    if not settings.no_topper:
        run_script_signature_topper(
            total_seconds=4,
            countdown=1,
            title="ZERO TRUST DESKTOP",
            operator_name=OPERATOR_NAME,
            operator_signature=SCRIPT_SIGNATURE,
            script_name=SCRIPT_NAME,
            script_version=VERSION,
        )

    require_debian_like(settings)
    write_manifest(settings)

    info(
        settings,
        f"{APP_NAME} — {STAGE_NAME} start",
        {
            "version": VERSION,
            "script_name": SCRIPT_NAME,
            "script_signature": SCRIPT_SIGNATURE,
            "log_file": str(settings.log_file),
            "run_root": str(settings.run_root),
            "best_effort_mode": not settings.strict,
        },
    )

    info(settings, "[1/7] validate sudo")
    best_effort_block(settings, "validate sudo", lambda: validate_sudo(settings))

    info(settings, "[2/7] apt update")
    best_effort_block(settings, "apt update", lambda: apt_update(settings))

    info(settings, "[3/7] install firewall tooling (idempotent)")
    best_effort_block(settings, "install firewall tooling", lambda: apt_install_missing(settings, PKGS_FIREWALL))

    info(settings, "[4/7] snapshot BEFORE optional apply")
    best_effort_block(settings, "snapshot before", lambda: snapshot_all(settings, settings.before_dir, "before"))

    info(settings, "[5/7] optional apply operations")
    best_effort_block(settings, "install persistence", lambda: install_persistence(settings))
    best_effort_block(settings, "apply ufw baseline", lambda: apply_ufw_baseline(settings))
    best_effort_block(settings, "save iptables rules", lambda: save_iptables_rules(settings))

    info(settings, "[6/7] snapshot AFTER optional apply")
    best_effort_block(settings, "snapshot after", lambda: snapshot_all(settings, settings.after_dir, "after"))

    info(settings, "[7/7] final summary")
    report_summary(settings)

    info(
        settings,
        f"{STAGE_NAME} complete",
        {
            "log_file": str(settings.log_file),
            "run_root": str(settings.run_root),
            "before_dir": str(settings.before_dir),
            "after_dir": str(settings.after_dir),
        },
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


"""
INSTRUCTIONS / USAGE
====================

Save as:
    05_firewall_layer.py

Make executable:
    chmod +x 05_firewall_layer.py

Run safe default:
    python3 05_firewall_layer.py --yes

Run safe default without apt metadata refresh:
    python3 05_firewall_layer.py --yes --skip-apt-update

Run from any directory:
    python3 /full/path/to/05_firewall_layer.py --yes

Apply conservative UFW baseline with SSH lockout protection:
    python3 05_firewall_layer.py --yes --apply-ufw-baseline

Install persistence tooling:
    python3 05_firewall_layer.py --yes --install-iptables-persistent

Save current iptables rules:
    python3 05_firewall_layer.py --yes --install-iptables-persistent --save-iptables

Strict mode:
    python3 05_firewall_layer.py --yes --strict

Disable topper/signature animation:
    python3 05_firewall_layer.py --yes --no-topper

JSON stdout mode:
    python3 05_firewall_layer.py --yes --json

Default operating model:
    - Checks what is already installed
    - Installs only what is missing
    - Continues section-by-section unless you use --strict
    - Does not enforce firewall rules unless you explicitly request it
    - Tries to avoid SSH lockout before enabling UFW

Artifacts written after each run:
    Log file:
        ~/.local/state/zero-trust-desktop/ztd_05/log/

    Run folder:
        ~/.local/state/zero-trust-desktop/ztd_05/runs/<timestamp>/

    Before snapshots:
        ~/.local/state/zero-trust-desktop/ztd_05/runs/<timestamp>/before/

    After snapshots:
        ~/.local/state/zero-trust-desktop/ztd_05/runs/<timestamp>/after/

What changed from your old 0.5.0 file:
    - Added integrated signature/topper block
    - Added README-style professional header
    - Added instructions block at bottom
    - Added best-effort continuation by default
    - Added strict mode for fail-fast behavior
    - Added skip-apt-update mode
    - Split before/after snapshots into separate directories
    - Added SSH-safe UFW enable logic
    - Added loopback allow rules
    - Added manifest structure and stronger logging
    - Kept safe-by-default behavior

Recommended command:
    python3 05_firewall_layer.py --yes
"""#!/usr/bin/env python3
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
