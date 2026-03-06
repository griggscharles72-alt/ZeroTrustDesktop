#!/usr/bin/env python3
"""
README
======

Filename:
    02_protonvpn_layer.py

Purpose:
    Install ProtonVPN on Debian/Ubuntu using Proton's official repository
    bootstrap package, optionally install safe network diagnostic tools,
    create a simple launcher command, and emit verification/log output.

System requirements:
    - Debian / Ubuntu / Debian-derived Linux
    - python3
    - sudo
    - apt-get
    - dpkg
    - Internet access for package/repository download

Behavior:
    Default actions:
        - Validate platform
        - Run apt-get update
        - Install missing base dependencies
        - Install ProtonVPN official repository bootstrap package
        - Install ProtonVPN GUI application
        - Create ~/.local/bin/vpn launcher
        - Emit verification snapshot
        - Write JSONL log to per-run log file

    Optional flags:
        --yes
            Pass -y to apt-get for non-interactive installation.

        --install-tools
            Install safe diagnostic/network tooling.

        --verify
            Emit deeper read-only network verification output.

        --json
            Emit structured JSON events to stdout instead of human-readable text.

        --skip-apt-update
            Skip apt-get update steps.

        --refresh-launcher
            Rewrite the launcher even if it already exists.

        --launcher-name NAME
            Create the launcher with a different name instead of 'vpn'.

Safety / non-goals:
    - Does NOT auto-connect ProtonVPN
    - Does NOT modify firewall rules
    - Does NOT add external kill-switch logic
    - Does NOT remove packages
    - Does NOT write custom routing policy

Paths:
    Script path handling is location-independent and resolved from __file__.

    Runtime paths:
        SCRIPT_PATH
            Absolute path to this file.

        SCRIPT_DIR
            Directory containing this file.

        STATE_DIR
            ~/.local/state/zero-trust-desktop/ztd_02

        LOG_DIR
            ~/.local/state/zero-trust-desktop/ztd_02/log

        LOG_FILE
            Per-run JSONL log file in LOG_DIR

        LAUNCHER_PATH
            ~/.local/bin/<launcher-name>

Example run:
    python3 /full/path/to/02_protonvpn_layer.py --yes
    python3 /full/path/to/02_protonvpn_layer.py --yes --install-tools
    python3 /full/path/to/02_protonvpn_layer.py --yes --install-tools --verify
"""

from __future__ import annotations

import argparse
import json
import platform
import shutil
import subprocess
import sys
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Iterable, Optional, Sequence


# ==============================================================================
# LOCATION-INDEPENDENT PATHS
# ==============================================================================

SCRIPT_PATH = Path(__file__).resolve()
SCRIPT_DIR = SCRIPT_PATH.parent

HOME = Path.home()
STATE_DIR = HOME / ".local" / "state" / "zero-trust-desktop" / "ztd_02"
LOG_DIR = STATE_DIR / "log"
RUN_ID = datetime.now().strftime("%Y%m%d_%H%M%S")
LOG_FILE = LOG_DIR / f"ztd_02_protonvpn_layer_{RUN_ID}.jsonl"


# ==============================================================================
# CONSTANTS
# ==============================================================================

APP_NAME = "Zero Trust Desktop"
STAGE_NAME = "Stage 02 — ProtonVPN Layer"
VERSION = "0.4.0"

PROTON_RELEASE_DEB = "protonvpn-stable-release_1.0.8_all.deb"
PROTON_RELEASE_URL = (
    "https://repo.protonvpn.com/debian/dists/stable/main/binary-all/"
    "protonvpn-stable-release_1.0.8_all.deb"
)

PROTON_RELEASE_PACKAGE = "protonvpn-stable-release"
PROTON_GUI_PACKAGE = "proton-vpn-gnome-desktop"
PROTON_APP_EXECUTABLE = "protonvpn-app"
DEFAULT_LAUNCHER_NAME = "vpn"

BASE_PACKAGES = [
    "ca-certificates",
    "wget",
    "curl",
    "gnupg",
    "apt-transport-https",
]

NETWORK_TOOL_PACKAGES = [
    "iproute2",
    "net-tools",
    "network-manager",
    "dnsutils",
    "jq",
    "curl",
]


# ==============================================================================
# DATA STRUCTURES
# ==============================================================================

@dataclass
class Settings:
    yes: bool
    json_stdout: bool
    install_tools: bool
    verify: bool
    skip_apt_update: bool
    refresh_launcher: bool
    launcher_name: str
    launcher_path: Path
    log_file: Path


@dataclass
class Event:
    ts: str
    level: str
    msg: str
    data: Optional[dict] = None


# ==============================================================================
# LOGGING
# ==============================================================================

def now_ts() -> str:
    return datetime.now().isoformat(timespec="seconds")


def emit(settings: Settings, event: Event) -> None:
    line = json.dumps(asdict(event), ensure_ascii=False)

    if settings.json_stdout:
        print(line)
    else:
        print(f"[{event.ts}] {event.level}: {event.msg}")
        if event.data:
            print(json.dumps(event.data, ensure_ascii=False, indent=2))

    settings.log_file.parent.mkdir(parents=True, exist_ok=True)
    with settings.log_file.open("a", encoding="utf-8") as handle:
        handle.write(line + "\n")


def info(settings: Settings, msg: str, data: Optional[dict] = None) -> None:
    emit(settings, Event(ts=now_ts(), level="INFO", msg=msg, data=data))


def warn(settings: Settings, msg: str, data: Optional[dict] = None) -> None:
    emit(settings, Event(ts=now_ts(), level="WARN", msg=msg, data=data))


def error(settings: Settings, msg: str, data: Optional[dict] = None) -> None:
    emit(settings, Event(ts=now_ts(), level="ERROR", msg=msg, data=data))


# ==============================================================================
# SYSTEM HELPERS
# ==============================================================================

def have(cmd: str) -> bool:
    return shutil.which(cmd) is not None


def run(
    settings: Settings,
    cmd: Sequence[str],
    *,
    check: bool = True,
) -> tuple[int, str, str]:
    cmd_list = list(cmd)
    info(settings, "command", {"cmd": cmd_list})

    proc = subprocess.run(
        cmd_list,
        text=True,
        capture_output=True,
    )

    stdout = (proc.stdout or "").strip()
    stderr = (proc.stderr or "").strip()

    if check and proc.returncode != 0:
        error(
            settings,
            "command failed",
            {
                "cmd": cmd_list,
                "rc": proc.returncode,
                "stdout": stdout,
                "stderr": stderr,
            },
        )
        raise RuntimeError(f"Command failed: {' '.join(cmd_list)}")

    return proc.returncode, stdout, stderr


def sudo(
    settings: Settings,
    cmd: Sequence[str],
    *,
    check: bool = True,
) -> tuple[int, str, str]:
    return run(settings, ["sudo", *cmd], check=check)


def read_os_release() -> dict[str, str]:
    os_release = Path("/etc/os-release")
    data: dict[str, str] = {}

    if not os_release.exists():
        return data

    for line in os_release.read_text(encoding="utf-8", errors="ignore").splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        data[key] = value.strip().strip('"')

    return data


def dpkg_installed(pkg: str) -> bool:
    proc = subprocess.run(
        ["dpkg", "-s", pkg],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return proc.returncode == 0


# ==============================================================================
# PLATFORM VALIDATION
# ==============================================================================

def require_supported_platform(settings: Settings) -> None:
    if not (have("apt-get") and have("dpkg") and Path("/etc/os-release").exists()):
        error(
            settings,
            "Unsupported platform",
            {"reason": "apt-get/dpkg/os-release missing"},
        )
        raise SystemExit(2)

    osr = read_os_release()
    distro_id = osr.get("ID", "").lower()
    distro_like = osr.get("ID_LIKE", "").lower()
    combined = f"{distro_id} {distro_like}"

    if not any(name in combined for name in ("debian", "ubuntu")):
        error(
            settings,
            "Unsupported distribution family",
            {"ID": distro_id, "ID_LIKE": distro_like},
        )
        raise SystemExit(2)


# ==============================================================================
# APT HELPERS
# ==============================================================================

def apt_update(settings: Settings) -> None:
    if settings.skip_apt_update:
        info(settings, "apt update skipped by flag")
        return

    cmd = ["apt-get", "update"]
    if settings.yes:
        cmd.append("-y")
    sudo(settings, cmd)


def apt_install_missing(
    settings: Settings,
    packages: Iterable[str],
    *,
    best_effort: bool = False,
) -> None:
    package_list = list(packages)
    missing = [pkg for pkg in package_list if not dpkg_installed(pkg)]

    for pkg in package_list:
        if pkg in missing:
            info(settings, "package missing", {"pkg": pkg})
        else:
            info(settings, "package already installed", {"pkg": pkg})

    if not missing:
        return

    cmd = ["apt-get", "install"]
    if settings.yes:
        cmd.append("-y")
    cmd.extend(missing)

    sudo(settings, cmd, check=not best_effort)


# ==============================================================================
# PROTONVPN INSTALLATION
# ==============================================================================

def ensure_proton_repo(settings: Settings) -> None:
    if dpkg_installed(PROTON_RELEASE_PACKAGE):
        info(settings, "Proton repository bootstrap package already installed")
        return

    tmp_deb = Path("/tmp") / PROTON_RELEASE_DEB

    info(
        settings,
        "downloading Proton repository bootstrap package",
        {"url": PROTON_RELEASE_URL, "dest": str(tmp_deb)},
    )
    run(settings, ["wget", "-O", str(tmp_deb), PROTON_RELEASE_URL])

    info(
        settings,
        "installing Proton repository bootstrap package",
        {"deb": str(tmp_deb)},
    )
    sudo(settings, ["dpkg", "-i", str(tmp_deb)])

    if not settings.skip_apt_update:
        info(settings, "running apt update after Proton repository bootstrap")
        apt_update(settings)


def install_proton_app(settings: Settings) -> None:
    if dpkg_installed(PROTON_GUI_PACKAGE):
        info(
            settings,
            "ProtonVPN GUI package already installed",
            {"pkg": PROTON_GUI_PACKAGE},
        )
        return

    info(settings, "installing ProtonVPN GUI package", {"pkg": PROTON_GUI_PACKAGE})
    apt_install_missing(settings, [PROTON_GUI_PACKAGE])


# ==============================================================================
# LAUNCHER
# ==============================================================================

def ensure_local_bin_on_path(settings: Settings) -> None:
    bashrc = HOME / ".bashrc"
    export_line = 'export PATH="$HOME/.local/bin:$PATH"'

    existing = (
        bashrc.read_text(encoding="utf-8", errors="ignore")
        if bashrc.exists()
        else ""
    )

    if export_line in existing:
        info(settings, "~/.local/bin already present in ~/.bashrc")
        return

    with bashrc.open("a", encoding="utf-8") as handle:
        handle.write("\n" + export_line + "\n")

    info(settings, "appended ~/.local/bin PATH export to ~/.bashrc")


def write_launcher(settings: Settings) -> None:
    settings.launcher_path.parent.mkdir(parents=True, exist_ok=True)

    content = f"""#!/usr/bin/env bash
set -euo pipefail
exec {PROTON_APP_EXECUTABLE} "$@"
"""

    current = ""
    if settings.launcher_path.exists():
        current = settings.launcher_path.read_text(encoding="utf-8", errors="ignore")

    should_write = settings.refresh_launcher or (current != content)

    if should_write:
        settings.launcher_path.write_text(content, encoding="utf-8")
        settings.launcher_path.chmod(0o755)
        info(settings, "launcher written", {"path": str(settings.launcher_path)})
    else:
        info(settings, "launcher already correct", {"path": str(settings.launcher_path)})

    ensure_local_bin_on_path(settings)


# ==============================================================================
# VERIFICATION
# ==============================================================================

def capture_shell(settings: Settings, name: str, shell_cmd: str) -> None:
    proc = subprocess.run(
        ["bash", "-lc", shell_cmd],
        text=True,
        capture_output=True,
    )
    info(
        settings,
        name,
        {
            "rc": proc.returncode,
            "stdout": (proc.stdout or "").strip(),
            "stderr": (proc.stderr or "").strip(),
        },
    )


def snapshot_basic(settings: Settings) -> None:
    info(
        settings,
        "system snapshot",
        {
            "app": APP_NAME,
            "stage": STAGE_NAME,
            "version": VERSION,
            "script_path": str(SCRIPT_PATH),
            "script_dir": str(SCRIPT_DIR),
            "system": platform.system(),
            "kernel": platform.release(),
            "arch": platform.machine(),
            "python": sys.version.splitlines()[0],
            "log_file": str(settings.log_file),
            "launcher_path": str(settings.launcher_path),
        },
    )

    for exe in (PROTON_APP_EXECUTABLE, settings.launcher_name, "nmcli", "ip"):
        info(
            settings,
            "executable check",
            {
                "exe": exe,
                "found": have(exe),
                "path": shutil.which(exe),
            },
        )

    if have("ip"):
        capture_shell(settings, "ip_brief_addr", "ip -brief addr")

    if have("nmcli"):
        capture_shell(
            settings,
            "nmcli_active_connections",
            "nmcli -t -f NAME,TYPE,DEVICE connection show --active 2>/dev/null || true",
        )


def snapshot_deep(settings: Settings) -> None:
    if not settings.verify:
        return

    info(settings, "starting deep verification", {"mode": "read-only"})

    commands = [
        ("ip_route", "ip route"),
        ("resolvectl_status", "resolvectl status 2>/dev/null || true"),
        ("nmcli_general_status", "nmcli -t -f RUNNING,STATE general status 2>/dev/null || true"),
        ("nmcli_devices", "nmcli -t -f DEVICE,TYPE,STATE device status 2>/dev/null || true"),
        ("listening_ports", "ss -tulnp | grep LISTEN || true"),
        ("proton_interfaces", "ip -brief addr | grep -E 'proton0|ipv6leakintrf0' || true"),
    ]

    for name, shell_cmd in commands:
        capture_shell(settings, name, shell_cmd)


# ==============================================================================
# CLI
# ==============================================================================

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog=SCRIPT_PATH.name)

    parser.add_argument(
        "--yes",
        action="store_true",
        help="Pass -y to apt-get for non-interactive installation.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit structured JSON events to stdout.",
    )
    parser.add_argument(
        "--install-tools",
        action="store_true",
        help="Install safe diagnostic/network tool packages.",
    )
    parser.add_argument(
        "--verify",
        action="store_true",
        help="Emit deeper read-only network verification.",
    )
    parser.add_argument(
        "--skip-apt-update",
        action="store_true",
        help="Skip apt-get update steps.",
    )
    parser.add_argument(
        "--refresh-launcher",
        action="store_true",
        help="Rewrite the launcher even if it already exists.",
    )
    parser.add_argument(
        "--launcher-name",
        default=DEFAULT_LAUNCHER_NAME,
        help="Launcher filename to create in ~/.local/bin (default: vpn).",
    )

    return parser.parse_args()


# ==============================================================================
# MAIN
# ==============================================================================

def main() -> int:
    args = parse_args()

    launcher_name = str(args.launcher_name).strip()
    if not launcher_name or "/" in launcher_name:
        raise SystemExit("Invalid --launcher-name. Use a simple filename only.")

    launcher_path = HOME / ".local" / "bin" / launcher_name

    LOG_DIR.mkdir(parents=True, exist_ok=True)

    settings = Settings(
        yes=bool(args.yes),
        json_stdout=bool(args.json),
        install_tools=bool(args.install_tools),
        verify=bool(args.verify),
        skip_apt_update=bool(args.skip_apt_update),
        refresh_launcher=bool(args.refresh_launcher),
        launcher_name=launcher_name,
        launcher_path=launcher_path,
        log_file=LOG_FILE,
    )

    info(
        settings,
        f"{APP_NAME} — {STAGE_NAME} start",
        {
            "version": VERSION,
            "script": str(SCRIPT_PATH),
            "log": str(settings.log_file),
        },
    )

    require_supported_platform(settings)

    info(settings, "step 1/6: apt update + base dependencies")
    apt_update(settings)
    apt_install_missing(settings, BASE_PACKAGES)

    if settings.install_tools:
        info(settings, "step 2/6: install optional network tools")
        apt_install_missing(settings, NETWORK_TOOL_PACKAGES, best_effort=True)
    else:
        info(settings, "step 2/6: optional network tools skipped")

    info(settings, "step 3/6: ensure Proton repository")
    ensure_proton_repo(settings)

    info(settings, "step 4/6: install ProtonVPN application")
    install_proton_app(settings)

    info(settings, "step 5/6: write launcher")
    write_launcher(settings)

    info(settings, "step 6/6: verification snapshot")
    snapshot_basic(settings)
    snapshot_deep(settings)

    info(
        settings,
        f"{STAGE_NAME} complete",
        {
            "launcher": str(settings.launcher_path),
            "log_file": str(settings.log_file),
            "run_command": settings.launcher_name,
        },
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())


# ================================================================
# INSTRUCTIONS
# ================================================================
#
# Filename:
#   02_protonvpn_layer.py
#
# Example location:
#   /home/pc-10/zero-trust-desktop/02_protonvpn_layer.py
#
# Run:
#   python3 /home/pc-10/zero-trust-desktop/02_protonvpn_layer.py --yes
#
# Optional:
#   python3 /home/pc-10/zero-trust-desktop/02_protonvpn_layer.py --yes --install-tools
#   python3 /home/pc-10/zero-trust-desktop/02_protonvpn_layer.py --yes --install-tools --verify
#   python3 /home/pc-10/zero-trust-desktop/02_protonvpn_layer.py --yes --json
#   python3 /home/pc-10/zero-trust-desktop/02_protonvpn_layer.py --yes --refresh-launcher
#   python3 /home/pc-10/zero-trust-desktop/02_protonvpn_layer.py --yes --launcher-name vpn
#   python3 /home/pc-10/zero-trust-desktop/02_protonvpn_layer.py --yes --skip-apt-update
#
# Optional executable mode:
#   chmod +x /home/pc-10/zero-trust-desktop/02_protonvpn_layer.py
#   /home/pc-10/zero-trust-desktop/02_protonvpn_layer.py --yes
#
# Launcher after install:
#   vpn
#
# Direct Proton app command:
#   protonvpn-app
#
# Logs:
#   ~/.local/state/zero-trust-desktop/ztd_02/log/
#
# Notes:
#   - Script works regardless of current directory
#   - Paths are resolved via __file__
#   - Safe to re-run
#   - Does not auto-connect VPN
#   - Does not modify firewall rules
#   - If Proton is already installed, script will verify and standardize launcher state
#
# ================================================================
