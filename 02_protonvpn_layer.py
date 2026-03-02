#!/usr/bin/env python3
"""
ZTD — 2. ProtonVPN Layer (INSTALL + VERIFY)
Version: 0.2.0
Suite: Zero Trust Desktop (ZTD)
Stage: 2 (Network / VPN)

PURPOSE
  Install ProtonVPN (official repo) and a minimal set of network diagnostics tools,
  without touching firewall rules or adding external kill-switch logic.

DESIGN
  - Idempotent: safe to re-run.
  - Debian/Ubuntu only.
  - No removals. No rule-writing. No auto-connect.
  - Proton's built-in kill switch is respected (we do NOT add another).

WHAT IT DOES
  - apt-get update
  - installs prerequisites if missing
  - installs ProtonVPN repo key + apt source (keyring-safe)
  - installs ProtonVPN GUI app (tries proton-vpn-gnome-desktop first)
  - creates a small launcher command in ~/.local/bin/protonvpn-app
  - prints verification / network snapshot

USAGE
  python3 02_protonvpn_layer.py --yes
  python3 02_protonvpn_layer.py --yes --install-tools
  python3 02_protonvpn_layer.py --yes --install-tools --verify

FLAGS
  --yes            Non-interactive apt
  --install-tools  Install helpful network tools (safe)
  --verify         Print deeper network status (interfaces/routes/dns)

NOTES
  - If you are not on GNOME, the GUI may still run, but desktop integration varies.
  - This script does not attempt to log into Proton or connect automatically.
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
STAGE_NAME = "2. ProtonVPN Layer"
STAGE_ID = "ztd_02_protonvpn_layer"
VERSION = "0.2.0"

HOME = Path.home()
STATE_DIR = HOME / ".local" / "state" / "zero-trust-desktop" / "ztd_02"
LOG_DIR = STATE_DIR / "log"
RUN_ID = datetime.now().strftime("%Y%m%d_%H%M%S")
LOG_FILE = LOG_DIR / f"{STAGE_ID}_{RUN_ID}.jsonl"

# Proton repo details
PROTON_LIST = Path("/etc/apt/sources.list.d/protonvpn.list")
PROTON_KEYRING = Path("/usr/share/keyrings/protonvpn-archive-keyring.gpg")
PROTON_REPO_LINE = "deb [signed-by=/usr/share/keyrings/protonvpn-archive-keyring.gpg] https://repo.protonvpn.com/debian stable main"
PROTON_KEY_URL = "https://repo.protonvpn.com/debian/public_key.asc"

# Base deps (for repo + install)
PKGS_BASE = [
    "ca-certificates",
    "wget",
    "curl",
    "gnupg",
    "apt-transport-https",
]

# Useful network tooling (safe diagnostics)
PKGS_TOOLS = [
    "iproute2",
    "net-tools",
    "network-manager",
    "dnsutils",
    "jq",
    "curl",
]

# Proton packages to attempt in order
PROTON_PKG_PRIMARY = "proton-vpn-gnome-desktop"
PROTON_PKG_FALLBACK = "protonvpn-app"


@dataclass
class Settings:
    yes: bool
    json_stdout: bool
    install_tools: bool
    verify: bool
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


def ensure_proton_repo(s: Settings) -> None:
    # Keyring
    if PROTON_KEYRING.exists():
        info(s, f"Proton keyring exists: {PROTON_KEYRING}")
    else:
        info(s, "Installing Proton repo keyring (keyring-safe)")
        # wget -> gpg dearmor -> keyring
        # shell used only to preserve pipe; still logged.
        sudo(s, ["bash", "-lc", f"wget -qO- {PROTON_KEY_URL} | gpg --dearmor | tee {PROTON_KEYRING} >/dev/null"], check=True)
        sudo(s, ["chmod", "0644", str(PROTON_KEYRING)], check=False)

    # Source list line
    current = ""
    if PROTON_LIST.exists():
        current = PROTON_LIST.read_text(encoding="utf-8", errors="ignore")

    if PROTON_REPO_LINE in current:
        info(s, f"Proton apt source already present: {PROTON_LIST}")
    else:
        info(s, f"Writing Proton apt source: {PROTON_LIST}")
        sudo(s, ["bash", "-lc", f"echo '{PROTON_REPO_LINE}' | tee {PROTON_LIST} >/dev/null"], check=True)


def install_proton_app(s: Settings) -> str:
    # Try GNOME package first
    if dpkg_installed(PROTON_PKG_PRIMARY) or dpkg_installed(PROTON_PKG_FALLBACK):
        info(s, "ProtonVPN already installed")
        return "protonvpn-app"

    info(s, f"Attempt install: {PROTON_PKG_PRIMARY}")
    try:
        sudo(s, ["apt-get", "install", "-y" if s.yes else "", PROTON_PKG_PRIMARY], check=True)
        return "protonvpn-app"
    except Exception:
        warn(s, f"Primary package failed, falling back to: {PROTON_PKG_FALLBACK}")

    sudo(s, ["apt-get", "install", "-y" if s.yes else "", PROTON_PKG_FALLBACK], check=False)
    return "protonvpn-app"


def write_launcher(s: Settings, cmd: str) -> None:
    # standardize on ~/.local/bin (already used by Stage 0)
    bin_dir = HOME / ".local" / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)
    launcher = bin_dir / "vpn"
    content = f"""#!/usr/bin/env bash
set -e
exec {cmd} "$@"
"""
    if launcher.exists():
        existing = launcher.read_text(encoding="utf-8", errors="ignore")
        if existing == content:
            info(s, f"Launcher already correct: {launcher}")
            return
        info(s, f"Updating launcher: {launcher}")
    else:
        info(s, f"Creating launcher: {launcher}")

    launcher.write_text(content, encoding="utf-8")
    launcher.chmod(0o755)

    # Ensure PATH in ~/.bashrc for ~/.local/bin (Stage 0 should do this, but keep idempotent)
    bashrc = HOME / ".bashrc"
    line = 'export PATH="$HOME/.local/bin:$PATH"'
    txt = bashrc.read_text(encoding="utf-8", errors="ignore") if bashrc.exists() else ""
    if line not in txt:
        info(s, "Appending ~/.local/bin PATH line to ~/.bashrc")
        with bashrc.open("a", encoding="utf-8") as f:
            f.write("\n" + line + "\n")
    else:
        info(s, "~/.local/bin already present in ~/.bashrc")


def snapshot_basic(s: Settings) -> None:
    info(s, "Verification snapshot", {
        "app": APP_ID,
        "stage": STAGE_ID,
        "version": VERSION,
        "system": f"{platform.system()} {platform.release()}",
        "arch": platform.machine(),
        "python": sys.version.splitlines()[0],
        "log": str(s.log_file),
    })

    # proton app presence
    for exe in ("protonvpn-app", "vpn"):
        if have(exe):
            info(s, f"{exe}: found ({shutil.which(exe)})")
        else:
            warn(s, f"{exe}: not found")

    # NM
    if have("nmcli"):
        p = subprocess.run(["nmcli", "-v"], text=True, capture_output=True)
        out = (p.stdout or p.stderr).strip().splitlines()
        if out:
            info(s, f"nmcli: {out[0]}")
    else:
        warn(s, "nmcli not found")

    # Quick IP
    if have("ip"):
        p = subprocess.run(["bash", "-lc", "ip -brief addr"], text=True, capture_output=True)
        out = (p.stdout or p.stderr).strip()
        if out:
            info(s, "ip addr (brief):")
            print(out)


def snapshot_deep(s: Settings) -> None:
    if not s.verify:
        return
    info(s, "Deep network verify (read-only)")

    cmds = [
        ("routes", "ip route"),
        ("dns_resolve_status", "resolvectl status 2>/dev/null || true"),
        ("nm_overview", "nmcli -t -f RUNNING,STATE general status 2>/dev/null || true"),
        ("active_connections", "nmcli -t -f NAME,TYPE,DEVICE connection show --active 2>/dev/null || true"),
        ("listening_ports", "ss -tulnp | grep LISTEN || true"),
    ]
    for name, cmd in cmds:
        info(s, f"[{name}]")
        p = subprocess.run(["bash", "-lc", cmd], text=True, capture_output=True)
        out = (p.stdout or p.stderr).strip()
        if out:
            print(out)


def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(prog="02_protonvpn_layer.py")
    ap.add_argument("--yes", action="store_true", help="Non-interactive apt (-y)")
    ap.add_argument("--json", action="store_true", help="Emit JSON to stdout (log file always JSONL)")
    ap.add_argument("--install-tools", action="store_true", help="Install helpful network tools")
    ap.add_argument("--verify", action="store_true", help="Print deeper network snapshot (read-only)")
    return ap.parse_args()


def main() -> int:
    args = parse_args()
    LOG_DIR.mkdir(parents=True, exist_ok=True)

    s = Settings(
        yes=bool(args.yes),
        json_stdout=bool(args.json),
        install_tools=bool(args.install_tools),
        verify=bool(args.verify),
        log_file=LOG_FILE,
    )

    require_debian_like(s)
    info(s, f"{APP_NAME} — {STAGE_NAME} start", {"version": VERSION, "log": str(s.log_file)})

    info(s, "[1] apt update + base deps")
    apt_update(s)
    apt_install_missing(s, PKGS_BASE)

    if s.install_tools:
        info(s, "[2] network tools (safe)")
        apt_install_missing(s, PKGS_TOOLS, best_effort=True)

    info(s, "[3] proton repo")
    ensure_proton_repo(s)

    info(s, "[4] apt update (post-repo)")
    apt_update(s)

    info(s, "[5] install proton app")
    vpn_cmd = install_proton_app(s)

    info(s, "[6] launcher")
    write_launcher(s, vpn_cmd)

    snapshot_basic(s)
    snapshot_deep(s)

    info(s, f"{STAGE_NAME} complete", {"log": str(s.log_file), "run": "vpn"})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
