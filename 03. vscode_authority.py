#!/usr/bin/env python3
"""
ZTD — 3. VS Code Authority (DEV ENV SETUP)
Version: 0.3.0
Suite: Zero Trust Desktop (ZTD)
Stage: 3 (Dev Environment)

PURPOSE
  Configure a Python-first VS Code development environment:
    - Install a curated extension set (idempotent)
    - Apply safe settings (merge + backup, not destructive)
    - Optional: Docker extensions
    - Optional: Extension dev tooling (nodejs/npm + yo/vsce)
    - Optional (dangerous): disable workspace trust
    - Optional (very dangerous): passwordless sudo (NOPASSWD) for current user

DEFAULTS (SAFE)
  - Installs core extensions (Python/Jupyter/Bash/Git/YAML)
  - Merges settings into ~/.config/Code/User/settings.json
  - Does NOT change sudoers
  - Does NOT disable workspace trust
  - Does NOT install docker extensions unless requested

USAGE
  python3 03_vscode_authority.py --yes
  python3 03_vscode_authority.py --yes --with-docker
  python3 03_vscode_authority.py --yes --extension-dev
  python3 03_vscode_authority.py --yes --disable-workspace-trust
  python3 03_vscode_authority.py --yes --sudo-nopasswd  # risky

NOTES
  - Requires VS Code 'code' CLI present. If missing, run Stage 0 first (or install VS Code).
"""

from __future__ import annotations

import argparse
import json
import os
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
STAGE_NAME = "3. VS Code Authority"
STAGE_ID = "ztd_03_vscode_authority"
VERSION = "0.3.0"

HOME = Path.home()
STATE_DIR = HOME / ".local" / "state" / "zero-trust-desktop" / "ztd_03"
LOG_DIR = STATE_DIR / "log"
RUN_ID = datetime.now().strftime("%Y%m%d_%H%M%S")
LOG_FILE = LOG_DIR / f"{STAGE_ID}_{RUN_ID}.jsonl"

VSCODE_USER_DIR = HOME / ".config" / "Code" / "User"
VSCODE_SETTINGS = VSCODE_USER_DIR / "settings.json"
WORKSPACE_DIR = HOME / "workspace"

EXT_CORE = [
    # Python core
    "ms-python.python",
    "ms-python.vscode-pylance",
    "ms-python.debugpy",
    "ms-python.vscode-python-envs",
    # Jupyter
    "ms-toolsai.jupyter",
    "ms-toolsai.jupyter-keymap",
    "ms-toolsai.jupyter-renderers",
    "ms-toolsai.vscode-jupyter-cell-tags",
    "ms-toolsai.vscode-jupyter-slideshow",
    # Bash / Shell
    "mads-hartmann.bash-ide-vscode",
    "timonwong.shellcheck",
    "foxundermoon.shell-format",
    # Run control
    "usernamehw.execute",
    "formulahendry.code-runner",
    # Git / YAML / Hex
    "eamodio.gitlens",
    "redhat.vscode-yaml",
    "ms-vscode.hexeditor",
]

EXT_DOCKER = [
    "ms-azuretools.vscode-docker",
    "ms-azuretools.vscode-containers",
]

APT_EXT_DEV = ["nodejs", "npm"]  # for yo/vsce
NPM_GLOBAL = ["yo", "generator-code", "vsce"]


@dataclass
class Settings:
    yes: bool
    json_stdout: bool
    with_docker: bool
    extension_dev: bool
    disable_workspace_trust: bool
    sudo_nopasswd: bool
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
    sudo(s, args, check=True)


def require_code_cli(s: Settings) -> None:
    if have("code"):
        info(s, "VS Code CLI found", {"path": shutil.which("code")})
        return
    error(s, "VS Code 'code' CLI not found. Run Stage 0 (Python provision) that installs VS Code.")
    raise SystemExit(2)


def code_list_extensions() -> List[str]:
    p = subprocess.run(["code", "--list-extensions"], text=True, capture_output=True)
    if p.returncode != 0:
        return []
    return [ln.strip() for ln in (p.stdout or "").splitlines() if ln.strip()]


def install_extensions(s: Settings) -> None:
    require_code_cli(s)

    wanted = list(EXT_CORE)
    if s.with_docker:
        wanted += EXT_DOCKER

    installed = set(code_list_extensions())
    info(s, "Installing extensions (idempotent)", {"count": len(wanted)})

    for ext in wanted:
        if ext in installed:
            info(s, f"Extension already installed: {ext}")
            continue
        info(s, f"Installing extension: {ext}")
        # do not hard-fail on extension install issues
        subprocess.run(["code", "--install-extension", ext], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def load_json(path: Path) -> Dict:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="ignore") or "{}")
    except Exception:
        return {}


def save_json_pretty(path: Path, data: Dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=4, sort_keys=True) + "\n", encoding="utf-8")


def merge_settings(s: Settings) -> None:
    VSCODE_USER_DIR.mkdir(parents=True, exist_ok=True)

    existing = load_json(VSCODE_SETTINGS)
    if VSCODE_SETTINGS.exists():
        backup = VSCODE_SETTINGS.with_suffix(f".bak_{RUN_ID}.json")
        info(s, "Backing up settings.json", {"backup": str(backup)})
        backup.write_text(VSCODE_SETTINGS.read_text(encoding="utf-8", errors="ignore"), encoding="utf-8")

    desired: Dict[str, object] = {
        "python.defaultInterpreterPath": "/usr/bin/python3",
        "python.terminal.activateEnvironment": True,

        "terminal.integrated.defaultProfile.linux": "bash",
        "terminal.integrated.shellIntegration.enabled": True,
        "terminal.integrated.inheritEnv": True,

        "files.autoSave": "afterDelay",
        "editor.formatOnSave": True,

        "code-runner.runInTerminal": True,
        "code-runner.saveFileBeforeRun": True,

        "shellformat.flag": "-i 4",

        "git.autofetch": True,
    }

    # workspace trust is security relevant: OFF only if explicitly requested
    if s.disable_workspace_trust:
        desired["security.workspace.trust.enabled"] = False
    else:
        # leave user setting alone if already set; otherwise allow VS Code defaults
        pass

    merged = dict(existing)
    merged.update(desired)

    info(s, "Writing merged VS Code settings", {"path": str(VSCODE_SETTINGS)})
    save_json_pretty(VSCODE_SETTINGS, merged)


def install_extension_dev_tools(s: Settings) -> None:
    if not s.extension_dev:
        info(s, "Extension dev tooling skipped")
        return
    require_debian_like(s)
    info(s, "Installing extension dev tooling (nodejs/npm + yo/vsce)")
    apt_update(s)
    apt_install_missing(s, APT_EXT_DEV)

    # npm global installs
    for pkg in NPM_GLOBAL:
        info(s, f"npm install -g {pkg}")
        sudo(s, ["npm", "install", "-g", pkg], check=False)


def setup_workspace(s: Settings) -> None:
    info(s, "Ensuring ~/workspace exists")
    WORKSPACE_DIR.mkdir(parents=True, exist_ok=True)


def set_sudo_nopasswd(s: Settings) -> None:
    if not s.sudo_nopasswd:
        info(s, "NOPASSWD sudo skipped (safe default)")
        return

    user = os.environ.get("USER") or ""
    if not user:
        warn(s, "USER env missing; cannot set sudoers")
        return

    # Safer than appending to /etc/sudoers: drop-in file
    dropin = Path(f"/etc/sudoers.d/{user}-nopasswd")
    line = f"{user} ALL=(ALL) NOPASSWD:ALL\n"
    info(s, "Enabling NOPASSWD sudo (DANGEROUS)", {"dropin": str(dropin)})

    # write via tee
    sudo(s, ["bash", "-lc", f"echo '{line.strip()}' | tee {dropin} >/dev/null"], check=True)
    sudo(s, ["chmod", "0440", str(dropin)], check=False)
    # validate sudoers syntax
    sudo(s, ["visudo", "-cf", "/etc/sudoers"], check=False)


def verify(s: Settings) -> None:
    info(s, "Verification", {
        "app": APP_ID,
        "stage": STAGE_ID,
        "version": VERSION,
        "system": f"{platform.system()} {platform.release()}",
        "arch": platform.machine(),
        "python": sys.version.splitlines()[0],
        "log": str(s.log_file),
    })

    if have("code"):
        p = subprocess.run(["code", "--version"], text=True, capture_output=True)
        out = (p.stdout or p.stderr).strip().splitlines()
        if out:
            info(s, f"code: {out[0]}")
    else:
        warn(s, "code not found")

    info(s, f"settings.json exists: {VSCODE_SETTINGS.exists()}")
    info(s, f"workspace exists: {WORKSPACE_DIR.exists()}")


def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(prog="03_vscode_authority.py")
    ap.add_argument("--yes", action="store_true", help="Non-interactive apt (-y)")
    ap.add_argument("--json", action="store_true", help="Emit JSON to stdout (log file always JSONL)")
    ap.add_argument("--with-docker", action="store_true", help="Install Docker-related extensions")
    ap.add_argument("--extension-dev", action="store_true", help="Install extension dev tooling (nodejs/npm + yo/vsce)")
    ap.add_argument("--disable-workspace-trust", action="store_true", help="Disable VS Code workspace trust (risky)")
    ap.add_argument("--sudo-nopasswd", action="store_true", help="Enable passwordless sudo for current user (VERY risky)")
    return ap.parse_args()


def main() -> int:
    args = parse_args()
    LOG_DIR.mkdir(parents=True, exist_ok=True)

    s = Settings(
        yes=bool(args.yes),
        json_stdout=bool(args.json),
        with_docker=bool(args.with_docker),
        extension_dev=bool(args.extension_dev),
        disable_workspace_trust=bool(args.disable_workspace_trust),
        sudo_nopasswd=bool(args.sudo_nopasswd),
        log_file=LOG_FILE,
    )

    info(s, f"{APP_NAME} — {STAGE_NAME} start", {"version": VERSION, "log": str(s.log_file)})

    require_code_cli(s)
    install_extensions(s)
    merge_settings(s)
    setup_workspace(s)
    install_extension_dev_tools(s)
    set_sudo_nopasswd(s)
    verify(s)

    info(s, f"{STAGE_NAME} complete", {"log": str(s.log_file)})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
