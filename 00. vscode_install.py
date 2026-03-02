#!/usr/bin/env python3
"""
ZTD — 00. VS Code Install (UNIVERSAL DEV CONTROL LAYER)
Version: 0.0.0
Suite: Zero Trust Desktop (ZTD)
Stage: 00 (VS Code Install + Baseline Dev Controls)

PURPOSE
  Install VS Code + core developer tooling so the machine can be driven from VS Code:
    - Installs VS Code from Microsoft repo (idempotent)
    - Ensures `code` CLI available
    - Installs core extensions (Python/Jupyter/Bash/Git/YAML/Run control)
    - Applies safe baseline settings (merge + backup; does not wipe your settings)
    - Ensures ~/workspace exists

SAFETY MODEL
  - No removals.
  - Does NOT touch sudoers.
  - Does NOT disable workspace trust by default (can be enabled via flag).
  - Does NOT install Docker tooling by default (optional flag).
  - Settings are merged and backed up each run.

USAGE
  python3 "00. vscode_install.py" --yes
  python3 "00. vscode_install.py" --yes --with-docker
  python3 "00. vscode_install.py" --yes --disable-workspace-trust
  python3 "00. vscode_install.py" --yes --extension-dev   # node/npm + yo/vsce

FLAGS
  --yes                    Non-interactive apt
  --with-docker            Install Docker-related extensions (extensions only)
  --extension-dev          Install nodejs/npm + yo/vsce (extension dev kit)
  --disable-workspace-trust  Disable VS Code workspace trust (risky)
  --json                   Emit JSON to stdout (logs always JSONL)
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
STAGE_NAME = "00. VS Code Install"
STAGE_ID = "ztd_00_vscode_install"
VERSION = "0.0.0"

HOME = Path.home()
STATE_DIR = HOME / ".local" / "state" / "zero-trust-desktop" / "ztd_00"
LOG_DIR = STATE_DIR / "log"
RUN_ID = datetime.now().strftime("%Y%m%d_%H%M%S")
LOG_FILE = LOG_DIR / f"{STAGE_ID}_{RUN_ID}.jsonl"

VSCODE_USER_DIR = HOME / ".config" / "Code" / "User"
VSCODE_SETTINGS = VSCODE_USER_DIR / "settings.json"
WORKSPACE_DIR = HOME / "workspace"

# Microsoft VS Code repo bits (Ubuntu/Debian)
MS_KEYRING = Path("/usr/share/keyrings/microsoft.gpg")
VSCODE_LIST = Path("/etc/apt/sources.list.d/vscode.list")
MS_KEY_URL = "https://packages.microsoft.com/keys/microsoft.asc"

# minimal packages to install VS Code repo + key
PKGS_REPO = ["ca-certificates", "wget", "gpg", "apt-transport-https"]

# optional extension dev kit
PKGS_EXT_DEV = ["nodejs", "npm"]
NPM_GLOBAL = ["yo", "generator-code", "vsce"]

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
    # Execution / Run control
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


@dataclass
class Settings:
    yes: bool
    json_stdout: bool
    with_docker: bool
    extension_dev: bool
    disable_workspace_trust: bool
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


def ensure_vscode_repo(s: Settings) -> None:
    info(s, "Ensuring VS Code Microsoft repo is configured")

    # Keyring
    if MS_KEYRING.exists():
        info(s, "Microsoft keyring exists", {"path": str(MS_KEYRING)})
    else:
        info(s, "Installing Microsoft GPG keyring")
        sudo(s, ["bash", "-lc", f"wget -qO- {MS_KEY_URL} | gpg --dearmor | tee {MS_KEYRING} >/dev/null"], check=True)
        sudo(s, ["chmod", "0644", str(MS_KEYRING)], check=False)

    # Source list
    line = f"deb [arch=amd64 signed-by={MS_KEYRING}] https://packages.microsoft.com/repos/code stable main"
    current = VSCODE_LIST.read_text(encoding="utf-8", errors="ignore") if VSCODE_LIST.exists() else ""
    if line in current:
        info(s, "VS Code apt source already present", {"path": str(VSCODE_LIST)})
    else:
        info(s, "Writing VS Code apt source", {"path": str(VSCODE_LIST)})
        sudo(s, ["bash", "-lc", f"echo '{line}' | tee {VSCODE_LIST} >/dev/null"], check=True)


def ensure_vscode_installed(s: Settings) -> None:
    if have("code"):
        info(s, "VS Code already installed", {"code": shutil.which("code")})
        return

    require_debian_like(s)
    info(s, "Installing VS Code package")

    apt_update(s)
    apt_install_missing(s, PKGS_REPO)

    ensure_vscode_repo(s)
    apt_update(s)
    sudo(s, ["apt-get", "install"] + (["-y"] if s.yes else []) + ["code"], check=True)

    if not have("code"):
        error(s, "VS Code install finished but 'code' not found on PATH")
        raise SystemExit(2)

    info(s, "VS Code installed", {"code": shutil.which("code")})


def code_list_extensions() -> List[str]:
    p = subprocess.run(["code", "--list-extensions"], text=True, capture_output=True)
    if p.returncode != 0:
        return []
    return [ln.strip() for ln in (p.stdout or "").splitlines() if ln.strip()]


def install_extensions(s: Settings) -> None:
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

    if s.disable_workspace_trust:
        desired["security.workspace.trust.enabled"] = False

    merged = dict(existing)
    merged.update(desired)

    info(s, "Writing merged VS Code settings", {"path": str(VSCODE_SETTINGS)})
    save_json_pretty(VSCODE_SETTINGS, merged)


def setup_workspace(s: Settings) -> None:
    info(s, "Ensuring ~/workspace exists")
    WORKSPACE_DIR.mkdir(parents=True, exist_ok=True)


def install_extension_dev_tools(s: Settings) -> None:
    if not s.extension_dev:
        info(s, "Extension dev tooling skipped")
        return
    require_debian_like(s)
    info(s, "Installing extension dev tooling (nodejs/npm + yo/vsce)")
    apt_update(s)
    apt_install_missing(s, PKGS_EXT_DEV)

    for pkg in NPM_GLOBAL:
        info(s, f"npm install -g {pkg}")
        sudo(s, ["npm", "install", "-g", pkg], check=False)


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
    ap = argparse.ArgumentParser(prog="00. vscode_install.py")
    ap.add_argument("--yes", action="store_true", help="Non-interactive apt (-y)")
    ap.add_argument("--json", action="store_true", help="Emit JSON to stdout (log file always JSONL)")
    ap.add_argument("--with-docker", action="store_true", help="Install Docker-related extensions (extensions only)")
    ap.add_argument("--extension-dev", action="store_true", help="Install extension dev tooling (nodejs/npm + yo/vsce)")
    ap.add_argument("--disable-workspace-trust", action="store_true", help="Disable VS Code workspace trust (risky)")
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
        log_file=LOG_FILE,
    )

    require_debian_like(s)
    info(s, f"{APP_NAME} — {STAGE_NAME} start", {"version": VERSION, "log": str(s.log_file)})

    ensure_vscode_installed(s)
    install_extensions(s)
    merge_settings(s)
    setup_workspace(s)
    install_extension_dev_tools(s)
    verify(s)

    info(s, f"{STAGE_NAME} complete", {"log": str(s.log_file)})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
