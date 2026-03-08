#!/usr/bin/env python3
"""
README
======

Filename:
    ztd_10_defense_observe.py

Project:
    Zero Trust Desktop (ZTD)

Stage:
    10 — Defense + Observation Toolkit

Purpose
-------

Stage 10 installs baseline defense tooling plus observation / visibility
tooling, captures auditable evidence snapshots, optionally runs heavy
security checks, optionally performs safe cleanup, and can optionally
install Wireshark GUI and enable capture permissions for the current user.

This script is designed to be:

    • Safe by default
    • Auditable
    • Idempotent
    • Location independent
    • Rebuild friendly
    • Best-effort where safe

Default Behavior
----------------

When run with no opt-in flags:

    1. Validates Debian/Ubuntu platform
    2. Validates sudo access
    3. Runs apt update
    4. Installs missing defense packages
    5. Installs missing observation packages
    6. Captures evidence snapshots
    7. Writes JSONL audit logs

It does NOT:

    • Run heavy scans
    • Delete files
    • Change capture permissions
    • Initialize AIDE
    • Install Wireshark GUI
    • Bundle evidence automatically

Explicit Opt-In Operations
--------------------------

--run-clamav-scan <path>
    Run recursive ClamAV scan on a path

--run-rkhunter
    Run rkhunter check

--run-chkrootkit
    Run chkrootkit check

--run-debsums
    Run debsums package integrity check

--init-aide
    Initialize AIDE database

--clean-safe
    Perform bounded safe cleanup:
        • apt clean/autoclean
        • selected user cache cleanup
        • bounded journald vacuum

--bundle-evidence
    Create tar.gz bundle containing snapshots + log

--install-wireshark-gui
    Install Wireshark GUI package explicitly

--enable-wireshark-capture
    Add current user to the wireshark group
    Logout/login required for group membership to take effect

Installed Defense Packages
--------------------------

clamav
rkhunter
chkrootkit
debsums
aide

Installed Observation Packages
------------------------------

nmap
tshark
tcpdump
lsof
strace
psmisc
iftop
nethogs
mtr-tiny
iperf3
dnsutils
whois
net-tools
jq

Optional GUI Package
--------------------

wireshark

Output Locations
----------------

Logs:
    ~/.local/state/zero-trust-desktop/ztd_10/log/

Snapshots:
    ~/.local/state/zero-trust-desktop/ztd_10/snapshots/<timestamp>/

Evidence Bundle:
    ~/.local/state/zero-trust-desktop/ztd_10/snapshots/ztd_10_evidence_<timestamp>.tar.gz

Supported Platforms
-------------------

Debian / Ubuntu / Debian-derived Linux systems
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import platform
import random
import shutil
import subprocess
import sys
import tarfile
import time
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple


# ---------------------------
# Ghost Protocol 00 (Topper)
# ---------------------------

def ghost_protocol(countdown: int = 5, pages: int = 5, cols: int = 64) -> None:
    green = "\033[0;32m"
    reset = "\033[0m"

    if not sys.stdout.isatty():
        return

    countdown = max(0, int(countdown))
    pages = max(1, int(pages))
    cols = max(1, int(cols))

    rows_per_page = 12
    subprocess.run(["clear"], check=False)

    print(f"{green}Initializing Ghost Protocol... It will begin in {countdown} seconds.{reset}")
    time.sleep(0.4)

    for i in range(countdown, 0, -1):
        print(f"{green}{i}...{reset}")
        time.sleep(1)

    print(f"{green}Initializing Ghost Protocol...{reset}")
    time.sleep(0.2)

    for page in range(1, pages + 1):
        print(f"{green}--- PAGE {page}/{pages} ---{reset}")
        for _ in range(rows_per_page):
            line = "".join(random.choice("01") for _ in range(cols))
            print(f"{green}{line}{reset}")
        if page != pages:
            print()
            time.sleep(0.08)

    print()


APP_NAME = "Zero Trust Desktop"
APP_ID = "ztd"
STAGE_NAME = "10. DEFENSE + OBSERVATION TOOLKIT"
STAGE_ID = "ztd_10_defense_observe"
VERSION = "2.0.0"

HOME = Path.home()
RUN_ID = datetime.now().strftime("%Y%m%d_%H%M%S")
STATE_DIR = HOME / ".local" / "state" / "zero-trust-desktop" / "ztd_10"
LOG_DIR = STATE_DIR / "log"
SNAP_DIR = STATE_DIR / "snapshots"
LOG_FILE = LOG_DIR / f"{STAGE_ID}_{RUN_ID}.jsonl"
SNAPSHOT_ROOT = SNAP_DIR / RUN_ID

PKGS_DEFENSE = [
    "clamav",
    "rkhunter",
    "chkrootkit",
    "debsums",
    "aide",
]

PKGS_OBSERVE = [
    "nmap",
    "tshark",
    "tcpdump",
    "lsof",
    "strace",
    "psmisc",
    "iftop",
    "nethogs",
    "mtr-tiny",
    "iperf3",
    "dnsutils",
    "whois",
    "net-tools",
    "jq",
]

PKGS_OPTIONAL_WIRESHARK = [
    "wireshark",
]


@dataclass
class Settings:
    yes: bool
    json_stdout: bool
    no_banner: bool

    run_clamav_path: Optional[str]
    run_rkhunter_check: bool
    run_chkrootkit_check: bool
    run_debsums_check: bool
    init_aide_db: bool

    clean_safe_mode: bool
    bundle_evidence_mode: bool
    install_wireshark_gui_mode: bool
    enable_wireshark_capture_mode: bool

    log_file: Path
    snapshot_root: Path
    run_id: str


@dataclass
class Event:
    ts: str
    level: str
    msg: str
    data: Optional[dict] = None


class AptSourceError(RuntimeError):
    pass


class PrivilegeError(RuntimeError):
    pass


def now_ts() -> str:
    return datetime.now().isoformat(timespec="seconds")


def have(cmd: str) -> bool:
    return shutil.which(cmd) is not None


def apt_env() -> Dict[str, str]:
    env = os.environ.copy()
    env["DEBIAN_FRONTEND"] = "noninteractive"
    env["NEEDRESTART_MODE"] = "a"
    env["APT_LISTCHANGES_FRONTEND"] = "none"
    return env


def safe_append_text(path: Path, text: str) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as f:
            f.write(text)
    except Exception:
        try:
            print(text, file=sys.stderr, end="")
        except Exception:
            pass


def emit(s: Settings, ev: Event) -> None:
    line = json.dumps(asdict(ev), ensure_ascii=False)

    try:
        if s.json_stdout:
            print(line)
        else:
            print(f"[{ev.ts}] {ev.level}: {ev.msg}")
            if ev.data:
                print(json.dumps(ev.data, ensure_ascii=False, indent=2))
    except Exception:
        pass

    safe_append_text(s.log_file, line + "\n")


def info(s: Settings, msg: str, data: Optional[dict] = None) -> None:
    emit(s, Event(ts=now_ts(), level="INFO", msg=msg, data=data))


def warn(s: Settings, msg: str, data: Optional[dict] = None) -> None:
    emit(s, Event(ts=now_ts(), level="WARN", msg=msg, data=data))


def error(s: Settings, msg: str, data: Optional[dict] = None) -> None:
    emit(s, Event(ts=now_ts(), level="ERROR", msg=msg, data=data))


def apt_cmd_base() -> List[str]:
    return [
        "apt-get",
        "-o", "Dpkg::Use-Pty=0",
        "-o", "APT::Color=0",
    ]


def read_os_release() -> Dict[str, str]:
    data: Dict[str, str] = {}
    path = Path("/etc/os-release")
    if not path.exists():
        return data

    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        if "=" not in line or line.strip().startswith("#"):
            continue
        k, v = line.split("=", 1)
        data[k.strip()] = v.strip().strip('"')
    return data


def run(
    s: Settings,
    cmd: List[str],
    check: bool = True,
    timeout: Optional[int] = None,
    env: Optional[Dict[str, str]] = None,
) -> Tuple[int, str, str]:
    info(s, "$ " + " ".join(cmd))

    p = subprocess.run(
        cmd,
        text=True,
        capture_output=True,
        timeout=timeout,
        env=env,
    )

    stdout = (p.stdout or "").strip()
    stderr = (p.stderr or "").strip()

    if stdout:
        info(s, "stdout", {"cmd": cmd, "stdout": stdout[:12000]})

    if stderr:
        info(s, "stderr", {"cmd": cmd, "stderr": stderr[:12000]})

    if check and p.returncode != 0:
        raise RuntimeError(
            json.dumps(
                {
                    "cmd": cmd,
                    "rc": p.returncode,
                    "stdout": stdout[:4000],
                    "stderr": stderr[:4000],
                },
                ensure_ascii=False,
            )
        )

    return p.returncode, p.stdout or "", p.stderr or ""


def sudo(
    s: Settings,
    cmd: List[str],
    check: bool = True,
    timeout: Optional[int] = None,
    use_noninteractive_env: bool = False,
) -> Tuple[int, str, str]:
    sudo_cmd = ["sudo"]

    if use_noninteractive_env:
        env_map = apt_env()
        sudo_cmd.extend([
            "env",
            f"DEBIAN_FRONTEND={env_map['DEBIAN_FRONTEND']}",
            f"NEEDRESTART_MODE={env_map['NEEDRESTART_MODE']}",
            f"APT_LISTCHANGES_FRONTEND={env_map['APT_LISTCHANGES_FRONTEND']}",
        ])

    sudo_cmd.extend(cmd)
    return run(s, sudo_cmd, check=check, timeout=timeout, env=None)


def require_debian_like(s: Settings) -> None:
    if not Path("/etc/os-release").exists():
        error(s, "Missing /etc/os-release")
        raise SystemExit(2)

    if not have("apt-get") or not have("dpkg"):
        error(s, "Unsupported platform. Debian/Ubuntu with apt-get/dpkg required.")
        raise SystemExit(2)

    osr = read_os_release()
    distro_tokens = " ".join([
        osr.get("ID", "").lower(),
        osr.get("ID_LIKE", "").lower(),
        osr.get("NAME", "").lower(),
        osr.get("PRETTY_NAME", "").lower(),
    ])

    if not any(token in distro_tokens for token in ("debian", "ubuntu")):
        error(s, "Unsupported Linux distribution for this stage", {"detected": osr})
        raise SystemExit(2)


def require_sudo_ready(s: Settings) -> None:
    if os.geteuid() == 0:
        info(s, "Running as root")
        return

    if not have("sudo"):
        error(s, "sudo is required but not found")
        raise PrivilegeError("sudo not found")

    info(s, "Validating sudo access")
    p = subprocess.run(["sudo", "-v"], text=True)
    if p.returncode != 0:
        error(s, "sudo authentication failed or was denied")
        raise PrivilegeError("sudo authentication failed")


def dpkg_installed(pkg: str) -> bool:
    p = subprocess.run(
        ["dpkg", "-s", pkg],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return p.returncode == 0


def write_snapshot(name: str, content: str, root: Path) -> None:
    root.mkdir(parents=True, exist_ok=True)
    (root / name).write_text(content, encoding="utf-8", errors="ignore")


def cap(cmd: List[str], timeout: Optional[int] = None) -> str:
    try:
        p = subprocess.run(
            cmd,
            text=True,
            capture_output=True,
            timeout=timeout,
        )
        return (p.stdout or p.stderr or "").strip()
    except Exception as exc:
        return f"[capture failed] {type(exc).__name__}: {exc}"


def run_and_write_output(
    s: Settings,
    name: str,
    cmd: List[str],
    timeout: Optional[int] = None,
    append_rc: bool = True,
) -> int:
    s.snapshot_root.mkdir(parents=True, exist_ok=True)
    out_path = s.snapshot_root / name

    info(s, "Streaming command output to snapshot", {"name": name, "cmd": cmd})

    try:
        with out_path.open("w", encoding="utf-8", errors="ignore") as f:
            f.write("$ " + " ".join(cmd) + "\n\n")
            f.flush()

            p = subprocess.run(
                cmd,
                text=True,
                stdout=f,
                stderr=subprocess.STDOUT,
                timeout=timeout,
            )

            if append_rc:
                f.write(f"\n[returncode] {p.returncode}\n")

        return p.returncode
    except subprocess.TimeoutExpired as exc:
        with out_path.open("a", encoding="utf-8", errors="ignore") as f:
            f.write(f"\n[timeout] {type(exc).__name__}: {exc}\n")
        warn(s, "Command timed out", {"name": name, "cmd": cmd})
        return 124
    except Exception as exc:
        with out_path.open("a", encoding="utf-8", errors="ignore") as f:
            f.write(f"\n[error] {type(exc).__name__}: {exc}\n")
        warn(s, "Command failed while writing snapshot", {"name": name, "error": str(exc)})
        return 1


def safe_snapshot_command(
    s: Settings,
    name: str,
    cmd: List[str],
    timeout: Optional[int] = None,
) -> None:
    try:
        out = cap(cmd, timeout=timeout)
        write_snapshot(name, out + ("\n" if out and not out.endswith("\n") else "\n"), s.snapshot_root)
    except Exception as exc:
        warn(s, "Snapshot command failed", {"name": name, "error": str(exc)})


def snapshot_apt_source_state(s: Settings) -> None:
    safe_snapshot_command(
        s,
        "apt_sources_scan.txt",
        [
            "bash",
            "-lc",
            "grep -RniE 'Signed-By|NO_PUBKEY|opera|deb\\.opera\\.com|opera-stable' /etc/apt/sources.list /etc/apt/sources.list.d 2>/dev/null || true",
        ],
        timeout=60,
    )

    safe_snapshot_command(
        s,
        "apt_sources_list_d.txt",
        [
            "bash",
            "-lc",
            "find /etc/apt/sources.list.d -maxdepth 1 -type f -printf '%f\\n' 2>/dev/null | sort || true",
        ],
        timeout=60,
    )

    safe_snapshot_command(
        s,
        "apt_policy_head.txt",
        ["bash", "-lc", "apt-cache policy 2>/dev/null | sed -n '1,260p' || true"],
        timeout=60,
    )

    safe_snapshot_command(
        s,
        "dpkg_audit.txt",
        ["bash", "-lc", "dpkg --audit 2>&1 || true"],
        timeout=60,
    )


def apt_update(s: Settings) -> None:
    try:
        sudo(s, apt_cmd_base() + ["update"], use_noninteractive_env=True)
    except RuntimeError as exc:
        details_raw = str(exc)
        try:
            details = json.loads(details_raw)
        except Exception:
            details = {"raw": details_raw}

        stderr = details.get("stderr", "")
        stdout = details.get("stdout", "")
        combined = f"{stdout}\n{stderr}"

        snapshot_apt_source_state(s)
        write_snapshot("apt_update_stdout.txt", stdout + "\n", s.snapshot_root)
        write_snapshot("apt_update_stderr.txt", stderr + "\n", s.snapshot_root)

        if "Conflicting values set for option Signed-By" in combined:
            error(
                s,
                "APT source configuration conflict detected",
                {
                    "problem": "conflicting Signed-By values in apt source definitions",
                    "hint": "deduplicate or correct the conflicting repository entry before rerunning",
                    "stderr": combined[:4000],
                    "snapshot_dir": str(s.snapshot_root),
                },
            )
            raise AptSourceError("APT source configuration conflict detected")

        if "Could not get lock" in combined or "Unable to acquire the dpkg frontend lock" in combined:
            error(
                s,
                "APT lock contention detected",
                {
                    "problem": "another apt/dpkg process is holding the lock",
                    "hint": "wait for the other package process to finish, then rerun",
                    "stderr": combined[:4000],
                    "snapshot_dir": str(s.snapshot_root),
                },
            )
            raise AptSourceError("APT lock contention detected")

        if "dpkg was interrupted" in combined:
            error(
                s,
                "Interrupted dpkg state detected",
                {
                    "problem": "dpkg needs repair before continuing",
                    "hint": "run: sudo dpkg --configure -a",
                    "stderr": combined[:4000],
                    "snapshot_dir": str(s.snapshot_root),
                },
            )
            raise AptSourceError("Interrupted dpkg state detected")

        if "NO_PUBKEY" in combined or "The following signatures couldn't be verified" in combined:
            error(
                s,
                "APT repository signing problem detected",
                {
                    "problem": "missing or invalid repository signing key",
                    "hint": "repair or remove the broken repository, then rerun",
                    "stderr": combined[:4000],
                    "snapshot_dir": str(s.snapshot_root),
                },
            )
            raise AptSourceError("APT repository signing problem detected")

        if "does not have a Release file" in combined or "404  Not Found" in combined:
            error(
                s,
                "APT repository definition problem detected",
                {
                    "problem": "missing release file or dead repository URL",
                    "hint": "remove or fix the broken repository entry, then rerun",
                    "stderr": combined[:4000],
                    "snapshot_dir": str(s.snapshot_root),
                },
            )
            raise AptSourceError("APT repository definition problem detected")

        error(
            s,
            "apt-get update failed",
            {
                "stderr": combined[:4000],
                "snapshot_dir": str(s.snapshot_root),
            },
        )
        raise AptSourceError("apt-get update failed")


def install_packages_with_fallback(s: Settings, label: str, pkgs: List[str]) -> Dict[str, List[str]]:
    missing = [p for p in pkgs if not dpkg_installed(p)]

    for pkg in pkgs:
        if pkg in missing:
            info(s, "Installing missing package", {"group": label, "package": pkg})
        else:
            info(s, "Already installed", {"group": label, "package": pkg})

    if not missing:
        return {"installed": [], "failed": []}

    args = apt_cmd_base() + ["install"]
    if s.yes:
        args.append("-y")
    args.extend(missing)

    try:
        sudo(s, args, use_noninteractive_env=True)
        return {"installed": missing, "failed": []}
    except RuntimeError as exc:
        warn(
            s,
            "Grouped package install failed; retrying individually",
            {"group": label, "packages": missing, "error": str(exc)[:2000]},
        )

    installed: List[str] = []
    failed: List[str] = []

    for pkg in missing:
        try:
            args = apt_cmd_base() + ["install"]
            if s.yes:
                args.append("-y")
            args.append(pkg)
            sudo(s, args, use_noninteractive_env=True)
            installed.append(pkg)
        except RuntimeError as exc:
            failed.append(pkg)
            error(
                s,
                "Individual package install failed",
                {"group": label, "package": pkg, "error": str(exc)[:2000]},
            )

    return {"installed": installed, "failed": failed}


def collect_snapshots(s: Settings) -> None:
    info(s, "Capturing evidence snapshots", {"dir": str(s.snapshot_root)})
    s.snapshot_root.mkdir(parents=True, exist_ok=True)

    write_snapshot(
        "system.txt",
        (
            f"system={platform.system()}\n"
            f"release={platform.release()}\n"
            f"machine={platform.machine()}\n"
            f"python={sys.version}\n"
            f"run_id={s.run_id}\n"
        ),
        s.snapshot_root,
    )

    if Path("/etc/os-release").exists():
        safe_snapshot_command(s, "os_release.txt", ["bash", "-lc", "cat /etc/os-release"], timeout=30)

    if have("ip"):
        safe_snapshot_command(s, "ip_addr.txt", ["bash", "-lc", "ip addr show || true"], timeout=60)
        safe_snapshot_command(s, "ip_route.txt", ["bash", "-lc", "ip route show || true"], timeout=60)

    if have("ss"):
        safe_snapshot_command(
            s,
            "listening_ports.txt",
            ["bash", "-lc", "ss -tulnp | sed -n '1,260p' || true"],
            timeout=60,
        )

    if have("nmcli"):
        safe_snapshot_command(
            s,
            "nmcli_overview.txt",
            ["bash", "-lc", "nmcli general status; echo; nmcli dev status || true"],
            timeout=60,
        )

    if have("last"):
        safe_snapshot_command(s, "last_logins.txt", ["bash", "-lc", "last -n 40 || true"], timeout=60)

    if have("journalctl"):
        safe_snapshot_command(
            s,
            "auth_signals_tail.txt",
            [
                "bash",
                "-lc",
                "journalctl -b --no-pager | grep -Ei 'ssh|sudo|polkit|authentication failure|fail2ban|apparmor' | tail -n 240 || true",
            ],
            timeout=120,
        )

    safe_snapshot_command(
        s,
        "suid_files.txt",
        ["bash", "-lc", "sudo find / -xdev -perm -4000 -type f 2>/dev/null | sed -n '1,500p' || true"],
        timeout=300,
    )

    if have("systemctl"):
        safe_snapshot_command(
            s,
            "enabled_services_head.txt",
            ["bash", "-lc", "systemctl list-unit-files --state=enabled --no-pager | sed -n '1,260p' || true"],
            timeout=120,
        )
        safe_snapshot_command(
            s,
            "failed_services.txt",
            ["bash", "-lc", "systemctl --failed --no-pager || true"],
            timeout=60,
        )

    safe_snapshot_command(s, "dpkg_audit.txt", ["bash", "-lc", "dpkg --audit 2>&1 || true"], timeout=60)
    safe_snapshot_command(
        s,
        "defense_pkg_versions.txt",
        ["bash", "-lc", "dpkg -l clamav rkhunter chkrootkit debsums aide 2>/dev/null || true"],
        timeout=60,
    )
    safe_snapshot_command(
        s,
        "observe_pkg_versions.txt",
        ["bash", "-lc", "dpkg -l nmap tshark tcpdump lsof strace psmisc iftop nethogs mtr-tiny iperf3 dnsutils whois net-tools jq 2>/dev/null || true"],
        timeout=60,
    )
    safe_snapshot_command(
        s,
        "wireshark_pkg_versions.txt",
        ["bash", "-lc", "dpkg -l wireshark 2>/dev/null || true"],
        timeout=60,
    )

    info(s, "Snapshots complete", {"dir": str(s.snapshot_root)})


def install_wireshark_gui(s: Settings) -> Dict[str, List[str]]:
    if not s.install_wireshark_gui_mode:
        warn(s, "Skipping Wireshark GUI install (use --install-wireshark-gui)")
        return {"installed": [], "failed": []}
    return install_packages_with_fallback(s, "wireshark_gui", PKGS_OPTIONAL_WIRESHARK)


def enable_wireshark_capture(s: Settings) -> bool:
    if not s.enable_wireshark_capture_mode:
        warn(s, "Skipping Wireshark capture enable (use --enable-wireshark-capture)")
        return True

    user = getpass.getuser().strip()
    if not user:
        warn(s, "Could not determine current username; skipping Wireshark group update")
        return False

    group_check = subprocess.run(
        ["getent", "group", "wireshark"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if group_check.returncode != 0:
        warn(s, "Wireshark group does not exist yet; install relevant package first")
        return False

    info(s, "Adding user to wireshark group (logout/login required)", {"user": user})
    rc, _, _ = sudo(s, ["usermod", "-aG", "wireshark", user], check=False)
    return rc == 0


def run_clamav_scan(s: Settings) -> bool:
    if not s.run_clamav_path:
        return True
    if not have("clamscan"):
        warn(s, "clamscan not found")
        return False

    target = Path(s.run_clamav_path).expanduser()
    if not target.exists():
        warn(s, "ClamAV target path does not exist", {"path": str(target)})
        return False

    info(s, "Running clamscan (opt-in)", {"path": str(target)})
    rc = run_and_write_output(
        s,
        "clamscan.txt",
        ["sudo", "clamscan", "-r", "-i", "--", str(target)],
        timeout=None,
    )
    return rc in (0, 1)


def run_rkhunter_check(s: Settings) -> bool:
    if not s.run_rkhunter_check:
        return True
    if not have("rkhunter"):
        warn(s, "rkhunter not found")
        return False

    info(s, "Running rkhunter (opt-in)")
    rc = run_and_write_output(
        s,
        "rkhunter.txt",
        ["bash", "-lc", "sudo rkhunter --check --sk 2>&1"],
        timeout=None,
    )
    return rc == 0


def run_chkrootkit_check(s: Settings) -> bool:
    if not s.run_chkrootkit_check:
        return True
    if not have("chkrootkit"):
        warn(s, "chkrootkit not found")
        return False

    info(s, "Running chkrootkit (opt-in)")
    rc = run_and_write_output(
        s,
        "chkrootkit.txt",
        ["bash", "-lc", "sudo chkrootkit 2>&1"],
        timeout=None,
    )
    return rc == 0


def run_debsums_check(s: Settings) -> bool:
    if not s.run_debsums_check:
        return True
    if not have("debsums"):
        warn(s, "debsums not found")
        return False

    info(s, "Running debsums integrity check (opt-in)")
    rc = run_and_write_output(
        s,
        "debsums.txt",
        ["bash", "-lc", "sudo debsums -s 2>&1"],
        timeout=None,
    )
    return rc == 0


def init_aide_database(s: Settings) -> bool:
    if not s.init_aide_db:
        return True

    if have("aideinit"):
        cmd = ["bash", "-lc", "sudo aideinit 2>&1"]
    elif have("aide"):
        cmd = ["bash", "-lc", "sudo aide --init 2>&1"]
    else:
        warn(s, "AIDE init command not found")
        return False

    info(s, "Initializing AIDE database (opt-in; heavy)")
    rc = run_and_write_output(
        s,
        "aideinit.txt",
        cmd,
        timeout=None,
    )
    return rc == 0


def clear_directory_contents(path: Path) -> dict:
    result = {"path": str(path), "removed_files": 0, "removed_dirs": 0, "errors": []}

    if not path.exists():
        result["status"] = "missing"
        return result

    if not path.is_dir():
        result["status"] = "not_directory"
        return result

    for child in path.iterdir():
        try:
            if child.is_symlink() or child.is_file():
                child.unlink(missing_ok=True)
                result["removed_files"] += 1
            elif child.is_dir():
                shutil.rmtree(child)
                result["removed_dirs"] += 1
        except Exception as exc:
            result["errors"].append(f"{child}: {exc}")

    result["status"] = "ok"
    return result


def clean_safe(s: Settings) -> bool:
    if not s.clean_safe_mode:
        warn(s, "Skipping safe cleaner (use --clean-safe)")
        return True

    info(s, "Safe cleaning start")

    sudo(s, apt_cmd_base() + ["clean"], check=False, use_noninteractive_env=True)
    sudo(s, apt_cmd_base() + ["autoclean"], check=False, use_noninteractive_env=True)

    cache_targets = [
        HOME / ".cache" / "thumbnails",
        HOME / ".cache" / "pip",
    ]

    clean_report = []
    for path in cache_targets:
        info(s, "Cleaning user cache path", {"path": str(path)})
        clean_report.append(clear_directory_contents(path))

    write_snapshot(
        "clean_safe_report.json",
        json.dumps(clean_report, ensure_ascii=False, indent=2) + "\n",
        s.snapshot_root,
    )

    if have("journalctl"):
        info(s, "Vacuuming journald logs (bounded)")
        sudo(s, ["journalctl", "--vacuum-time=14d"], check=False)
        sudo(s, ["journalctl", "--vacuum-size=200M"], check=False)

    info(s, "Safe cleaning complete", {"cleaned": clean_report})
    return True


def bundle_evidence(s: Settings) -> Optional[Path]:
    if not s.bundle_evidence_mode:
        return None

    out = s.snapshot_root.parent / f"ztd_10_evidence_{s.run_id}.tar.gz"
    info(s, "Creating evidence bundle", {"bundle": str(out)})

    with tarfile.open(out, "w:gz") as tf:
        if s.snapshot_root.exists():
            tf.add(s.snapshot_root, arcname=s.snapshot_root.name)
        if s.log_file.exists():
            tf.add(s.log_file, arcname=s.log_file.name)

    return out


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="ztd_10_defense_observe.py")

    p.add_argument("--yes", action="store_true", help="Non-interactive apt install (-y)")
    p.add_argument("--json", action="store_true", help="Emit JSON to stdout (log file always JSONL)")
    p.add_argument("--no-banner", action="store_true", help="Disable Ghost Protocol banner")

    p.add_argument("--run-clamav-scan", default=None, help="Run clamscan against a path (opt-in)")
    p.add_argument("--run-rkhunter", action="store_true", help="Run rkhunter (opt-in)")
    p.add_argument("--run-chkrootkit", action="store_true", help="Run chkrootkit (opt-in)")
    p.add_argument("--run-debsums", action="store_true", help="Run debsums integrity check (opt-in)")
    p.add_argument("--init-aide", action="store_true", help="Initialize AIDE DB (opt-in)")

    p.add_argument("--clean-safe", action="store_true", help="Perform safe cleaning (opt-in)")
    p.add_argument("--bundle-evidence", action="store_true", help="Create evidence tar.gz (opt-in)")
    p.add_argument("--install-wireshark-gui", action="store_true", help="Install Wireshark GUI package (opt-in)")
    p.add_argument("--enable-wireshark-capture", action="store_true", help="Add user to wireshark group (opt-in)")
    return p


def main() -> int:
    args = build_parser().parse_args()

    s = Settings(
        yes=bool(args.yes),
        json_stdout=bool(args.json),
        no_banner=bool(args.no_banner),

        run_clamav_path=(str(args.run_clamav_scan).strip() if args.run_clamav_scan else None),
        run_rkhunter_check=bool(args.run_rkhunter),
        run_chkrootkit_check=bool(args.run_chkrootkit),
        run_debsums_check=bool(args.run_debsums),
        init_aide_db=bool(args.init_aide),

        clean_safe_mode=bool(args.clean_safe),
        bundle_evidence_mode=bool(args.bundle_evidence),
        install_wireshark_gui_mode=bool(args.install_wireshark_gui),
        enable_wireshark_capture_mode=bool(args.enable_wireshark_capture),

        log_file=LOG_FILE,
        snapshot_root=SNAPSHOT_ROOT,
        run_id=RUN_ID,
    )

    if not s.no_banner:
        ghost_protocol(10, 5, 64)

    require_debian_like(s)

    info(
        s,
        f"{APP_NAME} — {STAGE_NAME} start",
        {
            "app_id": APP_ID,
            "stage": STAGE_ID,
            "version": VERSION,
            "script_path": str(Path(__file__).resolve()),
            "log": str(s.log_file),
            "snapshot_root": str(s.snapshot_root),
        },
    )

    try:
        info(s, "[0] sudo preflight")
        require_sudo_ready(s)

        info(s, "[1] apt update")
        apt_update(s)

        info(s, "[2] install defense packages")
        defense_result = install_packages_with_fallback(s, "defense", PKGS_DEFENSE)

        info(s, "[3] install observation packages")
        observe_result = install_packages_with_fallback(s, "observation", PKGS_OBSERVE)

        info(s, "[4] optional Wireshark GUI install")
        wireshark_result = install_wireshark_gui(s)

        info(s, "[5] snapshots")
        collect_snapshots(s)

        info(s, "[6] optional capture permissions")
        capture_ok = enable_wireshark_capture(s)

        info(s, "[7] optional scans")
        optional_results = {
            "clamav": True,
            "rkhunter": True,
            "chkrootkit": True,
            "debsums": True,
            "aide_init": True,
            "clean_safe": True,
            "capture_permissions": capture_ok,
        }

        try:
            optional_results["clamav"] = run_clamav_scan(s)
        except Exception as exc:
            optional_results["clamav"] = False
            error(s, "ClamAV scan block failed", {"error": str(exc)})

        try:
            optional_results["rkhunter"] = run_rkhunter_check(s)
        except Exception as exc:
            optional_results["rkhunter"] = False
            error(s, "rkhunter block failed", {"error": str(exc)})

        try:
            optional_results["chkrootkit"] = run_chkrootkit_check(s)
        except Exception as exc:
            optional_results["chkrootkit"] = False
            error(s, "chkrootkit block failed", {"error": str(exc)})

        try:
            optional_results["debsums"] = run_debsums_check(s)
        except Exception as exc:
            optional_results["debsums"] = False
            error(s, "debsums block failed", {"error": str(exc)})

        try:
            optional_results["aide_init"] = init_aide_database(s)
        except Exception as exc:
            optional_results["aide_init"] = False
            error(s, "AIDE init block failed", {"error": str(exc)})

        info(s, "[8] optional safe cleaning")
        try:
            optional_results["clean_safe"] = clean_safe(s)
        except Exception as exc:
            optional_results["clean_safe"] = False
            error(s, "clean-safe block failed", {"error": str(exc)})

        bundle = bundle_evidence(s)

        failed_any = bool(
            defense_result["failed"]
            or observe_result["failed"]
            or wireshark_result["failed"]
            or not all(optional_results.values())
        )

        info(
            s,
            "Run summary",
            {
                "stage": STAGE_ID,
                "version": VERSION,
                "log": str(s.log_file),
                "snapshot_dir": str(s.snapshot_root),
                "bundle": str(bundle) if bundle else None,
                "defense_installed": defense_result["installed"],
                "defense_failed": defense_result["failed"],
                "observation_installed": observe_result["installed"],
                "observation_failed": observe_result["failed"],
                "wireshark_gui_installed": wireshark_result["installed"],
                "wireshark_gui_failed": wireshark_result["failed"],
                "optional_results": optional_results,
                "status": "partial" if failed_any else "success",
            },
        )
        info(s, f"{STAGE_NAME} complete")
        return 3 if failed_any else 0

    except AptSourceError as exc:
        error(
            s,
            "Stage stopped due to apt source configuration problem",
            {
                "reason": str(exc),
                "action_required": "repair apt repository definitions and rerun",
                "snapshot_root": str(s.snapshot_root),
                "log": str(s.log_file),
            },
        )
        return 100

    except PrivilegeError as exc:
        error(
            s,
            "Stage stopped due to privilege problem",
            {
                "reason": str(exc),
                "action_required": "rerun with working sudo access",
                "snapshot_root": str(s.snapshot_root),
                "log": str(s.log_file),
            },
        )
        return 101

    except Exception as exc:
        error(
            s,
            "Unhandled failure",
            {
                "error_type": type(exc).__name__,
                "error": str(exc),
                "snapshot_root": str(s.snapshot_root),
                "log": str(s.log_file),
            },
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())


# =============================================================================
# USAGE / INSTRUCTIONS
# =============================================================================
#
# SAVE AS
#   ztd_10_defense_observe.py
#
# MAKE EXECUTABLE
#   chmod +x ztd_10_defense_observe.py
#
# RUN (SAFE DEFAULT)
#   python3 ztd_10_defense_observe.py --yes
#
# RUN WITHOUT BANNER
#   python3 ztd_10_defense_observe.py --yes --no-banner
#
# RUN WITH EVIDENCE BUNDLE
#   python3 ztd_10_defense_observe.py --yes --bundle-evidence
#
# RUN WITH SAFE CLEANING
#   python3 ztd_10_defense_observe.py --yes --clean-safe
#
# INSTALL WIRESHARK GUI EXPLICITLY
#   python3 ztd_10_defense_observe.py --yes --install-wireshark-gui
#
# ENABLE WIRESHARK CAPTURE FOR CURRENT USER
#   python3 ztd_10_defense_observe.py --yes --enable-wireshark-capture
#
# RUN CLAMAV AGAINST HOME
#   python3 ztd_10_defense_observe.py --yes --run-clamav-scan "$HOME"
#
# RUN ROOTKIT / INTEGRITY CHECKS
#   python3 ztd_10_defense_observe.py \
#       --yes \
#       --run-rkhunter \
#       --run-chkrootkit \
#       --run-debsums
#
# FULL EXPLICIT AUDIT PASS
#   python3 ztd_10_defense_observe.py \
#       --yes \
#       --install-wireshark-gui \
#       --enable-wireshark-capture \
#       --run-clamav-scan "$HOME" \
#       --run-rkhunter \
#       --run-chkrootkit \
#       --run-debsums \
#       --bundle-evidence
#
# VERIFY
#   python3 -m py_compile ztd_10_defense_observe.py
#
# NOTES
#   - Wireshark GUI is not installed by default to avoid package preconfigure stalls.
#   - tshark/tcpdump remain in the default observation path.
#   - If apt source definitions are broken, the script exits cleanly with evidence snapshots.
#   - Package install uses grouped install with automatic per-package fallback.
#   - Heavy scan output is streamed directly to snapshot files instead of buffered in memory.
#   - This script works from any directory.
#
# SIGNATURE
#   Zero Trust Desktop / Stage 10 / Defense + Observation Toolkit
#
# =============================================================================
