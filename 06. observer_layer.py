#!/usr/bin/env python3
"""
README
======

Filename:
    06_observer_layer.py

Repo placement:
    ~/ztd/06_observer_layer.py

Purpose:
    Zero Trust Desktop (ZTD) Stage 06 observer layer.
    Installs a development-safe observer toolkit and writes a deterministic
    posture report plus host snapshots to disk without changing firewall policy
    or blocking traffic.

System requirements:
    - Debian/Ubuntu-like Linux
    - python3
    - sudo
    - apt-get
    - dpkg

Default behavior:
    - validate platform and sudo access
    - apt-get update
    - install missing observer packages only
    - capture deterministic host/network/security snapshots
    - write JSONL log + snapshot files under the operator's home state directory
    - print a readable run summary

Optional flags:
    --upgrade
        Run apt-get upgrade explicitly.

    --run-lynis
        Run lynis system audit and save output.

    --run-rkhunter
        Run rkhunter check and save output.

    --capture-pcap IFACE
        Capture a short tcpdump sample on the given interface.

    --pcap-seconds N
        Duration for packet capture. Default: 7 seconds.

    --nmap-local
        Run an nmap localhost service scan.

    --lan-sweep CIDR
        Run an opt-in nmap ping sweep against a provided CIDR.

    --yes
        Use non-interactive apt (-y).

    --json
        Emit JSON events to stdout instead of readable text.

Design notes:
    - This stage does not install firewall policy stacks by default.
    - This stage does not modify group membership.
    - This stage does not install malware scanners.
    - Snapshot capture is best-effort and records non-zero command results.
    - Long-running checks use explicit timeouts.
    - State is written under the real operator account, even if launched with sudo.

Paths:
    Script path:
        Resolved using __file__ so the script works from any current directory.

    State path:
        ~/.local/state/zero-trust-desktop/ztd_06/

    Output:
        JSONL log:
            ~/.local/state/zero-trust-desktop/ztd_06/log/ztd_06_observer_layer_<ts>.jsonl

        Snapshots:
            ~/.local/state/zero-trust-desktop/ztd_06/snapshots/<ts>/

Example runs:
    python3 ~/ztd/06_observer_layer.py --yes
    python3 ~/ztd/06_observer_layer.py --yes --run-lynis --run-rkhunter
    python3 ~/ztd/06_observer_layer.py --yes --nmap-local
    python3 ~/ztd/06_observer_layer.py --yes --capture-pcap wlan0 --pcap-seconds 10
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import platform
import pwd
import shutil
import subprocess
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Iterable, List, Optional, Tuple


SCRIPT_PATH = Path(__file__).resolve()
SCRIPT_DIR = SCRIPT_PATH.parent

APP_NAME = "Zero Trust Desktop"
APP_ID = "ztd"
STAGE_NAME = "06. OBSERVER LAYER"
STAGE_ID = "ztd_06_observer_layer"
VERSION = "0.7.0"

DEFAULT_TIMEOUT_SHORT = 30
DEFAULT_TIMEOUT_MEDIUM = 120
DEFAULT_TIMEOUT_LONG = 900
DEFAULT_TIMEOUT_RKHUNTER = 1200

PKGS_OBSERVER_CORE = [
    # Discovery / visibility
    "nmap",
    "arp-scan",
    "fping",
    "traceroute",
    "mtr-tiny",
    "dnsutils",
    "whois",
    "iproute2",
    "net-tools",
    # Performance / link visibility
    "iperf3",
    "ethtool",
    "iw",
    "rfkill",
    # Traffic inspection
    "tcpdump",
    "wireshark",
    # Introspection
    "lsof",
    "strace",
    "psmisc",
    "sysstat",
    # Posture scanners
    "lynis",
    "rkhunter",
]


@dataclass
class Settings:
    yes: bool
    json_stdout: bool
    upgrade: bool
    run_lynis: bool
    run_rkhunter: bool
    capture_pcap_iface: Optional[str]
    capture_pcap_seconds: int
    nmap_local: bool
    lan_sweep_cidr: Optional[str]
    state_dir: Path
    log_dir: Path
    snapshot_dir: Path
    log_file: Path
    run_id: str
    operator_user: str
    operator_home: Path


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


def detect_operator_user() -> str:
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user:
        return sudo_user
    return getpass.getuser()


def detect_operator_home(user: str) -> Path:
    try:
        return Path(pwd.getpwnam(user).pw_dir).resolve()
    except Exception:
        return Path.home().resolve()


def emit(s: Settings, ev: Event) -> None:
    if s.json_stdout:
        print(json.dumps(asdict(ev), ensure_ascii=False))
    else:
        if ev.data:
            print(f"[{ev.ts}] {ev.level}: {ev.msg} :: {json.dumps(ev.data, ensure_ascii=False)}")
        else:
            print(f"[{ev.ts}] {ev.level}: {ev.msg}")

    s.log_dir.mkdir(parents=True, exist_ok=True)
    with s.log_file.open("a", encoding="utf-8") as f:
        f.write(json.dumps(asdict(ev), ensure_ascii=False) + "\n")


def info(s: Settings, msg: str, data: Optional[dict] = None) -> None:
    emit(s, Event(ts=now_ts(), level="INFO", msg=msg, data=data))


def warn(s: Settings, msg: str, data: Optional[dict] = None) -> None:
    emit(s, Event(ts=now_ts(), level="WARN", msg=msg, data=data))


def error(s: Settings, msg: str, data: Optional[dict] = None) -> None:
    emit(s, Event(ts=now_ts(), level="ERROR", msg=msg, data=data))


def run(
    s: Settings,
    cmd: List[str],
    *,
    check: bool = True,
    timeout: Optional[int] = None,
) -> Tuple[int, str, str]:
    info(s, "$ " + " ".join(cmd), {"timeout_seconds": timeout})
    try:
        p = subprocess.run(
            cmd,
            text=True,
            capture_output=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        error(s, "Command timed out", {"cmd": cmd, "timeout_seconds": timeout})
        if check:
            raise RuntimeError(f"Command timed out: {' '.join(cmd)}")
        return 124, "", f"Timed out after {timeout} seconds"

    if check and p.returncode != 0:
        error(
            s,
            "Command failed",
            {
                "rc": p.returncode,
                "cmd": cmd,
                "stderr": (p.stderr or "").strip(),
            },
        )
        raise RuntimeError(f"Command failed: {' '.join(cmd)} (rc={p.returncode})")

    return p.returncode, p.stdout or "", p.stderr or ""


def sudo(
    s: Settings,
    cmd: List[str],
    *,
    check: bool = True,
    timeout: Optional[int] = None,
) -> Tuple[int, str, str]:
    return run(s, ["sudo"] + cmd, check=check, timeout=timeout)


def require_debian_like(s: Settings) -> None:
    os_release = Path("/etc/os-release")
    if not (os_release.exists() and have("apt-get") and have("dpkg") and have("sudo")):
        error(s, "Unsupported platform. Debian/Ubuntu with apt-get, dpkg, and sudo required.")
        raise SystemExit(2)

    text = os_release.read_text(encoding="utf-8", errors="ignore").lower()
    if not any(token in text for token in ("id=ubuntu", "id=debian", "id_like=debian")):
        error(s, "Unsupported distro family. Debian-like system required.")
        raise SystemExit(2)


def sudo_preflight(s: Settings) -> None:
    info(s, "Validating sudo access")
    p = subprocess.run(["sudo", "-v"], text=True, capture_output=True)
    if p.returncode != 0:
        error(s, "sudo validation failed", {"rc": p.returncode, "stderr": (p.stderr or "").strip()})
        raise SystemExit(1)


def dpkg_installed(pkg: str) -> bool:
    p = subprocess.run(["dpkg", "-s", pkg], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return p.returncode == 0


def apt_update(s: Settings) -> None:
    args = ["apt-get", "update"]
    if s.yes:
        args.append("-y")
    sudo(s, args, timeout=DEFAULT_TIMEOUT_LONG)


def apt_upgrade(s: Settings) -> None:
    args = ["apt-get", "upgrade"]
    if s.yes:
        args.append("-y")
    sudo(s, args, timeout=DEFAULT_TIMEOUT_LONG)


def apt_install_missing(s: Settings, pkgs: Iterable[str]) -> None:
    pkg_list = list(pkgs)
    missing = [pkg for pkg in pkg_list if not dpkg_installed(pkg)]

    for pkg in pkg_list:
        if pkg in missing:
            info(s, "Installing missing package", {"package": pkg})
        else:
            info(s, "Already installed", {"package": pkg})

    if not missing:
        return

    args = ["apt-get", "install"]
    if s.yes:
        args.append("-y")
    args.extend(missing)
    sudo(s, args, timeout=DEFAULT_TIMEOUT_LONG)


def write_snapshot_file(s: Settings, name: str, content: str) -> Path:
    s.snapshot_dir.mkdir(parents=True, exist_ok=True)
    path = s.snapshot_dir / name
    path.write_text(content, encoding="utf-8", errors="ignore")
    return path


def cap(cmd: List[str], *, timeout: Optional[int] = None) -> Tuple[int, str]:
    try:
        p = subprocess.run(cmd, text=True, capture_output=True, timeout=timeout)
        combined = ((p.stdout or "") + ("\n" + p.stderr if p.stderr else "")).strip()
        return p.returncode, combined
    except subprocess.TimeoutExpired:
        return 124, f"Timed out after {timeout} seconds"


def capture_cmd(
    s: Settings,
    name: str,
    cmd: List[str],
    *,
    timeout: Optional[int] = DEFAULT_TIMEOUT_SHORT,
) -> None:
    try:
        rc, txt = cap(cmd, timeout=timeout)
        body = txt.strip()
        if rc != 0:
            warn(s, "Snapshot command returned non-zero", {"name": name, "rc": rc, "cmd": cmd})
            prefix = f"[command_rc={rc}]"
            body = f"{prefix}\n{body}" if body else prefix
        write_snapshot_file(s, name, body + ("\n" if body else ""))
    except Exception as exc:
        warn(s, "Snapshot capture failed", {"name": name, "error": str(exc)})


def baseline_snapshots(s: Settings) -> None:
    info(s, "Snapshot start", {"snapshot_dir": str(s.snapshot_dir)})

    capture_cmd(s, "uname.txt", ["uname", "-a"])
    if have("lsb_release"):
        capture_cmd(s, "lsb_release.txt", ["lsb_release", "-a"])
    capture_cmd(s, "ip_addr_brief.txt", ["bash", "-lc", "ip -br addr || true"])
    capture_cmd(s, "ip_route.txt", ["bash", "-lc", "ip route || true"])
    capture_cmd(s, "ss_listen.txt", ["bash", "-lc", "ss -tulnp | sed -n '1,220p' || true"], timeout=DEFAULT_TIMEOUT_MEDIUM)
    capture_cmd(s, "resolv_conf.txt", ["bash", "-lc", "cat /etc/resolv.conf 2>/dev/null | head -n 80 || true"])

    if have("resolvectl"):
        capture_cmd(s, "resolvectl_status.txt", ["bash", "-lc", "resolvectl status | head -n 200 || true"], timeout=DEFAULT_TIMEOUT_MEDIUM)

    if have("nmcli"):
        capture_cmd(s, "nmcli_general.txt", ["nmcli", "general", "status"])
        capture_cmd(s, "nmcli_device.txt", ["nmcli", "device", "status"])
        capture_cmd(s, "nmcli_active.txt", ["nmcli", "connection", "show", "--active"])
        capture_cmd(
            s,
            "nmcli_wifi_list.txt",
            ["bash", "-lc", "nmcli -f IN-USE,SSID,SECURITY,SIGNAL,RATE,BARS device wifi list | head -n 40 || true"],
            timeout=DEFAULT_TIMEOUT_MEDIUM,
        )

    if have("nft"):
        capture_cmd(s, "nft_ruleset.txt", ["sudo", "nft", "list", "ruleset"], timeout=DEFAULT_TIMEOUT_MEDIUM)
    if have("ufw"):
        capture_cmd(s, "ufw_status_verbose.txt", ["sudo", "ufw", "status", "verbose"], timeout=DEFAULT_TIMEOUT_MEDIUM)
    if have("iptables-save"):
        capture_cmd(s, "iptables_save.txt", ["sudo", "iptables-save"], timeout=DEFAULT_TIMEOUT_MEDIUM)

    if have("aa-status"):
        capture_cmd(s, "apparmor_status_head.txt", ["bash", "-lc", "aa-status | head -n 200 || true"], timeout=DEFAULT_TIMEOUT_MEDIUM)

    if have("systemctl"):
        capture_cmd(
            s,
            "security_services.txt",
            ["bash", "-lc", "systemctl list-units --type=service --no-pager | egrep 'apparmor|fail2ban|ufw|nftables|NetworkManager' || true"],
            timeout=DEFAULT_TIMEOUT_MEDIUM,
        )
        capture_cmd(
            s,
            "failed_units.txt",
            ["bash", "-lc", "systemctl --failed --no-pager || true"],
            timeout=DEFAULT_TIMEOUT_MEDIUM,
        )

    info(s, "Snapshot complete", {"snapshot_dir": str(s.snapshot_dir)})


def run_lynis_audit(s: Settings) -> None:
    if not s.run_lynis:
        return
    if not have("lynis"):
        warn(s, "lynis not found")
        return

    info(s, "Running lynis audit", {"timeout_seconds": DEFAULT_TIMEOUT_LONG})
    rc, txt = cap(["sudo", "lynis", "audit", "system", "--quick"], timeout=DEFAULT_TIMEOUT_LONG)
    if rc != 0:
        warn(s, "lynis returned non-zero", {"rc": rc})
    write_snapshot_file(s, "lynis_audit.txt", (txt + "\n") if txt else f"[command_rc={rc}]\n")


def run_rkhunter_check(s: Settings) -> None:
    if not s.run_rkhunter:
        return
    if not have("rkhunter"):
        warn(s, "rkhunter not found")
        return

    info(s, "Running rkhunter check", {"timeout_seconds": DEFAULT_TIMEOUT_RKHUNTER})
    rc, txt = cap(["sudo", "rkhunter", "--check", "--sk"], timeout=DEFAULT_TIMEOUT_RKHUNTER)
    if rc != 0:
        warn(s, "rkhunter returned non-zero", {"rc": rc})
    write_snapshot_file(s, "rkhunter_check.txt", (txt + "\n") if txt else f"[command_rc={rc}]\n")


def nmap_localhost(s: Settings) -> None:
    if not s.nmap_local:
        return
    if not have("nmap"):
        warn(s, "nmap not found")
        return

    info(s, "Running nmap localhost scan", {"timeout_seconds": DEFAULT_TIMEOUT_LONG})
    rc, txt = cap(["sudo", "nmap", "-sV", "127.0.0.1"], timeout=DEFAULT_TIMEOUT_LONG)
    if rc != 0:
        warn(s, "nmap localhost returned non-zero", {"rc": rc})
    write_snapshot_file(s, "nmap_localhost.txt", (txt + "\n") if txt else f"[command_rc={rc}]\n")


def lan_sweep(s: Settings) -> None:
    if not s.lan_sweep_cidr:
        return
    if not have("nmap"):
        warn(s, "nmap not found")
        return

    cidr = s.lan_sweep_cidr.strip()
    info(s, "Running LAN ping sweep", {"cidr": cidr, "timeout_seconds": DEFAULT_TIMEOUT_LONG})
    rc, txt = cap(["sudo", "nmap", "-sn", cidr], timeout=DEFAULT_TIMEOUT_LONG)
    if rc != 0:
        warn(s, "LAN sweep returned non-zero", {"rc": rc, "cidr": cidr})
    write_snapshot_file(s, "nmap_lan_sweep.txt", (txt + "\n") if txt else f"[command_rc={rc}]\n")


def capture_pcap(s: Settings) -> None:
    if not s.capture_pcap_iface:
        return
    if not have("tcpdump"):
        warn(s, "tcpdump not found")
        return
    if not have("timeout"):
        warn(s, "timeout command not found")
        return

    iface = s.capture_pcap_iface.strip()
    secs = max(1, int(s.capture_pcap_seconds))
    s.snapshot_dir.mkdir(parents=True, exist_ok=True)
    pcap_path = s.snapshot_dir / f"tcpdump_{iface}_{secs}s.pcap"

    info(
        s,
        "Capturing short tcpdump sample",
        {"iface": iface, "seconds": secs, "pcap": str(pcap_path)},
    )

    sudo(
        s,
        ["timeout", f"{secs}s", "tcpdump", "-i", iface, "-w", str(pcap_path)],
        check=False,
        timeout=secs + 15,
    )

    sudo(s, ["chown", f"{s.operator_user}:{s.operator_user}", str(pcap_path)], check=False, timeout=DEFAULT_TIMEOUT_SHORT)


def report_summary(s: Settings) -> None:
    info(
        s,
        "Run summary",
        {
            "app": APP_ID,
            "stage": STAGE_ID,
            "version": VERSION,
            "system": f"{platform.system()} {platform.release()}",
            "arch": platform.machine(),
            "script_path": str(SCRIPT_PATH),
            "operator_user": s.operator_user,
            "state_dir": str(s.state_dir),
            "log": str(s.log_file),
            "snapshot_dir": str(s.snapshot_dir),
        },
    )


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog=SCRIPT_PATH.name)
    p.add_argument("--yes", action="store_true", help="Non-interactive apt (-y)")
    p.add_argument("--json", action="store_true", help="Emit JSON events to stdout")
    p.add_argument("--upgrade", action="store_true", help="Explicit apt-get upgrade")
    p.add_argument("--run-lynis", action="store_true", help="Run lynis audit")
    p.add_argument("--run-rkhunter", action="store_true", help="Run rkhunter check")
    p.add_argument("--capture-pcap", default=None, help="Capture tcpdump pcap on interface, e.g. wlan0")
    p.add_argument("--pcap-seconds", type=int, default=7, help="Seconds for pcap capture (default: 7)")
    p.add_argument("--nmap-local", action="store_true", help="Run nmap localhost scan")
    p.add_argument("--lan-sweep", default=None, help="Run nmap ping sweep on CIDR, e.g. 192.168.1.0/24")
    return p


def build_settings(args: argparse.Namespace) -> Settings:
    run_id = datetime.now().strftime("%Y%m%d_%H%M%S")
    operator_user = detect_operator_user()
    operator_home = detect_operator_home(operator_user)

    state_dir = operator_home / ".local" / "state" / "zero-trust-desktop" / "ztd_06"
    log_dir = state_dir / "log"
    snapshot_dir = state_dir / "snapshots" / run_id
    log_file = log_dir / f"{STAGE_ID}_{run_id}.jsonl"

    return Settings(
        yes=bool(args.yes),
        json_stdout=bool(args.json),
        upgrade=bool(args.upgrade),
        run_lynis=bool(args.run_lynis),
        run_rkhunter=bool(args.run_rkhunter),
        capture_pcap_iface=(str(args.capture_pcap).strip() if args.capture_pcap else None),
        capture_pcap_seconds=int(args.pcap_seconds),
        nmap_local=bool(args.nmap_local),
        lan_sweep_cidr=(str(args.lan_sweep).strip() if args.lan_sweep else None),
        state_dir=state_dir,
        log_dir=log_dir,
        snapshot_dir=snapshot_dir,
        log_file=log_file,
        run_id=run_id,
        operator_user=operator_user,
        operator_home=operator_home,
    )


def main() -> int:
    args = build_parser().parse_args()
    s = build_settings(args)

    require_debian_like(s)
    sudo_preflight(s)

    info(
        s,
        f"{APP_NAME} — {STAGE_NAME} start",
        {
            "version": VERSION,
            "script_path": str(SCRIPT_PATH),
            "script_dir": str(SCRIPT_DIR),
            "log": str(s.log_file),
        },
    )

    info(s, "[1] apt update")
    apt_update(s)

    if s.upgrade:
        info(s, "[1b] apt upgrade (explicit)")
        apt_upgrade(s)

    info(s, "[2] install observer toolkit (idempotent)")
    apt_install_missing(s, PKGS_OBSERVER_CORE)

    info(s, "[3] baseline snapshots")
    baseline_snapshots(s)

    info(s, "[4] optional audits / scans")
    run_lynis_audit(s)
    run_rkhunter_check(s)
    nmap_localhost(s)
    lan_sweep(s)
    capture_pcap(s)

    report_summary(s)
    info(s, f"{STAGE_NAME} complete", {"log": str(s.log_file), "snapshot_dir": str(s.snapshot_dir)})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


# ================================================================
# INSTRUCTIONS
# ================================================================
#
# Repo directory:
#   mkdir -p ~/ztd
#
# Save file:
#   ~/ztd/06_observer_layer.py
#
# Make executable:
#   chmod +x ~/ztd/06_observer_layer.py
#
# Baseline run:
#   python3 ~/ztd/06_observer_layer.py --yes
#
# Full local host audit:
#   python3 ~/ztd/06_observer_layer.py --yes --run-lynis --run-rkhunter --nmap-local
#
# Optional packet capture:
#   python3 ~/ztd/06_observer_layer.py --yes --capture-pcap wlan0 --pcap-seconds 10
#
# Optional LAN sweep:
#   python3 ~/ztd/06_observer_layer.py --yes --lan-sweep 192.168.1.0/24
#
# Syntax check:
#   python3 -m py_compile ~/ztd/06_observer_layer.py
#
# Output location:
#   ~/.local/state/zero-trust-desktop/ztd_06/
#
# Notes:
#   - Script works regardless of current directory.
#   - Script resolves its own path via __file__.
#   - State is written under the real operator's home directory.
#   - This version intentionally excludes:
#       * wireshark group modification
#       * chkrootkit
#       * clamav install branch
#       * default firewall package installation
#
# ================================================================
