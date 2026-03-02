#!/usr/bin/env python3
"""
ZTD — 06. OBSERVER LAYER (FULL TOOL ARSENAL + POSTURE REPORT)
Version: 0.6.0
Suite: Zero Trust Desktop (ZTD)
Stage: 06 (Observer / Evidence / Tooling)

GOAL
  Install a comprehensive security + networking toolkit and emit a deterministic posture report
  WITHOUT enforcing firewall rules or breaking development.

DEFAULT BEHAVIOR (SAFE)
  - apt-get update
  - install missing observer/tooling packages (idempotent; no removals)
  - write snapshots + report to disk
  - print a readable summary

OPTIONAL BEHAVIOR (EXPLICIT FLAGS)
  --upgrade                apt-get upgrade (explicit)
  --run-lynis              run lynis audit (can take time)
  --run-rkhunter           run rkhunter check (can take time; may warn a lot)
  --run-chkrootkit         run chkrootkit (can take time; may warn a lot)
  --capture-pcap <iface>   capture a short tcpdump sample (requires sudo; opt-in)
  --nmap-local             run nmap against localhost (opt-in)
  --lan-sweep <CIDR>       run nmap ping-sweep (opt-in; only if you explicitly give CIDR)
  --wireshark-group        add current user to wireshark group (logout/login required)

NOTES
  - Debian/Ubuntu only.
  - This layer installs Wireshark but does not capture traffic unless explicitly asked.
  - No firewall changes. No network blocking. No OpenSnitch enablement.

OUTPUT
  - JSONL log: ~/.local/state/zero-trust-desktop/ztd_06/log/ztd_06_<ts>.jsonl
  - Snapshots: ~/.local/state/zero-trust-desktop/ztd_06/snapshots/<ts>/
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
STAGE_NAME = "06. OBSERVER LAYER"
STAGE_ID = "ztd_06_observer_layer"
VERSION = "0.6.0"

HOME = Path.home()
STATE_DIR = HOME / ".local" / "state" / "zero-trust-desktop" / "ztd_06"
LOG_DIR = STATE_DIR / "log"
SNAP_DIR = STATE_DIR / "snapshots"
RUN_ID = datetime.now().strftime("%Y%m%d_%H%M%S")
LOG_FILE = LOG_DIR / f"{STAGE_ID}_{RUN_ID}.jsonl"
SNAPSHOT_ROOT = SNAP_DIR / RUN_ID

# Comprehensive, dev-safe tooling. Some may already be installed from earlier layers.
PKGS_OBSERVER_CORE = [
    # Discovery / visibility
    "nmap",
    "arp-scan",
    "netdiscover",
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
    "wavemon",
    "iw",
    "wireless-tools",
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
    "debsums",
    "aide",
    "rkhunter",
    "chkrootkit",
    # Optional-ish but useful
    "ufw",
    "nftables",
    "iptables",
    "conntrack",
]

# Malware scanner (install-only; scanning opt-in)
PKGS_MALWARE = [
    "clamav",
    "clamav-daemon",
]


@dataclass
class Settings:
    yes: bool
    json_stdout: bool

    upgrade: bool
    install_malware: bool

    run_lynis: bool
    run_rkhunter: bool
    run_chkrootkit: bool

    capture_pcap_iface: Optional[str]
    capture_pcap_seconds: int

    nmap_local: bool
    lan_sweep_cidr: Optional[str]

    wireshark_group: bool

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


def apt_upgrade(s: Settings) -> None:
    args = ["apt-get", "upgrade"]
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


def _cap(cmd: List[str]) -> str:
    p = subprocess.run(cmd, text=True, capture_output=True)
    return (p.stdout or p.stderr or "").strip()


def capture_cmd(s: Settings, name: str, cmd: List[str]) -> None:
    try:
        txt = _cap(cmd)
        write_snapshot_file(s, name, (txt + "\n").lstrip())
    except Exception as e:
        warn(s, f"Snapshot capture failed: {name}", {"error": str(e)})


def baseline_snapshots(s: Settings) -> None:
    info(s, "Snapshot start", {"snapshot_dir": str(s.snapshot_root)})

    capture_cmd(s, "uname.txt", ["uname", "-a"])
    if have("lsb_release"):
        capture_cmd(s, "lsb_release.txt", ["lsb_release", "-a"])
    capture_cmd(s, "ip_addr_brief.txt", ["bash", "-lc", "ip -br addr || true"])
    capture_cmd(s, "ip_route.txt", ["bash", "-lc", "ip route || true"])
    capture_cmd(s, "ss_listen.txt", ["bash", "-lc", "ss -tulnp | sed -n '1,220p' || true"])
    capture_cmd(s, "resolv_conf.txt", ["bash", "-lc", "cat /etc/resolv.conf 2>/dev/null | head -n 80 || true"])

    if have("resolvectl"):
        capture_cmd(s, "resolvectl_status.txt", ["bash", "-lc", "resolvectl status | head -n 200 || true"])

    if have("nmcli"):
        capture_cmd(s, "nmcli_general.txt", ["nmcli", "general", "status"])
        capture_cmd(s, "nmcli_device.txt", ["nmcli", "device", "status"])
        capture_cmd(s, "nmcli_active.txt", ["nmcli", "connection", "show", "--active"])
        capture_cmd(s, "nmcli_wifi_list.txt", ["bash", "-lc", "nmcli -f IN-USE,SSID,SECURITY,SIGNAL,RATE,BARS device wifi list | head -n 40 || true"])

    # Firewall state (visibility only)
    if have("nft"):
        capture_cmd(s, "nft_ruleset.txt", ["sudo", "nft", "list", "ruleset"])
    if have("ufw"):
        capture_cmd(s, "ufw_status_verbose.txt", ["sudo", "ufw", "status", "verbose"])
    if have("iptables-save"):
        capture_cmd(s, "iptables_save.txt", ["sudo", "iptables-save"])

    # AppArmor status
    if have("aa-status"):
        capture_cmd(s, "apparmor_status_head.txt", ["bash", "-lc", "aa-status | head -n 200 || true"])

    # Services snapshot
    if have("systemctl"):
        capture_cmd(s, "security_services.txt", ["bash", "-lc", "systemctl list-units --type=service --no-pager | egrep 'apparmor|fail2ban|ufw|nftables|NetworkManager' || true"])
        capture_cmd(s, "failed_units.txt", ["bash", "-lc", "systemctl --failed --no-pager || true"])

    info(s, "Snapshot complete", {"snapshot_dir": str(s.snapshot_root)})


def maybe_add_wireshark_group(s: Settings) -> None:
    if not s.wireshark_group:
        return
    # On Debian/Ubuntu, group is typically "wireshark"
    info(s, "Adding current user to wireshark group (logout/login required)")
    sudo(s, ["usermod", "-aG", "wireshark", str(Path.home().owner())], check=False)  # best-effort


def run_lynis(s: Settings) -> None:
    if not s.run_lynis:
        return
    if not have("lynis"):
        warn(s, "lynis not found")
        return
    info(s, "Running lynis audit (this can take time)")
    # Best-effort: capture output
    txt = _cap(["sudo", "lynis", "audit", "system", "--quick"])
    write_snapshot_file(s, "lynis_audit.txt", txt + "\n")


def run_rkhunter(s: Settings) -> None:
    if not s.run_rkhunter:
        return
    if not have("rkhunter"):
        warn(s, "rkhunter not found")
        return
    info(s, "Running rkhunter check (this can take time; output may be noisy)")
    txt = _cap(["sudo", "rkhunter", "--check", "--sk"])
    write_snapshot_file(s, "rkhunter_check.txt", txt + "\n")


def run_chkrootkit(s: Settings) -> None:
    if not s.run_chkrootkit:
        return
    if not have("chkrootkit"):
        warn(s, "chkrootkit not found")
        return
    info(s, "Running chkrootkit (this can take time; output may be noisy)")
    txt = _cap(["sudo", "chkrootkit"])
    write_snapshot_file(s, "chkrootkit.txt", txt + "\n")


def nmap_localhost(s: Settings) -> None:
    if not s.nmap_local:
        return
    if not have("nmap"):
        warn(s, "nmap not found")
        return
    info(s, "Running nmap against localhost (opt-in)")
    txt = _cap(["sudo", "nmap", "-sV", "-O", "127.0.0.1"])
    write_snapshot_file(s, "nmap_localhost.txt", txt + "\n")


def lan_sweep(s: Settings) -> None:
    if not s.lan_sweep_cidr:
        return
    if not have("nmap"):
        warn(s, "nmap not found")
        return
    cidr = s.lan_sweep_cidr.strip()
    info(s, "Running LAN ping sweep (opt-in)", {"cidr": cidr})
    txt = _cap(["sudo", "nmap", "-sn", cidr])
    write_snapshot_file(s, "nmap_lan_sweep.txt", txt + "\n")


def capture_pcap(s: Settings) -> None:
    if not s.capture_pcap_iface:
        return
    if not have("tcpdump"):
        warn(s, "tcpdump not found")
        return
    iface = s.capture_pcap_iface.strip()
    secs = int(s.capture_pcap_seconds)
    if secs < 1:
        secs = 5
    pcap_path = s.snapshot_root / f"tcpdump_{iface}_{secs}s.pcap"
    info(s, "Capturing short tcpdump sample (opt-in)", {"iface": iface, "seconds": secs, "pcap": str(pcap_path)})
    # Use timeout to avoid hanging
    sudo(s, ["bash", "-lc", f"timeout {secs}s tcpdump -i {iface} -w '{pcap_path}' >/dev/null 2>&1 || true"], check=False)


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
            "log": str(s.log_file),
            "snapshot_dir": str(s.snapshot_root),
        },
    )


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="06. observer_layer.py")
    p.add_argument("--yes", action="store_true", help="Non-interactive apt (-y)")
    p.add_argument("--json", action="store_true", help="Emit JSON to stdout (log file always JSONL)")
    p.add_argument("--upgrade", action="store_true", help="Explicit apt-get upgrade")
    p.add_argument("--install-malware", action="store_true", help="Install clamav packages (install-only by default)")

    p.add_argument("--run-lynis", action="store_true", help="Run lynis audit (opt-in)")
    p.add_argument("--run-rkhunter", action="store_true", help="Run rkhunter check (opt-in)")
    p.add_argument("--run-chkrootkit", action="store_true", help="Run chkrootkit (opt-in)")

    p.add_argument("--capture-pcap", default=None, help="Capture tcpdump pcap on interface (opt-in), e.g. wlan0")
    p.add_argument("--pcap-seconds", type=int, default=7, help="Seconds for pcap capture (default 7)")

    p.add_argument("--nmap-local", action="store_true", help="Run nmap localhost scan (opt-in)")
    p.add_argument("--lan-sweep", default=None, help="Run nmap ping sweep on CIDR (opt-in), e.g. 192.168.1.0/24")

    p.add_argument("--wireshark-group", action="store_true", help="Add current user to wireshark group (logout/login required)")

    return p


def main() -> int:
    args = build_parser().parse_args()

    s = Settings(
        yes=bool(args.yes),
        json_stdout=bool(args.json),

        upgrade=bool(args.upgrade),
        install_malware=bool(args.install_malware),

        run_lynis=bool(args.run_lynis),
        run_rkhunter=bool(args.run_rkhunter),
        run_chkrootkit=bool(args.run_chkrootkit),

        capture_pcap_iface=(str(args.capture_pcap).strip() if args.capture_pcap else None),
        capture_pcap_seconds=int(args.pcap_seconds),

        nmap_local=bool(args.nmap_local),
        lan_sweep_cidr=(str(args.lan_sweep).strip() if args.lan_sweep else None),

        wireshark_group=bool(args.wireshark_group),

        log_file=LOG_FILE,
        snapshot_root=SNAPSHOT_ROOT,
    )

    require_debian_like(s)

    info(s, f"{APP_NAME} — {STAGE_NAME} start", {"version": VERSION, "log": str(s.log_file)})

    info(s, "[1] apt update")
    apt_update(s)

    if s.upgrade:
        info(s, "[1b] apt upgrade (explicit)")
        apt_upgrade(s)

    info(s, "[2] install observer/tool arsenal (idempotent)")
    apt_install_missing(s, PKGS_OBSERVER_CORE)

    if s.install_malware:
        info(s, "[2b] install malware scanner packages (clamav)")
        apt_install_missing(s, PKGS_MALWARE)

    if s.wireshark_group:
        maybe_add_wireshark_group(s)

    info(s, "[3] baseline snapshots")
    baseline_snapshots(s)

    info(s, "[4] optional audits/scans (explicit only)")
    run_lynis(s)
    run_rkhunter(s)
    run_chkrootkit(s)
    nmap_localhost(s)
    lan_sweep(s)
    capture_pcap(s)

    report_summary(s)
    info(s, f"{STAGE_NAME} complete", {"log": str(s.log_file), "snapshot_dir": str(s.snapshot_root)})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
