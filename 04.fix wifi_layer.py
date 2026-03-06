```python
#!/usr/bin/env python3
"""
ZTD — 04. WIFI LAYER (SAFE / IDEMPOTENT / REPAIRABLE)
Version: 0.2.1
Suite: Zero Trust Desktop
Stage: 04 (Wi-Fi / Network Stability + Privacy + Reporting)

DEFAULT BEHAVIOR (SAFE)
  - apt-get update
  - install missing Wi-Fi + diagnostic packages
  - status report (nmcli/ip/resolvectl + driver/firmware hints)

OPTIONAL BEHAVIOR CHANGES (FLAGS)
  --upgrade               apt-get upgrade (can change system behavior; explicit)
  --apply-nm-defaults     write /etc/NetworkManager/conf.d/99-ztd-wifi.conf
  --restart-nm            restart NetworkManager (brief drop possible)
  --flush-dns             resolvectl flush-caches
  --toggle-networking     nmcli networking off/on (repair)
  --rfkill-unblock        rfkill unblock wifi
  --restart-wpa           restart wpa_supplicant (repair)
  --set-regdom US         set Wi-Fi reg set (must be correct country)
  --capture-logs          print tail of NetworkManager logs for troubleshooting
  --install-optional      install optional tools (nmap)

NOTES
  - Debian/Ubuntu only (apt-get/dpkg/NetworkManager).
  - No firewall changes. No port controls. Dev-safe layer.
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
from typing import Iterable, List, Optional, Tuple, Dict, Any


APP_NAME = "Zero Trust Desktop"
APP_ID = "ztd"
STAGE_NAME = "04. WIFI LAYER"
STAGE_ID = "ztd_04_wifi_layer"
VERSION = "0.2.1"

HOME = Path.home()
STATE_DIR = HOME / ".local" / "state" / "zero-trust-desktop" / "ztd_04"
LOG_DIR = STATE_DIR / "log"
RUN_ID = datetime.now().strftime("%Y%m%d_%H%M%S")
LOG_FILE = LOG_DIR / f"{STAGE_ID}_{RUN_ID}.jsonl"

NM_CONF_DIR = Path("/etc/NetworkManager/conf.d")
NM_ZTD_CONF = NM_CONF_DIR / "99-ztd-wifi.conf"

PKGS_WIFI = ["network-manager", "wireless-tools", "iw", "rfkill"]
PKGS_DIAG = ["dnsutils", "iproute2", "traceroute", "mtr-tiny"]
PKGS_OPTIONAL = ["nmap"]


@dataclass
class Settings:
    yes: bool
    json_stdout: bool

    upgrade: bool
    install_optional: bool

    apply_nm_defaults: bool
    mac_policy: str
    disable_wifi_powersave: bool
    force_resolved_dns: bool

    restart_nm: bool
    flush_dns: bool
    toggle_networking: bool
    rfkill_unblock: bool
    restart_wpa: bool

    set_regdom: Optional[str]
    capture_logs: bool

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


def is_root() -> bool:
    return os.geteuid() == 0


def emit(s: Settings, ev: Event) -> None:
    line = json.dumps(asdict(ev), ensure_ascii=False)
    if s.json_stdout:
        print(line)
    else:
        print(f"[{ev.ts}] {ev.level}: {ev.msg}")
        if ev.data:
            print(json.dumps(ev.data, indent=2, ensure_ascii=False))

    s.log_file.parent.mkdir(parents=True, exist_ok=True)
    with s.log_file.open("a", encoding="utf-8") as f:
        f.write(line + "\n")


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
    if is_root():
        return run(s, cmd, check=check)
    if not have("sudo"):
        error(s, "sudo is required when not running as root")
        raise SystemExit(2)
    return run(s, ["sudo"] + cmd, check=check)


def require_debian_like(s: Settings) -> None:
    if not (Path("/etc/os-release").exists() and have("apt-get") and have("dpkg")):
        error(s, "Unsupported platform. Debian/Ubuntu with apt-get/dpkg required.")
        raise SystemExit(2)


def dpkg_installed(pkg: str) -> bool:
    p = subprocess.run(
        ["dpkg", "-s", pkg],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return p.returncode == 0


def apt_update(s: Settings) -> None:
    sudo(s, ["apt-get", "update"])


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


def write_nm_defaults(s: Settings) -> None:
    if not s.apply_nm_defaults:
        return

    if not NM_CONF_DIR.exists():
        warn(s, "NetworkManager conf.d directory not found; is NetworkManager installed?")
        return

    mac = s.mac_policy.lower().strip()
    if mac not in ("stable", "random"):
        error(s, "Invalid mac_policy", {"value": mac})
        raise SystemExit(2)

    lines: List[str] = [
        "# Managed by ZTD (Wi-Fi Layer)",
        "[device]",
        "wifi.scan-rand-mac-address=yes",
        "",
        "[connection]",
        f"wifi.cloned-mac-address={mac}",
    ]

    if s.disable_wifi_powersave:
        lines.append("wifi.powersave=2")

    lines.append("")

    if s.force_resolved_dns:
        lines.extend([
            "[main]",
            "dns=systemd-resolved",
            "rc-manager=symlink",
            "",
        ])

    content = "\n".join(lines).rstrip() + "\n"

    info(
        s,
        f"Writing NetworkManager defaults: {NM_ZTD_CONF}",
        {
            "mac_policy": mac,
            "disable_wifi_powersave": s.disable_wifi_powersave,
            "force_resolved_dns": s.force_resolved_dns,
        },
    )

    tmp = Path("/tmp") / f"{NM_ZTD_CONF.name}.{RUN_ID}"
    try:
        tmp.write_text(content, encoding="utf-8")
        sudo(s, ["install", "-m", "0644", str(tmp), str(NM_ZTD_CONF)], check=True)
    finally:
        try:
            tmp.unlink(missing_ok=True)
        except Exception:
            pass


def do_repairs(s: Settings) -> None:
    if s.rfkill_unblock and have("rfkill"):
        info(s, "rfkill unblock wifi")
        sudo(s, ["rfkill", "unblock", "wifi"], check=False)

    if s.set_regdom:
        cc = s.set_regdom.strip().upper()
        if have("iw"):
            info(s, f"Setting Wi-Fi regulatory domain: {cc} (must be correct country code)")
            sudo(s, ["iw", "reg", "set", cc], check=False)
        else:
            warn(s, "iw not found; cannot set reg domain")

    if s.flush_dns and have("resolvectl"):
        info(s, "Flushing DNS cache (resolvectl flush-caches)")
        sudo(s, ["resolvectl", "flush-caches"], check=False)

    if s.restart_wpa:
        info(s, "Restarting wpa_supplicant (best-effort)")
        sudo(s, ["systemctl", "restart", "wpa_supplicant"], check=False)

    if s.toggle_networking and have("nmcli"):
        info(s, "Toggling networking OFF/ON (last-resort repair)")
        sudo(s, ["nmcli", "networking", "off"], check=False)
        sudo(s, ["nmcli", "networking", "on"], check=False)

    if s.restart_nm:
        info(s, "Restarting NetworkManager (may drop connection briefly)")
        sudo(s, ["systemctl", "restart", "NetworkManager"], check=False)


def _cap(cmd: List[str]) -> str:
    p = subprocess.run(cmd, text=True, capture_output=True)
    return (p.stdout or p.stderr or "").strip()


def gather_status(s: Settings) -> Dict[str, Any]:
    report: Dict[str, Any] = {
        "app": APP_ID,
        "stage": STAGE_ID,
        "version": VERSION,
        "system": f"{platform.system()} {platform.release()}",
        "arch": platform.machine(),
        "python": sys.version.splitlines()[0],
        "nm_conf": str(NM_ZTD_CONF) if NM_ZTD_CONF.exists() else "not-present",
        "log": str(s.log_file),
    }

    report["nmcli_general"] = _cap(["nmcli", "general", "status"]) if have("nmcli") else None
    report["nmcli_radio"] = _cap(["nmcli", "radio"]) if have("nmcli") else None
    report["nmcli_device"] = _cap(["nmcli", "device", "status"]) if have("nmcli") else None
    report["nmcli_active"] = _cap(["nmcli", "connection", "show", "--active"]) if have("nmcli") else None
    report["wifi_list_top20"] = (
        _cap(["bash", "-lc", "nmcli -f IN-USE,SSID,SECURITY,SIGNAL,RATE,BARS device wifi list | head -n 21"])
        if have("nmcli") else None
    )

    report["ip_addr_brief"] = _cap(["bash", "-lc", "ip -br addr"]) if have("ip") else None
    report["ip_route"] = _cap(["ip", "route"]) if have("ip") else None
    report["iw_dev"] = _cap(["bash", "-lc", "iw dev || true"]) if have("iw") else None

    if have("resolvectl"):
        report["dns_status"] = _cap(["bash", "-lc", "resolvectl status | head -n 80"])
    else:
        report["dns_status"] = _cap(["bash", "-lc", "cat /etc/resolv.conf 2>/dev/null | head -n 40 || true"])

    vpn_if = _cap(["bash", "-lc", "ip -o link show | awk -F': ' '{print $2}' | egrep '^(tun|wg|proton)' || true"])
    default_route = _cap(["bash", "-lc", "ip route show default || true"])
    report["vpn_heuristic"] = {
        "vpn_like_interfaces": vpn_if.splitlines() if vpn_if else [],
        "default_route": default_route,
    }

    if s.capture_logs and have("journalctl"):
        report["networkmanager_logs_tail"] = _cap(
            ["bash", "-lc", "journalctl -u NetworkManager -b --no-pager | tail -n 200 || true"]
        )

    return report


def status_report(s: Settings) -> None:
    report = gather_status(s)
    info(s, "Status report", report)

    if s.json_stdout:
        return

    def section(title: str, value: Optional[str]) -> None:
        print(f"\n--- {title} ---")
        print(value if value else "(not available)")

    section("nmcli general", report.get("nmcli_general"))
    section("nmcli radio", report.get("nmcli_radio"))
    section("nmcli device", report.get("nmcli_device"))
    section("active connections", report.get("nmcli_active"))
    section("wifi list (top 20)", report.get("wifi_list_top20"))
    section("ip addr (brief)", report.get("ip_addr_brief"))
    section("ip route", report.get("ip_route"))
    section("iw dev", report.get("iw_dev"))
    section("dns status", report.get("dns_status"))

    print("\n--- vpn heuristic ---")
    print(json.dumps(report.get("vpn_heuristic", {}), indent=2, ensure_ascii=False))

    if s.capture_logs:
        section("NetworkManager logs (tail)", report.get("networkmanager_logs_tail"))


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="04_wifi_layer.py")
    p.add_argument("--yes", action="store_true", help="Non-interactive apt (-y)")
    p.add_argument("--json", action="store_true", help="Emit JSON events to stdout (log always JSONL)")

    p.add_argument("--upgrade", action="store_true", help="Run apt-get upgrade (explicit)")
    p.add_argument("--install-optional", action="store_true", help="Install optional tooling (includes nmap)")

    p.add_argument("--apply-nm-defaults", action="store_true", help="Write NetworkManager defaults config")
    p.add_argument("--mac-policy", choices=["stable", "random"], default="stable", help="MAC policy")
    p.add_argument("--no-disable-powersave", action="store_true", help="Do NOT disable Wi-Fi powersave")
    p.add_argument("--no-force-resolved-dns", action="store_true", help="Do NOT force systemd-resolved DNS integration")

    p.add_argument("--restart-nm", action="store_true", help="Restart NetworkManager")
    p.add_argument("--flush-dns", action="store_true", help="Flush DNS cache")
    p.add_argument("--toggle-networking", action="store_true", help="nmcli networking off/on")
    p.add_argument("--rfkill-unblock", action="store_true", help="rfkill unblock wifi")
    p.add_argument("--restart-wpa", action="store_true", help="Restart wpa_supplicant")

    p.add_argument("--set-regdom", default=None, help="Set Wi-Fi regulatory domain (e.g. US, MX) - must be correct")
    p.add_argument("--capture-logs", action="store_true", help="Print tail of NetworkManager logs")

    return p


def main() -> int:
    args = build_parser().parse_args()

    s = Settings(
        yes=bool(args.yes),
        json_stdout=bool(args.json),

        upgrade=bool(args.upgrade),
        install_optional=bool(args.install_optional),

        apply_nm_defaults=bool(args.apply_nm_defaults),
        mac_policy=str(args.mac_policy),
        disable_wifi_powersave=not bool(args.no_disable_powersave),
        force_resolved_dns=not bool(args.no_force_resolved_dns),

        restart_nm=bool(args.restart_nm),
        flush_dns=bool(args.flush_dns),
        toggle_networking=bool(args.toggle_networking),
        rfkill_unblock=bool(args.rfkill_unblock),
        restart_wpa=bool(args.restart_wpa),

        set_regdom=(str(args.set_regdom).strip() if args.set_regdom else None),
        capture_logs=bool(args.capture_logs),

        log_file=LOG_FILE,
    )

    require_debian_like(s)
    info(s, f"{APP_NAME} — {STAGE_NAME} start", {"version": VERSION, "log": str(s.log_file)})

    info(s, "[1] apt-get update")
    apt_update(s)

    if s.upgrade:
        info(s, "[1b] apt-get upgrade (explicit)")
        apt_upgrade(s)

    info(s, "[2] install Wi-Fi tooling (idempotent)")
    apt_install_missing(s, PKGS_WIFI)

    info(s, "[3] install diagnostics (idempotent)")
    apt_install_missing(s, PKGS_DIAG)

    if s.install_optional:
        info(s, "[4] install optional tooling (idempotent)")
        apt_install_missing(s, PKGS_OPTIONAL)

    if s.apply_nm_defaults:
        info(s, "[5] apply NetworkManager defaults")
        write_nm_defaults(s)

    info(s, "[6] repair actions (optional flags)")
    do_repairs(s)

    status_report(s)
    info(s, f"{STAGE_NAME} complete", {"log": str(s.log_file)})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

## Recommended execution patterns

Safe default run:

```bash
python3 04_wifi_layer.py --yes
```

Apply sane NM defaults and print logs:

```bash
python3 04_wifi_layer.py --yes --apply-nm-defaults --capture-logs
```

Repair sweep:

```bash
python3 04_wifi_layer.py --yes --rfkill-unblock --flush-dns --restart-wpa --restart-nm
```

Structured output mode:

```bash
python3 04_wifi_layer.py --yes --json > wifi_run.jsonl
```

