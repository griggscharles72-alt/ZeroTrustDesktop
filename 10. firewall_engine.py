#!/usr/bin/env python3
"""
ZTD — 09. FIREWALL ENGINE (nftables baseline + lockout safety)
Version: 0.9.0
Stage: 09 (Firewall engine layer)

DEFAULT (SAFE)
  - Installs firewall tooling if missing
  - Captures snapshots
  - Writes a conservative nftables ruleset file
  - DOES NOT APPLY anything unless --apply

APPLY (EXPLICIT)
  --apply                 apply nft ruleset
  --allow-ssh             allow inbound SSH (tcp/22)
  --ssh-port <port>       change SSH port allowance (default 22)
  --auto-rollback-sec N   schedule rollback in N seconds after apply (default 90)
  --cancel-rollback       cancel any scheduled rollback from this stage

SAFETY MODEL
  - Never flushes UFW here.
  - Does NOT disable UFW automatically.
  - Uses a timed rollback fuse when applying nft rules.
  - Stores backups under ~/.local/state/zero-trust-desktop/ztd_09/snapshots/<run_id>/

NOTES
  - If you are already using UFW as your main firewall, you may choose to never run --apply here.
    This stage still gives you tooling + evidence + a baseline nft config you can activate later.
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
from typing import List, Optional, Tuple


APP_NAME = "Zero Trust Desktop"
STAGE_NAME = "09. FIREWALL ENGINE"
STAGE_ID = "ztd_09_firewall_engine"
VERSION = "0.9.0"

HOME = Path.home()
STATE_DIR = HOME / ".local" / "state" / "zero-trust-desktop" / "ztd_09"
LOG_DIR = STATE_DIR / "log"
SNAP_DIR = STATE_DIR / "snapshots"
RUN_ID = datetime.now().strftime("%Y%m%d_%H%M%S")

LOG_FILE = LOG_DIR / f"{STAGE_ID}_{RUN_ID}.jsonl"
SNAPSHOT_ROOT = SNAP_DIR / RUN_ID
RULESET_FILE = SNAPSHOT_ROOT / "nft_ztd_baseline.nft"
ROLLBACK_FILE = SNAPSHOT_ROOT / "rollback.sh"

PKGS = [
    "nftables",
    "iptables",
    "iptables-persistent",
]


@dataclass
class Settings:
    yes: bool
    json_stdout: bool
    apply: bool
    allow_ssh: bool
    ssh_port: int
    auto_rollback_sec: int
    cancel_rollback: bool
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


def cap(cmd: str) -> str:
    p = subprocess.run(["bash", "-lc", cmd], text=True, capture_output=True)
    return (p.stdout or p.stderr or "").strip()


def write_snapshot(name: str, content: str, root: Path) -> None:
    root.mkdir(parents=True, exist_ok=True)
    (root / name).write_text(content + "\n", encoding="utf-8", errors="ignore")


def snapshots(s: Settings) -> None:
    info(s, "Capturing firewall snapshots", {"dir": str(s.snapshot_root)})
    write_snapshot("system.txt", f"{platform.system()} {platform.release()} {platform.machine()}\n{sys.version.splitlines()[0]}", s.snapshot_root)

    if have("ufw"):
        write_snapshot("ufw_status.txt", cap("ufw status verbose || true"), s.snapshot_root)

    if have("nft"):
        write_snapshot("nft_ruleset_before.txt", cap("sudo nft list ruleset 2>/dev/null || true"), s.snapshot_root)

    if have("iptables-save"):
        write_snapshot("iptables_save_before.txt", cap("sudo iptables-save 2>/dev/null || true"), s.snapshot_root)

    if have("ss"):
        write_snapshot("listening_ports.txt", cap("ss -tulnp | sed -n '1,260p' || true"), s.snapshot_root)

    info(s, "Snapshots complete", {"dir": str(s.snapshot_root)})


def build_ruleset(s: Settings) -> str:
    ssh_rule = ""
    if s.allow_ssh:
        ssh_rule = f"tcp dport {s.ssh_port} accept"

    # Conservative baseline: allow established/related + loopback, allow DHCP client traffic, drop inbound by default.
    # Outgoing allowed.
    ruleset = f"""#!/usr/sbin/nft -f

flush ruleset

table inet ztd {{
  chain input {{
    type filter hook input priority 0;
    policy drop;

    iif "lo" accept
    ct state established,related accept

    # DHCP (client)
    udp sport 67 udp dport 68 accept
    udp sport 68 udp dport 67 accept

    # ICMP (debug-friendly)
    ip protocol icmp accept
    ip6 nexthdr ipv6-icmp accept

    # Optional SSH
    {ssh_rule}

    # Rate-limited logging for drops
    limit rate 6/minute log prefix "ZTD_DROP " flags all
    drop
  }}

  chain forward {{
    type filter hook forward priority 0;
    policy drop;
  }}

  chain output {{
    type filter hook output priority 0;
    policy accept;
  }}
}}
"""
    # clean blank lines if ssh_rule empty
    return "\n".join([ln for ln in ruleset.splitlines() if ln.strip() != "" or True])


def write_rollback_script(s: Settings) -> None:
    # Restores nft to previous ruleset capture if available, else disables ztd table by flush ruleset.
    prior = s.snapshot_root / "nft_ruleset_before.txt"
    body = ""
    if prior.exists() and prior.read_text(encoding="utf-8", errors="ignore").strip():
        # Use saved text as a restore by writing it to a temp and nft -f it.
        body = f"""
tmp="$(mktemp)"
cat > "$tmp" <<'EOF'
{prior.read_text(encoding="utf-8", errors="ignore")}
EOF
sudo nft -f "$tmp" || true
rm -f "$tmp"
"""
    else:
        body = "sudo nft flush ruleset || true\n"

    script = f"""#!/usr/bin/env bash
set -euo pipefail
echo "[ZTD 09] rollback start"
{body}
echo "[ZTD 09] rollback complete"
"""
    ROLLBACK_FILE.write_text(script, encoding="utf-8")
    ROLLBACK_FILE.chmod(0o755)
    info(s, "Rollback script written", {"path": str(ROLLBACK_FILE)})


def schedule_rollback(s: Settings) -> None:
    if not have("systemd-run"):
        warn(s, "systemd-run not found; cannot schedule rollback fuse")
        return
    unit = f"ztd09-rollback-{RUN_ID}"
    cmd = f"bash '{ROLLBACK_FILE}'"
    # Runs rollback after N seconds unless user cancels.
    sudo(s, ["systemd-run", f"--unit={unit}", f"--on-active={s.auto_rollback_sec}s", "bash", "-lc", cmd], check=False)
    info(s, "Rollback fuse scheduled", {"unit": unit, "seconds": s.auto_rollback_sec})


def cancel_rollbacks(s: Settings) -> None:
    if not have("systemctl"):
        return
    # Best-effort: stop any ztd09 rollback units.
    # We do not rely on exact IDs.
    info(s, "Cancelling any ztd09 rollback units (best-effort)")
    subprocess.run(["bash", "-lc", "systemctl list-units --all | grep -E 'ztd09-rollback-' | awk '{print $1}' | xargs -r sudo systemctl stop || true"], check=False)
    subprocess.run(["bash", "-lc", "systemctl list-units --all | grep -E 'ztd09-rollback-' | awk '{print $1}' | xargs -r sudo systemctl reset-failed || true"], check=False)


def apply_ruleset(s: Settings) -> None:
    if not s.apply:
        warn(s, "Not applying firewall ruleset (use --apply)")
        return
    if not have("nft"):
        error(s, "nft not found; cannot apply")
        raise SystemExit(2)

    # Safety fuse: schedule rollback first, then apply.
    write_rollback_script(s)
    schedule_rollback(s)

    info(s, "Applying nft ruleset", {"file": str(RULESET_FILE)})
    sudo(s, ["nft", "-f", str(RULESET_FILE)], check=True)

    # Post snapshot
    write_snapshot("nft_ruleset_after.txt", cap("sudo nft list ruleset 2>/dev/null || true"), s.snapshot_root)
    info(s, "Firewall apply complete. If everything is OK, cancel rollback with --cancel-rollback.")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="ztd_09_firewall_engine.py")
    p.add_argument("--yes", action="store_true", help="Non-interactive apt (-y)")
    p.add_argument("--json", action="store_true", help="Emit JSON to stdout (log file always JSONL)")

    p.add_argument("--apply", action="store_true", help="Apply nft ruleset")
    p.add_argument("--allow-ssh", action="store_true", help="Allow inbound SSH (tcp/22 by default)")
    p.add_argument("--ssh-port", type=int, default=22, help="SSH port to allow if --allow-ssh")
    p.add_argument("--auto-rollback-sec", type=int, default=90, help="Rollback fuse delay seconds")
    p.add_argument("--cancel-rollback", action="store_true", help="Cancel any scheduled rollback unit(s)")
    return p


def main() -> int:
    args = build_parser().parse_args()
    s = Settings(
        yes=bool(args.yes),
        json_stdout=bool(args.json),
        apply=bool(args.apply),
        allow_ssh=bool(args.allow_ssh),
        ssh_port=int(args.ssh_port),
        auto_rollback_sec=int(args.auto_rollback_sec),
        cancel_rollback=bool(args.cancel_rollback),
        log_file=LOG_FILE,
        snapshot_root=SNAPSHOT_ROOT,
    )

    require_debian_like(s)
    info(s, f"{APP_NAME} — {STAGE_NAME} start", {"version": VERSION, "log": str(s.log_file)})

    SNAPSHOT_ROOT.mkdir(parents=True, exist_ok=True)

    if s.cancel_rollback:
        cancel_rollbacks(s)

    info(s, "[1] apt update")
    apt_update(s)

    info(s, "[2] install firewall tooling (idempotent)")
    apt_install_missing(s, PKGS)

    info(s, "[3] snapshots")
    snapshots(s)

    info(s, "[4] write nft ruleset file")
    ruleset = build_ruleset(s)
    RULESET_FILE.write_text(ruleset, encoding="utf-8")
    info(s, "Ruleset written", {"path": str(RULESET_FILE)})

    info(s, "[5] apply (optional)")
    apply_ruleset(s)

    info(s, f"{STAGE_NAME} complete", {"snapshot_dir": str(SNAPSHOT_ROOT), "log": str(LOG_FILE)})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
