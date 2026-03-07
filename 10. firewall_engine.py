#!/usr/bin/env python3
"""
README
======

Filename:
    ztd_09_firewall_engine.py

Project:
    Zero Trust Desktop (ZTD)

Stage:
    09 — Firewall Engine

Purpose
-------
This stage prepares a conservative nftables baseline with rollback safety.

Default behavior:
    - Verifies Debian/Ubuntu-style platform
    - Updates apt metadata
    - Installs required firewall tooling if missing
    - Captures firewall/network snapshots
    - Writes a baseline nftables ruleset
    - Does NOT apply rules unless --apply is explicitly provided

Apply behavior:
    --apply                 Apply nftables ruleset
    --allow-ssh             Allow inbound SSH
    --ssh-port PORT         SSH port to allow (default: 22)
    --auto-rollback-sec N   Schedule rollback fuse after apply (default: 90)
    --cancel-rollback       Cancel previously scheduled rollback unit(s)

Safety notes
------------
- This stage does not disable or reconfigure UFW.
- This stage writes an nftables ruleset file even if you never apply it.
- When applying, a timed rollback fuse is scheduled first.
- Snapshots and logs are written under:
      ~/.local/state/zero-trust-desktop/ztd_09/

Design
------
- Safe by default
- Auditable
- Idempotent
- Location independent
- Best-effort snapshots
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
from typing import Optional, Sequence


APP_NAME = "Zero Trust Desktop"
STAGE_NAME = "09. FIREWALL ENGINE"
STAGE_ID = "ztd_09_firewall_engine"
VERSION = "1.0.0"

REQUIRED_PACKAGES = [
    "nftables",
    "iptables",
]


@dataclass(frozen=True)
class Event:
    ts: str
    level: str
    msg: str
    data: Optional[dict] = None


@dataclass(frozen=True)
class AppPaths:
    state_dir: Path
    log_dir: Path
    snapshot_dir: Path
    log_file: Path
    ruleset_file: Path
    rollback_script: Path
    rollback_unit_file: Path


@dataclass(frozen=True)
class Settings:
    yes: bool
    json_stdout: bool
    apply: bool
    allow_ssh: bool
    ssh_port: int
    auto_rollback_sec: int
    cancel_rollback: bool
    paths: AppPaths


def now_ts() -> str:
    return datetime.now().isoformat(timespec="seconds")


def have(cmd: str) -> bool:
    return shutil.which(cmd) is not None


def run_id() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def build_paths() -> AppPaths:
    rid = run_id()
    state_dir = Path.home() / ".local" / "state" / "zero-trust-desktop" / "ztd_09"
    log_dir = state_dir / "log"
    snapshot_dir = state_dir / "snapshots" / rid
    return AppPaths(
        state_dir=state_dir,
        log_dir=log_dir,
        snapshot_dir=snapshot_dir,
        log_file=log_dir / f"{STAGE_ID}_{rid}.jsonl",
        ruleset_file=snapshot_dir / "nft_ztd_baseline.nft",
        rollback_script=snapshot_dir / "rollback.sh",
        rollback_unit_file=state_dir / "rollback_unit_name.txt",
    )


def emit(settings: Settings, level: str, msg: str, data: Optional[dict] = None) -> None:
    ev = Event(ts=now_ts(), level=level, msg=msg, data=data)
    payload = json.dumps(asdict(ev), ensure_ascii=False)

    if settings.json_stdout:
        print(payload)
    else:
        print(f"[{ev.ts}] {ev.level}: {ev.msg}")

    settings.paths.log_dir.mkdir(parents=True, exist_ok=True)
    with settings.paths.log_file.open("a", encoding="utf-8") as fh:
        fh.write(payload + "\n")


def info(settings: Settings, msg: str, data: Optional[dict] = None) -> None:
    emit(settings, "INFO", msg, data)


def warn(settings: Settings, msg: str, data: Optional[dict] = None) -> None:
    emit(settings, "WARN", msg, data)


def error(settings: Settings, msg: str, data: Optional[dict] = None) -> None:
    emit(settings, "ERROR", msg, data)


def run_cmd(
    settings: Settings,
    cmd: Sequence[str],
    *,
    check: bool = True,
    use_sudo: bool = False,
) -> subprocess.CompletedProcess[str]:
    full_cmd = ["sudo", *cmd] if use_sudo else list(cmd)
    info(settings, "$ " + " ".join(full_cmd))

    proc = subprocess.run(
        full_cmd,
        text=True,
        capture_output=True,
        check=False,
    )

    if check and proc.returncode != 0:
        error(
            settings,
            "Command failed",
            {
                "rc": proc.returncode,
                "cmd": full_cmd,
                "stdout": (proc.stdout or "").strip(),
                "stderr": (proc.stderr or "").strip(),
            },
        )
        raise RuntimeError(f"Command failed: {' '.join(full_cmd)} (rc={proc.returncode})")

    return proc


def shell_capture(command: str) -> str:
    proc = subprocess.run(
        ["bash", "-lc", command],
        text=True,
        capture_output=True,
        check=False,
    )
    return (proc.stdout or proc.stderr or "").strip()


def write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content.rstrip() + "\n", encoding="utf-8", errors="ignore")


def require_supported_platform(settings: Settings) -> None:
    ok = Path("/etc/os-release").exists() and have("apt-get") and have("dpkg")
    if not ok:
        error(settings, "Unsupported platform. Debian/Ubuntu with apt-get/dpkg required.")
        raise SystemExit(2)


def validate_args(settings: Settings) -> None:
    if not (1 <= settings.ssh_port <= 65535):
        error(settings, "Invalid SSH port", {"ssh_port": settings.ssh_port})
        raise SystemExit(2)

    if settings.auto_rollback_sec < 5:
        error(settings, "Rollback fuse must be at least 5 seconds", {"seconds": settings.auto_rollback_sec})
        raise SystemExit(2)


def dpkg_installed(pkg: str) -> bool:
    proc = subprocess.run(
        ["dpkg", "-s", pkg],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return proc.returncode == 0


def apt_update(settings: Settings) -> None:
    cmd = ["apt-get", "update"]
    run_cmd(settings, cmd, use_sudo=True)


def apt_install_missing(settings: Settings, packages: Sequence[str]) -> None:
    missing = [pkg for pkg in packages if not dpkg_installed(pkg)]

    for pkg in packages:
        if pkg in missing:
            info(settings, f"Installing missing package: {pkg}")
        else:
            info(settings, f"Already installed: {pkg}")

    if not missing:
        return

    cmd = ["apt-get", "install"]
    if settings.yes:
        cmd.append("-y")
    cmd.extend(missing)
    run_cmd(settings, cmd, use_sudo=True)


def capture_snapshots(settings: Settings) -> None:
    root = settings.paths.snapshot_dir
    root.mkdir(parents=True, exist_ok=True)

    info(settings, "Capturing firewall snapshots", {"dir": str(root)})

    system_text = "\n".join(
        [
            f"{platform.system()} {platform.release()} {platform.machine()}",
            sys.version.splitlines()[0],
        ]
    )
    write_text(root / "system.txt", system_text)

    if have("ufw"):
        write_text(root / "ufw_status.txt", shell_capture("ufw status verbose || true"))

    if have("nft"):
        write_text(root / "nft_ruleset_before.txt", shell_capture("sudo nft list ruleset 2>/dev/null || true"))

    if have("iptables-save"):
        write_text(root / "iptables_save_before.txt", shell_capture("sudo iptables-save 2>/dev/null || true"))

    if have("ss"):
        write_text(root / "listening_ports.txt", shell_capture("ss -tulnp | sed -n '1,260p' || true"))

    info(settings, "Snapshots complete", {"dir": str(root)})


def build_ruleset(settings: Settings) -> str:
    optional_rules: list[str] = []

    if settings.allow_ssh:
        optional_rules.append(f"    tcp dport {settings.ssh_port} accept")

    optional_block = "\n".join(optional_rules)
    if optional_block:
        optional_block = "\n    # Optional SSH\n" + optional_block + "\n"

    return f"""#!/usr/sbin/nft -f

flush ruleset

table inet ztd {{
  chain input {{
    type filter hook input priority 0;
    policy drop;

    iif "lo" accept
    ct state established,related accept

    # DHCP client traffic
    udp sport 67 udp dport 68 accept
    udp sport 68 udp dport 67 accept

    # ICMP
    ip protocol icmp accept
    ip6 nexthdr ipv6-icmp accept{optional_block}
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
""".rstrip() + "\n"


def write_ruleset(settings: Settings) -> None:
    content = build_ruleset(settings)
    write_text(settings.paths.ruleset_file, content)
    info(settings, "Ruleset written", {"path": str(settings.paths.ruleset_file)})


def write_rollback_script(settings: Settings) -> None:
    prior_ruleset = settings.paths.snapshot_dir / "nft_ruleset_before.txt"

    if prior_ruleset.exists() and prior_ruleset.read_text(encoding="utf-8", errors="ignore").strip():
        restore_body = f"""tmp="$(mktemp)"
cat > "$tmp" <<'EOF'
{prior_ruleset.read_text(encoding="utf-8", errors="ignore")}
EOF
sudo nft -f "$tmp" || true
rm -f "$tmp"
"""
    else:
        restore_body = 'sudo nft flush ruleset || true\n'

    script = f"""#!/usr/bin/env bash
set -euo pipefail

echo "[ZTD 09] rollback start"
{restore_body}echo "[ZTD 09] rollback complete"
"""
    write_text(settings.paths.rollback_script, script)
    settings.paths.rollback_script.chmod(0o755)

    info(settings, "Rollback script written", {"path": str(settings.paths.rollback_script)})


def schedule_rollback(settings: Settings) -> None:
    if not have("systemd-run"):
        warn(settings, "systemd-run not found; rollback fuse not scheduled")
        return

    unit_name = f"ztd09-rollback-{run_id()}"
    cmd = [
        "systemd-run",
        f"--unit={unit_name}",
        f"--on-active={settings.auto_rollback_sec}s",
        "bash",
        str(settings.paths.rollback_script),
    ]
    proc = run_cmd(settings, cmd, check=False, use_sudo=True)

    if proc.returncode == 0:
        write_text(settings.paths.rollback_unit_file, unit_name)
        info(settings, "Rollback fuse scheduled", {"unit": unit_name, "seconds": settings.auto_rollback_sec})
    else:
        warn(
            settings,
            "Failed to schedule rollback fuse",
            {
                "unit": unit_name,
                "rc": proc.returncode,
                "stderr": (proc.stderr or "").strip(),
            },
        )


def cancel_rollbacks(settings: Settings) -> None:
    if not have("systemctl"):
        warn(settings, "systemctl not found; cannot cancel rollback units")
        return

    cancelled_any = False

    if settings.paths.rollback_unit_file.exists():
        unit_name = settings.paths.rollback_unit_file.read_text(encoding="utf-8", errors="ignore").strip()
        if unit_name:
            run_cmd(settings, ["systemctl", "stop", unit_name], check=False, use_sudo=True)
            run_cmd(settings, ["systemctl", "reset-failed", unit_name], check=False, use_sudo=True)
            cancelled_any = True
            info(settings, "Cancelled tracked rollback unit", {"unit": unit_name})

    grep_cmd = (
        r"systemctl list-units --all --plain --no-legend "
        r"| awk '{print $1}' "
        r"| grep -E '^ztd09-rollback-' "
        r"| xargs -r sudo systemctl stop || true"
    )
    subprocess.run(["bash", "-lc", grep_cmd], check=False)

    reset_cmd = (
        r"systemctl list-units --all --plain --no-legend "
        r"| awk '{print $1}' "
        r"| grep -E '^ztd09-rollback-' "
        r"| xargs -r sudo systemctl reset-failed || true"
    )
    subprocess.run(["bash", "-lc", reset_cmd], check=False)

    if cancelled_any:
        try:
            settings.paths.rollback_unit_file.unlink(missing_ok=True)
        except OSError:
            pass

    info(settings, "Rollback cancel pass complete")


def apply_ruleset(settings: Settings) -> None:
    if not settings.apply:
        warn(settings, "Ruleset not applied; use --apply to activate it")
        return

    if not have("nft"):
        error(settings, "nft command not found; cannot apply ruleset")
        raise SystemExit(2)

    write_rollback_script(settings)
    schedule_rollback(settings)

    info(settings, "Applying nft ruleset", {"file": str(settings.paths.ruleset_file)})
    run_cmd(settings, ["nft", "-f", str(settings.paths.ruleset_file)], use_sudo=True)

    write_text(
        settings.paths.snapshot_dir / "nft_ruleset_after.txt",
        shell_capture("sudo nft list ruleset 2>/dev/null || true"),
    )

    info(
        settings,
        "Firewall apply complete. Cancel rollback when verified.",
        {"hint": "Run again with --cancel-rollback after validation"},
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="ztd_09_firewall_engine.py")
    parser.add_argument("--yes", action="store_true", help="Use non-interactive apt install mode")
    parser.add_argument("--json", action="store_true", help="Emit JSON events to stdout")
    parser.add_argument("--apply", action="store_true", help="Apply nftables ruleset")
    parser.add_argument("--allow-ssh", action="store_true", help="Allow inbound SSH")
    parser.add_argument("--ssh-port", type=int, default=22, help="SSH port to allow if --allow-ssh is set")
    parser.add_argument("--auto-rollback-sec", type=int, default=90, help="Rollback fuse delay in seconds")
    parser.add_argument("--cancel-rollback", action="store_true", help="Cancel scheduled rollback unit(s)")
    return parser


def build_settings(args: argparse.Namespace) -> Settings:
    paths = build_paths()
    return Settings(
        yes=bool(args.yes),
        json_stdout=bool(args.json),
        apply=bool(args.apply),
        allow_ssh=bool(args.allow_ssh),
        ssh_port=int(args.ssh_port),
        auto_rollback_sec=int(args.auto_rollback_sec),
        cancel_rollback=bool(args.cancel_rollback),
        paths=paths,
    )


def main() -> int:
    args = build_parser().parse_args()
    settings = build_settings(args)

    settings.paths.snapshot_dir.mkdir(parents=True, exist_ok=True)

    require_supported_platform(settings)
    validate_args(settings)

    info(
        settings,
        f"{APP_NAME} — {STAGE_NAME} start",
        {
            "version": VERSION,
            "log_file": str(settings.paths.log_file),
            "snapshot_dir": str(settings.paths.snapshot_dir),
        },
    )

    if settings.cancel_rollback:
        info(settings, "[0] cancel rollback units")
        cancel_rollbacks(settings)

    info(settings, "[1] apt update")
    apt_update(settings)

    info(settings, "[2] install required packages")
    apt_install_missing(settings, REQUIRED_PACKAGES)

    info(settings, "[3] capture snapshots")
    capture_snapshots(settings)

    info(settings, "[4] write nft ruleset")
    write_ruleset(settings)

    info(settings, "[5] apply ruleset (optional)")
    apply_ruleset(settings)

    info(
        settings,
        f"{STAGE_NAME} complete",
        {
            "log_file": str(settings.paths.log_file),
            "snapshot_dir": str(settings.paths.snapshot_dir),
            "ruleset_file": str(settings.paths.ruleset_file),
        },
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


# =============================================================================
# INSTRUCTIONS
# =============================================================================
# Save as:
#   ztd_09_firewall_engine.py
#
# Make executable:
#   chmod +x ztd_09_firewall_engine.py
#
# Run in safe/report mode:
#   ./ztd_09_firewall_engine.py --yes
#
# Run in safe/report mode with JSON stdout:
#   ./ztd_09_firewall_engine.py --yes --json
#
# Apply baseline nftables rules with rollback fuse:
#   ./ztd_09_firewall_engine.py --yes --apply
#
# Apply baseline and allow SSH on default port 22:
#   ./ztd_09_firewall_engine.py --yes --apply --allow-ssh
#
# Apply baseline and allow SSH on a custom port:
#   ./ztd_09_firewall_engine.py --yes --apply --allow-ssh --ssh-port 2222
#
# Apply with a longer rollback fuse:
#   ./ztd_09_firewall_engine.py --yes --apply --auto-rollback-sec 180
#
# Cancel scheduled rollback after verifying connectivity:
#   ./ztd_09_firewall_engine.py --cancel-rollback
#
# Signature:
#   ZTD Stage 09 / professional rewrite / safe-default / audit-first
# =============================================================================
