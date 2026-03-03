#!/usr/bin/env python3
"""
ZTD — 10. RELEASE RUNNER (ONE-COMMAND ORCHESTRATION)
Version: 1.0.0
Stage: 10 (Repo finalizer)

Purpose
  - Provide a single entrypoint to run and verify the ZTD stack in order
  - Bundle logs/snapshots for evidence + troubleshooting

Usage
  python3 ztd_10_release_runner.py status
  python3 ztd_10_release_runner.py run --yes --plan dev
  python3 ztd_10_release_runner.py bundle

Plans
  dev:    Python + VS Code + Security baseline + Wi-Fi + Observe/Defense + Firewall tools (no apply)
  harden: Same, but also applies Stage 09 firewall with SSH allow + rollback fuse

Notes
  - This runner assumes stage scripts live in the same folder as this file.
  - It does not embed the stages; it invokes them.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import subprocess
import sys
import tarfile
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional

HOME = Path.home()
ZTD_STATE = HOME / ".local" / "state" / "zero-trust-desktop"
RUN_ID = datetime.now().strftime("%Y%m%d_%H%M%S")

HERE = Path(__file__).resolve().parent
BUNDLE_OUT = HERE / f"ztd_bundle_{RUN_ID}.tar.gz"


@dataclass
class Stage:
    id: str
    file: str
    args: List[str]


def have_python() -> bool:
    return sys.version_info >= (3, 10)


def run_stage(stage: Stage) -> int:
    script = HERE / stage.file
    if not script.exists():
        print(f"[missing] {stage.id}: {script}")
        return 2
    cmd = ["python3", str(script)] + stage.args
    print("\n$ " + " ".join(cmd))
    p = subprocess.run(cmd)
    return p.returncode


def stage_plan(plan: str, yes: bool) -> List[Stage]:
    y = ["--yes"] if yes else []

    # Adjust filenames to match what you actually keep in repo.
    # You already have: ztd_01_full_security_stack_check.py and Wi-Fi layer script name on your side.
    stages: List[Stage] = [
        Stage("00_python_provision", "zero_python_provision.py", y + ["bootstrap", "--profile", "dev"]),
        Stage("00_vscode", "ztd_00_vscode_setup.py", y),  # you said you’re adding this as a separate 00
        Stage("01_security", "ztd_01_full_security_stack_check.py", y),
        Stage("wifi_layer", "ztd_wifi_layer.py", y),  # rename to your actual wifi script name
        Stage("08_defense_observe", "ztd_08_defense_observe.py", y),
        Stage("09_firewall_engine", "ztd_09_firewall_engine.py", y),
    ]

    if plan == "harden":
        # Apply firewall conservatively with rollback fuse + SSH allowed
        stages = [s if s.id != "09_firewall_engine"
                  else Stage("09_firewall_engine", "ztd_09_firewall_engine.py", y + ["--apply", "--allow-ssh"])
                  for s in stages]
    return stages


def cmd_status() -> int:
    print(f"System: {platform.system()} {platform.release()} ({platform.machine()})")
    print(f"Python: {sys.version.splitlines()[0]}")
    print(f"ZTD state dir: {ZTD_STATE}")
    print("Recent stage dirs:")
    if ZTD_STATE.exists():
        for p in sorted(ZTD_STATE.glob("ztd_*"))[:30]:
            if p.is_dir():
                print(" -", p.name)
    return 0


def cmd_run(plan: str, yes: bool) -> int:
    if not have_python():
        print("Python 3.10+ required.")
        return 2

    stages = stage_plan(plan=plan, yes=yes)
    print(f"[ZTD 10] plan={plan} yes={yes} stages={len(stages)}")

    for st in stages:
        rc = run_stage(st)
        if rc != 0:
            print(f"[ZTD 10] STOP: stage={st.id} rc={rc}")
            return rc

    print("[ZTD 10] complete")
    return 0


def cmd_bundle() -> int:
    if not ZTD_STATE.exists():
        print("No ZTD state dir found; nothing to bundle.")
        return 2

    with tarfile.open(BUNDLE_OUT, "w:gz") as tf:
        tf.add(ZTD_STATE, arcname="zero-trust-desktop-state")
        # also include stage scripts for reproducibility
        for py in HERE.glob("*.py"):
            tf.add(py, arcname=f"repo/{py.name}")

    print(f"Bundle created: {BUNDLE_OUT}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(prog="ztd_10_release_runner.py")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("status")

    r = sub.add_parser("run")
    r.add_argument("--plan", choices=["dev", "harden"], default="dev")
    r.add_argument("--yes", action="store_true")

    sub.add_parser("bundle")

    args = ap.parse_args()

    if args.cmd == "status":
        return cmd_status()
    if args.cmd == "run":
        return cmd_run(plan=str(args.plan), yes=bool(args.yes))
    if args.cmd == "bundle":
        return cmd_bundle()

    return 2


if __name__ == "__main__":
    raise SystemExit(main())
