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
    - Does NOT show the topper unless --topper is explicitly provided

Apply behavior:
    --apply                 Apply nftables ruleset
    --allow-ssh             Allow inbound SSH
    --ssh-port PORT         SSH port to allow (default: 22)
    --auto-rollback-sec N   Schedule rollback fuse after apply (default: 90)
    --cancel-rollback       Cancel previously scheduled rollback unit(s)

Optional UI behavior:
    --topper                Enable terminal intro topper
    --topper-design NAME    Select topper design or use random
    --topper-seconds N      Total topper runtime target
    --topper-countdown N    Countdown seconds

Safety notes
------------
- This stage does not disable or reconfigure UFW.
- This stage writes an nftables ruleset file even if you never apply it.
- When applying, a timed rollback fuse is scheduled first.
- The topper is cosmetic only and auto-skips in unsafe/non-interactive terminals.
- Snapshots and logs are written under:
      ~/.local/state/zero-trust-desktop/ztd_09/

Design
------
- Safe by default
- Auditable
- Idempotent
- Location independent
- Best-effort snapshots
- Optional isolated terminal UI
"""

from __future__ import annotations

import argparse
import json
import math
import os
import platform
import random
import shutil
import subprocess
import sys
import time
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Callable, Optional, Sequence


APP_NAME = "Zero Trust Desktop"
STAGE_NAME = "09. FIREWALL ENGINE"
STAGE_ID = "ztd_09_firewall_engine"
VERSION = "1.1.0"

REQUIRED_PACKAGES = [
    "nftables",
    "iptables",
]

# =============================================================================
# OPTIONAL TOPPER / ANSI CONSTANTS
# =============================================================================

ANSI_RESET = "\033[0m"
ANSI_BOLD = "\033[1m"
ANSI_DIM = "\033[2m"

ANSI_BLACK = "\033[30m"
ANSI_RED = "\033[31m"
ANSI_GREEN = "\033[32m"
ANSI_YELLOW = "\033[33m"
ANSI_BLUE = "\033[34m"
ANSI_MAGENTA = "\033[35m"
ANSI_CYAN = "\033[36m"
ANSI_WHITE = "\033[37m"

ANSI_BRIGHT_BLACK = "\033[90m"
ANSI_BRIGHT_RED = "\033[91m"
ANSI_BRIGHT_GREEN = "\033[92m"
ANSI_BRIGHT_YELLOW = "\033[93m"
ANSI_BRIGHT_BLUE = "\033[94m"
ANSI_BRIGHT_MAGENTA = "\033[95m"
ANSI_BRIGHT_CYAN = "\033[96m"
ANSI_BRIGHT_WHITE = "\033[97m"

ANSI_HIDE_CURSOR = "\033[?25l"
ANSI_SHOW_CURSOR = "\033[?25h"
ANSI_ALTSCREEN_ON = "\033[?1049h"
ANSI_ALTSCREEN_OFF = "\033[?1049l"
ANSI_CLEAR = "\033[2J\033[H"


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
    topper: bool
    topper_design: str
    topper_seconds: float
    topper_countdown: int
    paths: AppPaths


# =============================================================================
# GENERIC HELPERS
# =============================================================================

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
    event = Event(ts=now_ts(), level=level, msg=msg, data=data)
    payload = json.dumps(asdict(event), ensure_ascii=False)

    if settings.json_stdout:
        print(payload)
    else:
        print(f"[{event.ts}] {event.level}: {event.msg}")

    settings.paths.log_dir.mkdir(parents=True, exist_ok=True)
    with settings.paths.log_file.open("a", encoding="utf-8") as handle:
        handle.write(payload + "\n")


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


# =============================================================================
# OPTIONAL TOPPER SAFETY
# =============================================================================

def _is_safe_interactive_terminal() -> bool:
    try:
        if os.name != "posix":
            return False
        if not sys.stdout.isatty():
            return False
        if not sys.stdin.isatty():
            return False
        term = os.environ.get("TERM", "").strip().lower()
        if not term or term == "dumb":
            return False
        return True
    except Exception:
        return False


def _topper_write(text: str) -> None:
    sys.stdout.write(text)
    sys.stdout.flush()


def _move_home() -> None:
    _topper_write("\033[H")


def _clear() -> None:
    _topper_write(ANSI_CLEAR)


def _cursor_to(row: int, col: int) -> None:
    _topper_write(f"\033[{row};{col}H")


@contextmanager
def _terminal_overlay():
    entered = False
    try:
        _topper_write(ANSI_ALTSCREEN_ON)
        _topper_write(ANSI_HIDE_CURSOR)
        _topper_write(ANSI_CLEAR)
        entered = True
        yield
    finally:
        try:
            if entered:
                _topper_write(ANSI_RESET)
                _topper_write(ANSI_SHOW_CURSOR)
                _topper_write(ANSI_ALTSCREEN_OFF)
            else:
                _topper_write(ANSI_RESET + ANSI_SHOW_CURSOR)
        except Exception:
            pass


def _term_size() -> tuple[int, int]:
    try:
        size = shutil.get_terminal_size(fallback=(100, 30))
        return max(40, size.columns), max(16, size.lines)
    except Exception:
        return 100, 30


def _fit_text(text: str, width: int) -> str:
    return text[: max(0, width)]


def _center(text: str, width: int) -> str:
    if len(text) >= width:
        return text[:width]
    left = (width - len(text)) // 2
    return (" " * left) + text


def _binary_line(width: int) -> str:
    return "".join(random.choice("01") for _ in range(width))


def _hex_line(width: int) -> str:
    alphabet = "0123456789ABCDEF"
    return "".join(random.choice(alphabet) for _ in range(width))


def _glyph_line(width: int, glyphs: str) -> str:
    return "".join(random.choice(glyphs) for _ in range(width))


def _make_frame(title: str, subtitle: str, width: int, color: str) -> str:
    inner = max(20, width - 2)
    top = f"{color}┌" + ("─" * (inner - 2)) + f"┐{ANSI_RESET}"
    mid1 = f"{color}│{ANSI_RESET}" + _center(title, inner - 2) + f"{color}│{ANSI_RESET}"
    mid2 = f"{color}│{ANSI_RESET}" + _center(subtitle, inner - 2) + f"{color}│{ANSI_RESET}"
    bot = f"{color}└" + ("─" * (inner - 2)) + f"┘{ANSI_RESET}"
    return "\n".join([top, mid1, mid2, bot])


def _sleep_or_break(duration: float) -> None:
    if duration > 0:
        time.sleep(duration)


def _render_countdown(width: int, countdown: int, color: str, title: str) -> None:
    for i in range(countdown, 0, -1):
        _move_home()
        _clear()
        print()
        print(_center(f"{color}{ANSI_BOLD}{title}{ANSI_RESET}", width))
        print()
        print(_center(f"{color}System arm in {i}...{ANSI_RESET}", width))
        print()
        print(_center(f"{color}[{'#' * (countdown - i)}{'-' * i}]{ANSI_RESET}", width))
        _sleep_or_break(1.0)


# =============================================================================
# TOPPER DESIGNS
# =============================================================================

def _design_01_matrix(width: int, height: int, frames: int, frame_sleep: float) -> None:
    for _ in range(frames):
        _move_home()
        print(_center(f"{ANSI_BRIGHT_GREEN}{ANSI_BOLD}GHOST PROTOCOL // MATRIX VEIL{ANSI_RESET}", width))
        for _row in range(height - 4):
            print(f"{ANSI_GREEN}{_binary_line(width)}{ANSI_RESET}")
        _sleep_or_break(frame_sleep)


def _design_02_hexstorm(width: int, height: int, frames: int, frame_sleep: float) -> None:
    for _ in range(frames):
        _move_home()
        print(_center(f"{ANSI_BRIGHT_CYAN}{ANSI_BOLD}HEX STORM / SECTOR SCAN{ANSI_RESET}", width))
        print(_center(f"{ANSI_CYAN}ADDR BUS // MEMORY SWEEP // HASH GRID{ANSI_RESET}", width))
        for _row in range(height - 5):
            print(f"{ANSI_CYAN}{_hex_line(width)}{ANSI_RESET}")
        _sleep_or_break(frame_sleep)


def _design_03_waveform(width: int, height: int, frames: int, frame_sleep: float) -> None:
    usable_rows = max(8, height - 6)
    for t in range(frames):
        _move_home()
        print(_center(f"{ANSI_BRIGHT_BLUE}{ANSI_BOLD}SIGNAL WAVEFORM / PHASE LOCK{ANSI_RESET}", width))
        print(_center(f"{ANSI_BLUE}carrier sync stabilizing{ANSI_RESET}", width))
        canvas = [[" " for _ in range(width)] for _ in range(usable_rows)]
        for x in range(width):
            y = int((usable_rows / 2) + math.sin((x / 6.0) + (t / 2.0)) * (usable_rows / 3))
            y = max(0, min(usable_rows - 1, y))
            canvas[y][x] = "•"
        for row in canvas:
            print(f"{ANSI_BRIGHT_BLUE}{''.join(row)}{ANSI_RESET}")
        _sleep_or_break(frame_sleep)


def _design_04_radar(width: int, height: int, frames: int, frame_sleep: float) -> None:
    usable_rows = max(10, height - 5)
    cx = width // 2
    cy = usable_rows // 2
    radius = min(cx - 2, cy - 1, 14)
    for t in range(frames):
        _move_home()
        print(_center(f"{ANSI_BRIGHT_GREEN}{ANSI_BOLD}RADAR SWEEP / GHOST FIELD{ANSI_RESET}", width))
        grid = [[" " for _ in range(width)] for _ in range(usable_rows)]
        for ang in range(0, 360, 6):
            x = cx + int(radius * math.cos(math.radians(ang)))
            y = cy + int(radius * math.sin(math.radians(ang)))
            if 0 <= x < width and 0 <= y < usable_rows:
                grid[y][x] = "·"
        sweep_angle = (t * 18) % 360
        for r in range(radius):
            x = cx + int(r * math.cos(math.radians(sweep_angle)))
            y = cy + int(r * math.sin(math.radians(sweep_angle)))
            if 0 <= x < width and 0 <= y < usable_rows:
                grid[y][x] = "*"
        for _ in range(8):
            x = random.randint(max(0, cx - radius), min(width - 1, cx + radius))
            y = random.randint(max(0, cy - radius), min(usable_rows - 1, cy + radius))
            grid[y][x] = "x"
        for row in grid:
            print(f"{ANSI_GREEN}{''.join(row)}{ANSI_RESET}")
        _sleep_or_break(frame_sleep)


def _design_05_glitch_banner(width: int, height: int, frames: int, frame_sleep: float) -> None:
    lines = [
        "██████   ██   ██  ██████  ███████ ████████",
        "██       ██   ██ ██    ██ ██         ██   ",
        "██  ███  ███████ ██    ██ ███████    ██   ",
        "██   ██  ██   ██ ██    ██      ██    ██   ",
        " █████   ██   ██  ██████  ███████    ██   ",
    ]
    noise = "!@#$%^&*()_+-=[]{}<>?/|"
    for t in range(frames):
        _move_home()
        print()
        color = random.choice([ANSI_BRIGHT_MAGENTA, ANSI_BRIGHT_CYAN, ANSI_BRIGHT_RED, ANSI_BRIGHT_GREEN])
        for line in lines:
            mutated = list(_center(line, width))
            for _ in range(max(1, width // 20)):
                idx = random.randint(0, len(mutated) - 1)
                mutated[idx] = random.choice(noise)
            print(f"{color}{''.join(mutated)}{ANSI_RESET}")
        print()
        print(_center(f"{ANSI_DIM}signal fracture index: {t:02d}{ANSI_RESET}", width))
        remaining = max(0, height - 9)
        for _ in range(remaining):
            print(_center(random.choice(["", ".", "..", "...", "////", "####"]), width))
        _sleep_or_break(frame_sleep)


def _design_06_circuit(width: int, height: int, frames: int, frame_sleep: float) -> None:
    glyphs = "─│┌┐└┘┼┬┴┤├"
    for _ in range(frames):
        _move_home()
        print(_center(f"{ANSI_BRIGHT_YELLOW}{ANSI_BOLD}CIRCUIT MESH / BUS TOPOLOGY{ANSI_RESET}", width))
        for _ in range(height - 4):
            row = _glyph_line(width, glyphs + "   ")
            print(f"{ANSI_YELLOW}{row}{ANSI_RESET}")
        _sleep_or_break(frame_sleep)


def _design_07_starfield(width: int, height: int, frames: int, frame_sleep: float) -> None:
    stars = []
    count = max(40, (width * height) // 35)
    for _ in range(count):
        stars.append([random.randint(0, width - 1), random.randint(0, height - 6), random.choice([".", "+", "*"])])

    for _ in range(frames):
        _move_home()
        print(_center(f"{ANSI_BRIGHT_WHITE}{ANSI_BOLD}STARFIELD DRIFT / NAV LOCK{ANSI_RESET}", width))
        canvas = [[" " for _ in range(width)] for _ in range(height - 4)]
        for star in stars:
            x, y, ch = star
            if 0 <= x < width and 0 <= y < len(canvas):
                canvas[y][x] = ch
            star[0] -= 1
            if star[0] < 0:
                star[0] = width - 1
                star[1] = random.randint(0, len(canvas) - 1)
                star[2] = random.choice([".", "+", "*"])
        for row in canvas:
            print(f"{ANSI_WHITE}{''.join(row)}{ANSI_RESET}")
        _sleep_or_break(frame_sleep)


def _design_08_lockpick(width: int, height: int, frames: int, frame_sleep: float) -> None:
    bar_width = min(50, max(20, width - 20))
    for t in range(frames):
        _move_home()
        print()
        print(_center(f"{ANSI_BRIGHT_RED}{ANSI_BOLD}LOCK ARRAY / BYPASS SEQUENCE{ANSI_RESET}", width))
        print()
        progress = (t + 1) / frames
        filled = int(bar_width * progress)
        bar = "[" + ("#" * filled) + ("-" * (bar_width - filled)) + "]"
        print(_center(f"{ANSI_RED}{bar}{ANSI_RESET}", width))
        print()
        print(_center(f"{ANSI_BRIGHT_RED}{int(progress * 100):03d}% // tumbler alignment{ANSI_RESET}", width))
        for i in range(max(0, height - 8)):
            label = f"port-{i:02d} " + random.choice(["open", "probe", "sync", "arm", "seed"])
            print(_center(f"{ANSI_DIM}{label}{ANSI_RESET}", width))
        _sleep_or_break(frame_sleep)


def _design_09_dna(width: int, height: int, frames: int, frame_sleep: float) -> None:
    usable_rows = max(10, height - 4)
    for t in range(frames):
        _move_home()
        print(_center(f"{ANSI_BRIGHT_MAGENTA}{ANSI_BOLD}DNA HELIX / CODE THREAD{ANSI_RESET}", width))
        for y in range(usable_rows):
            offset = int((math.sin((y / 2.0) + (t / 2.0)) + 1) * (width / 6))
            left = max(2, offset)
            right = min(width - 3, width - offset - 1)
            row = [" "] * width
            if left < width:
                row[left] = "╲"
            if right < width:
                row[right] = "╱"
            for x in range(left + 1, right):
                if x % 4 == 0:
                    row[x] = random.choice("ATCG")
            print(f"{ANSI_MAGENTA}{''.join(row)}{ANSI_RESET}")
        _sleep_or_break(frame_sleep)


def _design_10_vault(width: int, height: int, frames: int, frame_sleep: float) -> None:
    wheel = ["|", "/", "-", "\\"]
    for t in range(frames):
        _move_home()
        print()
        print(_center(f"{ANSI_BRIGHT_CYAN}{ANSI_BOLD}VAULT CORE / ENCRYPTION CHAMBER{ANSI_RESET}", width))
        print()
        print(_center(f"{ANSI_CYAN}           _________           {ANSI_RESET}", width))
        print(_center(f"{ANSI_CYAN}        .-'         '-.        {ANSI_RESET}", width))
        print(_center(f"{ANSI_CYAN}      .'   {wheel[t % 4]}  LOCKED   '.      {ANSI_RESET}", width))
        print(_center(f"{ANSI_CYAN}     /   SECURE   NODE   \\     {ANSI_RESET}", width))
        print(_center(f"{ANSI_CYAN}     |   HASH: {random.randint(1000, 9999)}    |     {ANSI_RESET}", width))
        print(_center(f"{ANSI_CYAN}     \\   AUTHORIZED?     /     {ANSI_RESET}", width))
        print(_center(f"{ANSI_CYAN}      '.             .'       {ANSI_RESET}", width))
        print(_center(f"{ANSI_CYAN}        '-._______.-'         {ANSI_RESET}", width))
        for _ in range(max(0, height - 12)):
            print()
        _sleep_or_break(frame_sleep)


def _design_11_blueprint(width: int, height: int, frames: int, frame_sleep: float) -> None:
    for t in range(frames):
        _move_home()
        print(_center(f"{ANSI_BRIGHT_BLUE}{ANSI_BOLD}BLUEPRINT GRID / STRUCTURAL MAP{ANSI_RESET}", width))
        for y in range(height - 4):
            row = []
            for x in range(width):
                if y % 4 == 0 and x % 6 == 0:
                    row.append("+")
                elif y % 4 == 0:
                    row.append("-")
                elif x % 6 == 0:
                    row.append("|")
                else:
                    row.append(" ")
            if 4 < y < height - 8:
                text = f" node[{(t + y) % 17:02d}]"
                start = max(1, min(width - len(text) - 1, (y * 3) % max(2, width - len(text) - 1)))
                for i, ch in enumerate(text):
                    row[start + i] = ch
            print(f"{ANSI_BLUE}{''.join(row)}{ANSI_RESET}")
        _sleep_or_break(frame_sleep)


def _design_12_quantum(width: int, height: int, frames: int, frame_sleep: float) -> None:
    glyphs = "·•○◉◌◎"
    for t in range(frames):
        _move_home()
        print(_center(f"{ANSI_BRIGHT_CYAN}{ANSI_BOLD}QUANTUM LATTICE / ENTANGLEMENT MAP{ANSI_RESET}", width))
        for y in range(height - 4):
            row = []
            for x in range(width):
                if (x + y + t) % 7 == 0:
                    row.append(random.choice(glyphs))
                else:
                    row.append(" ")
            print(f"{ANSI_CYAN}{''.join(row)}{ANSI_RESET}")
        _sleep_or_break(frame_sleep)


def _design_13_embers(width: int, height: int, frames: int, frame_sleep: float) -> None:
    for _t in range(frames):
        _move_home()
        print(_center(f"{ANSI_BRIGHT_RED}{ANSI_BOLD}EMBER CORE / THERMAL WAKE{ANSI_RESET}", width))
        canvas = [[" " for _ in range(width)] for _ in range(height - 4)]
        for _ in range(max(80, width)):
            x = random.randint(0, width - 1)
            y = random.randint(0, len(canvas) - 1)
            canvas[y][x] = random.choice([".", "*", "•"])
        for row in canvas:
            print(f"{random.choice([ANSI_RED, ANSI_YELLOW, ANSI_BRIGHT_RED, ANSI_BRIGHT_YELLOW])}{''.join(row)}{ANSI_RESET}")
        _sleep_or_break(frame_sleep)


def _design_14_shield(width: int, height: int, frames: int, frame_sleep: float) -> None:
    statuses = ["SCAN", "LOCK", "VERIFY", "SEAL", "HOLD"]
    for t in range(frames):
        _move_home()
        print()
        print(_center(f"{ANSI_BRIGHT_GREEN}{ANSI_BOLD}DEFENSE SHIELD / HARDENING FIELD{ANSI_RESET}", width))
        print()
        frame = _make_frame(
            title=f"{ANSI_BOLD}SHIELD STATUS: {statuses[t % len(statuses)]}{ANSI_RESET}",
            subtitle=f"{ANSI_GREEN}integrity={97 + (t % 3)}%  entropy={random.randint(70, 99)}{ANSI_RESET}",
            width=min(width, 72),
            color=ANSI_GREEN,
        )
        for line in frame.splitlines():
            print(_center(line, width))
        for _ in range(max(0, height - 10)):
            print(_center(f"{ANSI_DIM}{random.choice(['|', '/', '-', '\\'])} field node active {ANSI_RESET}", width))
        _sleep_or_break(frame_sleep)


def _design_15_glyphforge(width: int, height: int, frames: int, frame_sleep: float) -> None:
    glyphs = "░▒▓█▌▐■◆◼◻"
    for _ in range(frames):
        _move_home()
        print(_center(f"{ANSI_BRIGHT_MAGENTA}{ANSI_BOLD}GLYPH FORGE / SYMBOL FOUNDRY{ANSI_RESET}", width))
        for _ in range(height - 4):
            print(f"{ANSI_MAGENTA}{_glyph_line(width, glyphs + '   ')}{ANSI_RESET}")
        _sleep_or_break(frame_sleep)


def _design_16_oscilloscope(width: int, height: int, frames: int, frame_sleep: float) -> None:
    usable_rows = max(10, height - 4)
    for t in range(frames):
        _move_home()
        print(_center(f"{ANSI_BRIGHT_YELLOW}{ANSI_BOLD}OSCILLOSCOPE / FREQUENCY TRACE{ANSI_RESET}", width))
        canvas = [[" " for _ in range(width)] for _ in range(usable_rows)]
        for x in range(width):
            wave = math.sin((x / 5.0) + (t / 2.0)) + 0.45 * math.sin((x / 11.0) - (t / 3.0))
            y = int((usable_rows / 2) + wave * (usable_rows / 4))
            y = max(0, min(usable_rows - 1, y))
            canvas[y][x] = "█"
        for row in canvas:
            print(f"{ANSI_YELLOW}{''.join(row)}{ANSI_RESET}")
        _sleep_or_break(frame_sleep)


def _design_17_tunnel(width: int, height: int, frames: int, frame_sleep: float) -> None:
    usable_rows = max(10, height - 4)
    cx = width // 2
    cy = usable_rows // 2
    for t in range(frames):
        _move_home()
        print(_center(f"{ANSI_BRIGHT_BLUE}{ANSI_BOLD}DATA TUNNEL / DEPTH VECTOR{ANSI_RESET}", width))
        canvas = [[" " for _ in range(width)] for _ in range(usable_rows)]
        rings = 7
        for r in range(rings, 0, -1):
            half_w = max(2, int((r / rings) * (width // 2 - 2) * (1 + (t % 2) * 0.05)))
            half_h = max(1, int((r / rings) * (usable_rows // 2 - 1)))
            left = max(0, cx - half_w)
            right = min(width - 1, cx + half_w)
            top = max(0, cy - half_h)
            bottom = min(usable_rows - 1, cy + half_h)
            for x in range(left, right + 1):
                canvas[top][x] = "-"
                canvas[bottom][x] = "-"
            for y in range(top, bottom + 1):
                canvas[y][left] = "|"
                canvas[y][right] = "|"
        for row in canvas:
            print(f"{ANSI_BLUE}{''.join(row)}{ANSI_RESET}")
        _sleep_or_break(frame_sleep)


def _design_18_constellation(width: int, height: int, frames: int, frame_sleep: float) -> None:
    points = [(random.randint(2, width - 3), random.randint(1, max(2, height - 6))) for _ in range(max(12, width // 8))]
    for t in range(frames):
        _move_home()
        print(_center(f"{ANSI_BRIGHT_CYAN}{ANSI_BOLD}CONSTELLATION LINK / NODE MAPPER{ANSI_RESET}", width))
        canvas = [[" " for _ in range(width)] for _ in range(height - 4)]
        for i, (x, y) in enumerate(points):
            if 0 <= y < len(canvas) and 0 <= x < width:
                canvas[y][x] = "*"
            if i > 0:
                px, py = points[i - 1]
                steps = max(abs(x - px), abs(y - py), 1)
                for s in range(steps + 1):
                    ix = px + ((x - px) * s // steps)
                    iy = py + ((y - py) * s // steps)
                    if 0 <= iy < len(canvas) and 0 <= ix < width and canvas[iy][ix] == " ":
                        canvas[iy][ix] = "." if (s + t) % 2 == 0 else "·"
        for row in canvas:
            print(f"{ANSI_CYAN}{''.join(row)}{ANSI_RESET}")
        _sleep_or_break(frame_sleep)


def _design_19_cathedral(width: int, height: int, frames: int, frame_sleep: float) -> None:
    art = [
        "                    /\\                    ",
        "                   /  \\                   ",
        "                  / /\\ \\                  ",
        "                 / /  \\ \\                 ",
        "                /_/____\\_\\                ",
        "                |  __  |                  ",
        "                | |  | |                  ",
        "                | |[]| |                  ",
        "                | |  | |                  ",
        "                |_|__|_|                  ",
    ]
    for t in range(frames):
        _move_home()
        color = random.choice([ANSI_BRIGHT_WHITE, ANSI_BRIGHT_BLUE, ANSI_BRIGHT_MAGENTA])
        print()
        print(_center(f"{color}{ANSI_BOLD}DATA CATHEDRAL / ARCHIVE SHRINE{ANSI_RESET}", width))
        print()
        for line in art:
            print(_center(f"{color}{line}{ANSI_RESET}", width))
        for i in range(max(0, height - len(art) - 6)):
            sig = f"archive-channel-{(t + i) % 9}"
            print(_center(f"{ANSI_DIM}{sig}{ANSI_RESET}", width))
        _sleep_or_break(frame_sleep)


def _design_20_operator(width: int, height: int, frames: int, frame_sleep: float) -> None:
    for t in range(frames):
        _move_home()
        print()
        print(_center(f"{ANSI_BRIGHT_GREEN}{ANSI_BOLD}OPERATOR CONSOLE / LIVE READY{ANSI_RESET}", width))
        print()
        left_w = max(24, width // 2 - 2)
        rows = max(8, height - 8)
        for i in range(rows):
            left = f"[{i:02d}] " + random.choice([
                "io sync",
                "entropy align",
                "cache prewarm",
                "key ring",
                "route audit",
                "sig verify",
                "node map",
                "task ready",
            ])
            right = random.choice(["OK", "PASS", "LOCK", "SYNC", "ARM", "LIVE"])
            meter_fill = (i + t) % 10
            meter = "[" + ("#" * meter_fill) + ("-" * (10 - meter_fill)) + "]"
            line = f"{ANSI_GREEN}{left:<{left_w}}{ANSI_RESET}  {ANSI_BRIGHT_GREEN}{meter} {right:<6}{ANSI_RESET}"
            print(_fit_text(line, width))
        _sleep_or_break(frame_sleep)


TOPPER_DESIGNS: dict[str, tuple[str, Callable[[int, int, int, float], None]]] = {
    "matrix": ("Matrix Veil", _design_01_matrix),
    "hexstorm": ("Hex Storm", _design_02_hexstorm),
    "waveform": ("Waveform", _design_03_waveform),
    "radar": ("Radar Sweep", _design_04_radar),
    "glitch": ("Glitch Banner", _design_05_glitch_banner),
    "circuit": ("Circuit Mesh", _design_06_circuit),
    "starfield": ("Starfield Drift", _design_07_starfield),
    "lockpick": ("Lock Array", _design_08_lockpick),
    "dna": ("DNA Helix", _design_09_dna),
    "vault": ("Vault Core", _design_10_vault),
    "blueprint": ("Blueprint Grid", _design_11_blueprint),
    "quantum": ("Quantum Lattice", _design_12_quantum),
    "embers": ("Ember Core", _design_13_embers),
    "shield": ("Defense Shield", _design_14_shield),
    "glyphforge": ("Glyph Forge", _design_15_glyphforge),
    "oscilloscope": ("Oscilloscope", _design_16_oscilloscope),
    "tunnel": ("Data Tunnel", _design_17_tunnel),
    "constellation": ("Constellation Link", _design_18_constellation),
    "cathedral": ("Data Cathedral", _design_19_cathedral),
    "operator": ("Operator Console", _design_20_operator),
}


def run_ghost_topper_safe(
    *,
    enabled: bool = False,
    total_seconds: float = 6.0,
    countdown: int = 2,
    design: str = "random",
    title: str = "ZERO TRUST DESKTOP",
) -> None:
    """
    Optional terminal topper.
    Safe by default:
        - disabled unless explicitly enabled
        - auto-skips in non-interactive/unsafe terminals
        - restores terminal state cleanly
    """
    if not enabled:
        return
    if not _is_safe_interactive_terminal():
        return

    width, height = _term_size()
    countdown = max(1, countdown)
    total_seconds = max(2.0, total_seconds)

    try:
        selected_key = random.choice(list(TOPPER_DESIGNS.keys())) if design == "random" else design.strip().lower()
        if selected_key not in TOPPER_DESIGNS:
            selected_key = "matrix"

        design_name, design_func = TOPPER_DESIGNS[selected_key]

        prelude_sleep = 0.35
        post_countdown_sleep = 0.25
        fixed_time = prelude_sleep + countdown + post_countdown_sleep
        remaining = max(0.8, total_seconds - fixed_time)

        frames = max(8, min(24, int(remaining / 0.09)))
        frame_sleep = remaining / frames if frames > 0 else 0.08

        with _terminal_overlay():
            _move_home()
            _clear()
            print()
            print(_center(f"{ANSI_BRIGHT_GREEN}{ANSI_BOLD}{title}{ANSI_RESET}", width))
            print()
            print(_center(f"{ANSI_GREEN}Design: {design_name}{ANSI_RESET}", width))
            _sleep_or_break(prelude_sleep)

            _render_countdown(width=width, countdown=countdown, color=ANSI_BRIGHT_GREEN, title=title)
            _sleep_or_break(post_countdown_sleep)

            design_func(width, height, frames, frame_sleep)

    except KeyboardInterrupt:
        raise
    except Exception:
        try:
            _topper_write(ANSI_RESET + ANSI_SHOW_CURSOR)
        except Exception:
            pass


# =============================================================================
# FIREWALL ENGINE
# =============================================================================

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

    if settings.topper_seconds < 2:
        error(settings, "Topper seconds must be at least 2", {"topper_seconds": settings.topper_seconds})
        raise SystemExit(2)

    if settings.topper_countdown < 1:
        error(settings, "Topper countdown must be at least 1", {"topper_countdown": settings.topper_countdown})
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
    run_cmd(settings, ["apt-get", "update"], use_sudo=True)


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


# =============================================================================
# ARGPARSE / SETTINGS
# =============================================================================

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="ztd_09_firewall_engine.py")
    parser.add_argument("--yes", action="store_true", help="Use non-interactive apt install mode")
    parser.add_argument("--json", action="store_true", help="Emit JSON events to stdout")
    parser.add_argument("--apply", action="store_true", help="Apply nftables ruleset")
    parser.add_argument("--allow-ssh", action="store_true", help="Allow inbound SSH")
    parser.add_argument("--ssh-port", type=int, default=22, help="SSH port to allow if --allow-ssh is set")
    parser.add_argument("--auto-rollback-sec", type=int, default=90, help="Rollback fuse delay in seconds")
    parser.add_argument("--cancel-rollback", action="store_true", help="Cancel scheduled rollback unit(s)")

    parser.add_argument("--topper", action="store_true", help="Enable optional interactive terminal topper")
    parser.add_argument("--topper-design", default="random", choices=["random", *sorted(TOPPER_DESIGNS.keys())], help="Topper design selection")
    parser.add_argument("--topper-seconds", type=float, default=6.0, help="Topper total runtime target")
    parser.add_argument("--topper-countdown", type=int, default=2, help="Topper countdown seconds")

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
        topper=bool(args.topper),
        topper_design=str(args.topper_design),
        topper_seconds=float(args.topper_seconds),
        topper_countdown=int(args.topper_countdown),
        paths=paths,
    )


# =============================================================================
# MAIN
# =============================================================================

def main() -> int:
    args = build_parser().parse_args()
    settings = build_settings(args)

    run_ghost_topper_safe(
        enabled=settings.topper,
        total_seconds=settings.topper_seconds,
        countdown=settings.topper_countdown,
        design=settings.topper_design,
        title="ZERO TRUST DESKTOP",
    )

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
            "topper_enabled": settings.topper,
            "topper_design": settings.topper_design,
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
# Syntax check:
#   python3 -m py_compile ztd_09_firewall_engine.py
#
# Safe/report mode:
#   ./ztd_09_firewall_engine.py --yes
#
# Safe/report mode with JSON stdout:
#   ./ztd_09_firewall_engine.py --yes --json
#
# Safe/report mode with optional topper:
#   ./ztd_09_firewall_engine.py --yes --topper
#
# Safe/report mode with locked topper design:
#   ./ztd_09_firewall_engine.py --yes --topper --topper-design operator
#
# Faster topper:
#   ./ztd_09_firewall_engine.py --yes --topper --topper-seconds 4 --topper-countdown 1
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
#   ZTD Stage 09 / single-file integration / safe-default / audit-first
# =============================================================================
