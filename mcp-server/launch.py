#!/usr/bin/env python3
"""
Cross-platform launcher for the local MCP server workflows.

Prefers the repo-local virtual environment when present so editor integrations
do not depend on the caller already activating the correct interpreter.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
MODE_TO_SCRIPT = {
    "mcp": "icc_profile_mcp.py",
    "web": "web_ui.py",
    "test-mcp": "test_mcp.py",
    "test-web": "test_web_ui.py",
}


def _force_option(existing: str | None, name: str, value: str) -> str:
    parts = []
    for part in (existing or "").split(":"):
        part = part.strip()
        if not part or part.startswith(f"{name}="):
            continue
        parts.append(part)
    return ":".join([f"{name}={value}", *parts])


def _resolve_python() -> Path:
    candidates = []
    if os.name == "nt":
        candidates.append(SCRIPT_DIR / ".venv" / "Scripts" / "python.exe")
    candidates.append(SCRIPT_DIR / ".venv" / "bin" / "python")
    if sys.executable:
        candidates.append(Path(sys.executable))

    for candidate in candidates:
        if candidate.is_file():
            return candidate

    return Path(sys.executable or "python")


def _build_env() -> dict[str, str]:
    env = os.environ.copy()
    env.setdefault("ICC_MCP_ROOT", str(REPO_ROOT))
    env["ASAN_OPTIONS"] = _force_option(
        env.get("ASAN_OPTIONS"),
        "detect_leaks",
        "0",
    )
    return env


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Launch local MCP server workflows with the repo venv when available."
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the resolved interpreter and target script without running it.",
    )
    parser.add_argument(
        "mode",
        nargs="?",
        default="mcp",
        choices=sorted(MODE_TO_SCRIPT),
        help="Workflow to launch.",
    )
    parser.add_argument(
        "args",
        nargs=argparse.REMAINDER,
        help="Arguments passed through to the target script.",
    )
    ns = parser.parse_args()

    passthrough = list(ns.args)
    if passthrough and passthrough[0] == "--":
        passthrough = passthrough[1:]

    interpreter = _resolve_python()
    target = SCRIPT_DIR / MODE_TO_SCRIPT[ns.mode]
    cmd = [str(interpreter), str(target), *passthrough]

    if ns.dry_run:
        print(f"interpreter={interpreter}")
        print(f"target={target}")
        if passthrough:
            print("args=" + " ".join(passthrough))
        return 0

    return subprocess.call(cmd, cwd=str(SCRIPT_DIR), env=_build_env())


if __name__ == "__main__":
    raise SystemExit(main())
