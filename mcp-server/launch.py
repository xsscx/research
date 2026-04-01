#!/usr/bin/env python3
"""
Cross-platform launcher for the local MCP server workflows.

Prefers the repo-local virtual environment when present so editor integrations
do not depend on the caller already activating the correct interpreter.
"""

from __future__ import annotations

import argparse
import os
import shlex
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


def _quote_wsl_cd(path: str) -> str:
    if path.startswith("~"):
        return path
    return shlex.quote(path)


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


def _build_delegate_env() -> dict[str, str]:
    env = os.environ.copy()
    env.pop("ICC_MCP_ROOT", None)
    return env


def _discover_wsl_root(
    env: dict[str, str] | None = None,
    *,
    platform: str | None = None,
    runner=subprocess.run,
) -> str | None:
    env = env or os.environ
    platform = platform or os.name
    if platform != "nt":
        return None
    if env.get("ICC_MCP_NO_WSL", "").strip().lower() in {"1", "true", "yes", "on"}:
        return None

    candidates: list[str] = []
    explicit = (env.get("ICC_MCP_WSL_ROOT") or "").strip()
    if explicit:
        candidates.append(explicit)
    candidates.extend(
        [
            "~/work/codex/current/research",
            "~/work/codex/research",
            "~/po/research",
        ]
    )

    seen: set[str] = set()
    for candidate in candidates:
        if not candidate or candidate in seen:
            continue
        seen.add(candidate)
        try:
            probe = runner(
                [
                    "wsl.exe",
                    "bash",
                    "-lc",
                    f"cd {_quote_wsl_cd(candidate)} 2>/dev/null && pwd -P",
                ],
                capture_output=True,
                text=True,
                timeout=10,
            )
        except (OSError, subprocess.TimeoutExpired):
            continue
        if probe.returncode == 0:
            resolved = probe.stdout.strip()
            if resolved:
                return resolved
    return None


def _build_wsl_delegate_command(wsl_root: str, mode: str, passthrough: list[str]) -> list[str]:
    argv = ["python3", "mcp-server/launch.py", mode, *passthrough]
    script = "cd {root} && exec {cmd}".format(
        root=shlex.quote(wsl_root),
        cmd=" ".join(shlex.quote(part) for part in argv),
    )
    return ["wsl.exe", "bash", "-lc", script]


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

    wsl_root = _discover_wsl_root()
    backend = "local"
    env = _build_env()
    interpreter = _resolve_python()
    target = SCRIPT_DIR / MODE_TO_SCRIPT[ns.mode]
    cmd = [str(interpreter), str(target), *passthrough]
    if wsl_root:
        backend = "wsl"
        env = _build_delegate_env()
        cmd = _build_wsl_delegate_command(wsl_root, ns.mode, passthrough)

    if ns.dry_run:
        print(f"backend={backend}")
        if backend == "wsl":
            print(f"wsl_root={wsl_root}")
            print("command=" + " ".join(cmd))
        else:
            print(f"interpreter={interpreter}")
            print(f"target={target}")
            if passthrough:
                print("args=" + " ".join(passthrough))
        return 0

    return subprocess.call(cmd, cwd=str(SCRIPT_DIR), env=env)


if __name__ == "__main__":
    raise SystemExit(main())
