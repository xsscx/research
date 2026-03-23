#!/usr/bin/env python3
"""Helpers for constructing runtime environments for parity tooling."""

from __future__ import annotations

import os
from pathlib import Path


def _existing_dirs(paths: list[Path]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for path in paths:
        text = str(path)
        if path.is_dir() and text not in seen:
            seen.add(text)
            out.append(text)
    return out


def v1_runtime_env(binary: Path, *, disable_library_ub_defense: bool = False) -> dict[str, str]:
    """Return an environment that can execute the V1 binary in CI.

    The V1 executable lives next to the project root binary and depends on the
    shared iccDEV libraries under `iccDEV/Build`. GitHub Actions runners do not
    carry those directories in their default linker path, so parity adapters
    must inject them explicitly.
    """

    env = os.environ.copy()
    env.setdefault("ASAN_OPTIONS", "detect_leaks=0")
    env.setdefault("LLVM_PROFILE_FILE", "/dev/null")

    binary_dir = binary.resolve().parent
    candidate_roots = [
        binary_dir,
        binary_dir.parent,
    ]
    candidate_paths: list[Path] = []
    for root in candidate_roots:
        candidate_paths.extend(
            [
                root / "iccDEV" / "Build" / "IccProfLib",
                root / "iccDEV" / "Build" / "IccXML",
            ]
        )

    lib_dirs = _existing_dirs(candidate_paths)
    if lib_dirs:
        existing = env.get("LD_LIBRARY_PATH", "")
        env["LD_LIBRARY_PATH"] = ":".join(lib_dirs + ([existing] if existing else []))

    if disable_library_ub_defense:
        env["ICCANALYZER_ENABLE_LIBRARY_UB_DEFENSE"] = "0"

    return env
