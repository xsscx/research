#!/usr/bin/env python3
"""Helpers for constructing runtime environments for parity tooling."""

from __future__ import annotations

import os
import re
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


def force_sanitizer_env(env: dict[str, str]) -> dict[str, str]:
    """Force leak detection off for harnessed ASan runs.

    Some runners inject ASAN_OPTIONS globally, sometimes as an empty string and
    sometimes with detect_leaks enabled. The parity/verification harnesses need
    a deterministic setting because LeakSanitizer aborts under some harness
    execution environments even when the code under test is otherwise healthy.
    """

    out = env.copy()
    asan = out.get("ASAN_OPTIONS", "").strip()
    if asan:
        asan = re.sub(r"(^|[:,])detect_leaks=[^:,]*", r"\1", asan).strip(":,")
        out["ASAN_OPTIONS"] = f"detect_leaks=0:{asan}" if asan else "detect_leaks=0"
    else:
        out["ASAN_OPTIONS"] = "detect_leaks=0"
    out.setdefault("LLVM_PROFILE_FILE", "/dev/null")
    return out


def v1_runtime_env(binary: Path, *, disable_library_ub_defense: bool = False) -> dict[str, str]:
    """Return an environment that can execute the V1 binary in CI.

    The V1 executable lives next to the project root binary and depends on the
    shared iccDEV libraries under `iccDEV/Build`. GitHub Actions runners do not
    carry those directories in their default linker path, so parity adapters
    must inject them explicitly.
    """

    env = force_sanitizer_env(os.environ.copy())

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
