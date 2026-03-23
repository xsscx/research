#!/usr/bin/env python3
"""Bounded PAWG endpoint smoke for random ICC profiles.

Runs the MCP/Web UI `/api/pawg` endpoint in-process via ASGITransport so the
workflow exercises the endpoint surface without standing up a live server.
Profiles are sampled deterministically from repo fixtures and routine
resource-bomb families are excluded using the shared quarantine file.
"""

from __future__ import annotations

import argparse
import asyncio
import fnmatch
import hashlib
import json
import logging
import os
import random
import re
import sys
from pathlib import Path

import httpx


REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "mcp-server"))

from web_ui import app  # noqa: E402


PROFILE_EXTS = {".icc", ".icm"}
ITEM_RE = re.compile(r"^\s+\[(?:OK|WARN|FAIL|N/A|GAP| -- )\]\s+[SCQ]\d+\s+", re.MULTILINE)
CHECKLIST_URL = "https://www.color.org/profiles/assessment/index.xalter"
REFERENCE_PROFILE_CANDIDATES = (
    "test-profiles/sRGB_D65_MAT.icc",
    "iccanalyzer-lite/tests/corpus/valid_srgb.icc",
)
REQUIRED_SNIPPETS = (
    "Profile Assessment Working Group Checklist Reference",
    "View: PAWG / compact checklist",
    "Date:",
    "File:",
    "SHA-256:",
    "Size:",
    "\nSecurity\n",
    "\nConformance\n",
    "\nQuality\n",
    "Checks evaluated:",
    "Checks mapped:",
    "Registry total:",
    "Spec coverage:",
)
FORBIDDEN_SNIPPETS = (
    "CWE-",
    "docs/iccDEV/specifications/",
    "ICC PROFILE ASSESSMENT REPORT (PAWG)",
    "[ SECURITY ]",
    "[ CONFORMANCE ]",
    "[ QUALITY ]",
    "Goals for profile assessment",
    "Tool:",
    "Build:",
    "\n          CF-",
    "AddressSanitizer",
    "UndefinedBehaviorSanitizer",
    "--- stderr ---",
)


def quiet_logs() -> None:
    for name in (
        "httpx",
        "httpcore",
        "uvicorn",
        "uvicorn.access",
        "uvicorn.error",
    ):
        logging.getLogger(name).setLevel(logging.WARNING)


def load_quarantine_patterns(path: Path) -> list[str]:
    if not path.is_file():
        return []
    patterns: list[str] = []
    for raw_line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        pattern = raw_line.split("#", 1)[0].strip()
        if pattern:
            patterns.append(pattern)
    return patterns


def is_quarantined(relpath: str, patterns: list[str]) -> bool:
    basename = Path(relpath).name
    for pattern in patterns:
        if fnmatch.fnmatch(relpath, pattern) or fnmatch.fnmatch(basename, pattern):
            return True
    return False


def gather_profiles(repo_root: Path, patterns: list[str], include_test_profiles: bool) -> list[str]:
    profiles: list[str] = []
    profile_dirs = ["iccanalyzer-lite/tests/corpus"]
    if include_test_profiles:
        profile_dirs.append("test-profiles")

    for relative_dir in profile_dirs:
        base = repo_root / relative_dir
        if not base.is_dir():
            continue
        for path in base.rglob("*"):
            if not path.is_file():
                continue
            if path.suffix.lower() not in PROFILE_EXTS:
                continue
            relpath = path.relative_to(repo_root).as_posix()
            if is_quarantined(relpath, patterns):
                continue
            profiles.append(relpath)
    return sorted(set(profiles))


def seeded_sample(items: list[str], limit: int, seed_text: str) -> tuple[list[str], int]:
    seed_int = int(hashlib.sha256(seed_text.encode("utf-8")).hexdigest()[:16], 16)
    rng = random.Random(seed_int)
    shuffled = list(items)
    rng.shuffle(shuffled)
    return shuffled[: min(limit, len(shuffled))], seed_int


async def fetch_pawg(path: str, engine: str) -> dict:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        resp = await client.get("/api/pawg", params={"path": path, "engine": engine})

    payload: dict = {
        "path": path,
        "statusCode": resp.status_code,
    }

    try:
        data = resp.json()
    except json.JSONDecodeError as exc:
        payload["ok"] = False
        payload["error"] = f"invalid json: {exc}"
        return payload

    payload["ok"] = bool(data.get("ok"))
    if resp.status_code != 200 or not payload["ok"]:
        payload["error"] = data.get("error", f"http {resp.status_code}")
        return payload

    result = data.get("result", "")
    payload["result"] = result
    payload["resultLength"] = len(result)
    payload["itemCount"] = len(ITEM_RE.findall(result))
    payload["hasChecklistUrl"] = CHECKLIST_URL in result
    payload["missingRequired"] = [snippet for snippet in REQUIRED_SNIPPETS if snippet not in result]
    payload["presentForbidden"] = [snippet for snippet in FORBIDDEN_SNIPPETS if snippet in result]
    payload["valid"] = (
        payload["itemCount"] == 31
        and payload["hasChecklistUrl"]
        and not payload["missingRequired"]
        and not payload["presentForbidden"]
    )
    if not payload["valid"]:
        payload["preview"] = result[:1200]
    return payload


def pick_reference_profile(repo_root: Path, selected: list[str]) -> str | None:
    for relpath in REFERENCE_PROFILE_CANDIDATES:
        if (repo_root / relpath).is_file():
            return relpath
    if selected:
        return selected[0]
    return None


async def main_async(args: argparse.Namespace) -> int:
    quiet_logs()
    quarantine_patterns = load_quarantine_patterns(args.quarantine_file)
    candidates = gather_profiles(args.repo_root, quarantine_patterns, args.include_test_profiles)
    selected, seed_int = seeded_sample(candidates, args.max_profiles, args.seed)

    results = [await fetch_pawg(path, args.engine) for path in selected]
    failures = [entry for entry in results if not entry.get("valid", False)]
    reference_path = pick_reference_profile(args.repo_root, selected)
    reference = await fetch_pawg(reference_path, args.engine) if reference_path else None
    reference_failure = None
    if reference and not reference.get("valid", False):
        reference_failure = reference

    summary = {
        "tool": "pawg-endpoint-sample",
        "repoRoot": str(args.repo_root),
        "engine": args.engine,
        "seedText": args.seed,
        "seedInt": seed_int,
        "candidateCount": len(candidates),
        "profilePools": [
            "iccanalyzer-lite/tests/corpus",
            *([] if not args.include_test_profiles else ["test-profiles"]),
        ],
        "selectedCount": len(selected),
        "selectedProfiles": selected,
        "quarantineFile": str(args.quarantine_file),
        "failureCount": len(failures) + (1 if reference_failure else 0),
        "failures": failures,
        "reference": reference,
        "results": results,
    }

    if args.output:
        args.output.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    else:
        print(json.dumps(summary, indent=2))

    if failures or reference_failure:
        for failure in failures:
            print(
                f"[FAIL] {failure['path']}: status={failure.get('statusCode')} "
                f"error={failure.get('error', '')} "
                f"missing={failure.get('missingRequired', [])} "
                f"forbidden={failure.get('presentForbidden', [])} "
                f"itemCount={failure.get('itemCount')}",
                file=sys.stderr,
            )
        if reference_failure:
            print(
                f"[FAIL] reference {reference_failure['path']}: status={reference_failure.get('statusCode')} "
                f"error={reference_failure.get('error', '')} "
                f"missing={reference_failure.get('missingRequired', [])} "
                f"forbidden={reference_failure.get('presentForbidden', [])} "
                f"itemCount={reference_failure.get('itemCount')}",
                file=sys.stderr,
            )
        return 1

    print(
        f"PAWG endpoint sample passed: {len(selected)}/{len(selected)} profiles "
        f"(seed={seed_int}, engine={args.engine})"
    )
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=REPO_ROOT,
        help="Repository root containing mcp-server/, test-profiles/, etc.",
    )
    parser.add_argument(
        "--quarantine-file",
        type=Path,
        default=REPO_ROOT / "iccanalyzer-lite" / "tests" / "profile-resource-quarantine.txt",
        help="Pattern file for routine resource-bomb exclusions",
    )
    parser.add_argument(
        "--engine",
        choices=("auto", "v1", "v2"),
        default="v2",
        help="Analyzer engine to request through /api/pawg",
    )
    parser.add_argument(
        "--include-test-profiles",
        action="store_true",
        help="Also sample from test-profiles/ in addition to the maintained corpus",
    )
    parser.add_argument(
        "--max-profiles",
        type=int,
        default=25,
        help="Maximum number of sampled profiles to exercise",
    )
    parser.add_argument(
        "--seed",
        default=os.environ.get("GITHUB_SHA", "local-pawg-endpoint"),
        help="Deterministic seed text for profile sampling",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Optional JSON summary output path",
    )
    return parser.parse_args()


def main() -> int:
    return asyncio.run(main_async(parse_args()))


if __name__ == "__main__":
    raise SystemExit(main())
