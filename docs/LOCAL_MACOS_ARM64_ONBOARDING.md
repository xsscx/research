# Local macOS arm64 Onboarding

Use this path when you are on an Apple Silicon Mac but the repo's native
analysis stack remains Linux-first.

## What This Covers

- macOS host prerequisites for local tooling
- repo-root and launcher usage without hardcoded local paths

## Prerequisites

Install the host tools once:

```bash
brew install git python
```

## Bootstrap Order

Resolve the repo root once:

```bash
REPO_ROOT="$(git rev-parse --show-toplevel)"
```

Use the normal repo entrypoints:

```bash
REPO_ROOT="$(git rev-parse --show-toplevel)"

cd "$REPO_ROOT/colorbleed_tools" && make setup && make test && make qa

cd "$REPO_ROOT/cfl" && ./build.sh
```

## Notes

- `colorbleed_tools`, `cfl`, and related native analysis tools should still be
  treated as Linux-pegged for day-to-day development.
- The repo-root scripts no longer depend on hardcoded workspace paths, so the
  same checkout can move between machines and container mounts more cleanly.
- The repo keeps local Finder metadata out of version control via `.gitignore`,
  but existing untracked `.DS_Store` files still need to be removed once if
  they are already present in your checkout.
- If you eventually experiment with native host builds anyway, treat that path
  as best-effort only rather than the supported source-of-truth workflow.
