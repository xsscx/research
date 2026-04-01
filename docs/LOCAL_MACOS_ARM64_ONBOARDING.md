# Local macOS arm64 Onboarding

Use this path when you are on an Apple Silicon Mac but the repo's native
analysis stack remains Linux-first.

## What This Covers

- Linux devcontainer selection
- Container-first build and test flow
- macOS host prerequisites for Docker or Colima based work
- repo-root and launcher usage without hardcoded local paths

## Prerequisites

Install the host tools once:

```bash
brew install docker colima git python
```

If you prefer Docker Desktop instead of Colima, that works too. The important
part is having a Linux container runtime available on the Mac host.

## Bootstrap Order

Resolve the repo root once:

```bash
REPO_ROOT="$(git rev-parse --show-toplevel)"
```

Start the Linux container runtime if you are using Colima:

```bash
colima start
```

Open the repo with the Linux devcontainer. Prefer one of these:

```bash
${REPO_ROOT}/.devcontainer/devcontainer.json
${REPO_ROOT}/.devcontainer/dockerfile-build/devcontainer.json
```

Inside the Linux container, resolve the repo root again and use the normal repo
entrypoints:

```bash
REPO_ROOT="$(git rev-parse --show-toplevel)"

cd "$REPO_ROOT/iccanalyzer-lite" && ./build.sh
python3 "$REPO_ROOT/iccanalyzer-lite/tests/run_tests.py" -v

cd "$REPO_ROOT/iccanalyzer-lite/icctest" && ./build.sh
ctest --test-dir build --output-on-failure

cd "$REPO_ROOT/colorbleed_tools" && make setup && make test

cd "$REPO_ROOT/cfl" && ./build.sh

cd "$REPO_ROOT/mcp-server" && ./build.sh build && ./build.sh test
```

For editor integration on the host, the launcher remains useful because it does
not hardcode workspace paths:

```bash
cd "$REPO_ROOT/mcp-server"
python launch.py test-mcp
python launch.py test-web
python launch.py web --host 127.0.0.1 --port 8000
```

## Notes

- `iccanalyzer-lite`, `colorbleed_tools`, `cfl`, and related native analysis
  tools should still be treated as Linux-pegged for day-to-day development.
- The repo-root scripts no longer depend on hardcoded workspace paths, so the
  same checkout can move between machines and container mounts more cleanly.
- The repo keeps local Finder metadata out of version control via `.gitignore`,
  but existing untracked `.DS_Store` files still need to be removed once if
  they are already present in your checkout.
- If you eventually experiment with native host builds anyway, treat that path
  as best-effort only rather than the supported source-of-truth workflow.
