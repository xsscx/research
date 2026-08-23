---
name: iccdev-linear-stack
description: >
  Rebase an iccDEV feature branch onto upstream master and stack additional
  squash or feature commits on top without merge commits. Uses clean worktrees,
  range-diff review, local CMake/CTest validation, and exact force-with-lease
  pushes.
allowed-tools:
  - bash
  - read
  - write
  - grep
  - glob
  - shell(git:*)
---

# iccDEV Linear Stack Workflow

## Overview

Use this workflow when an iccDEV feature branch needs to be restacked on current
`master`, then have one or more squash commits or feature commits applied on
top. The output must be a linear branch: no merge commits, no dirty worktree
reuse, and no unreviewed force push.

## Rules

1. Rebase before PR creation whenever possible. This skill does not authorize
   opening, reopening, or force-updating a PR.
2. Use a clean clone or worktree under `~/work/copilot/`, not the local
   research checkout or another user's dirty worktree.
3. Fetch the target branch, source branch, and `master` before rewriting.
4. Rebase the target branch onto `origin/master`.
5. Stack extra commits with `git cherry-pick`, not merge.
6. When the user explicitly says to prefer the stacked commit, use
   `git cherry-pick -X theirs <commit>`. In cherry-pick conflicts, `theirs`
   means the commit being picked.
7. Resolve remaining conflicts manually and preserve upstream `master`
   improvements unless they directly conflict with the requested stacked commit.
8. Review with `git range-diff` before pushing.
9. Build the normal targets and `build-test-binaries`, then run CTest locally.
10. Push only with an exact `--force-with-lease`; never use plain `--force`.

## Workflow

Set variables first:

```bash
repo=/home/h02332/work/copilot/iccdev-linear-stack
remote=git@github.com:InternationalColorConsortium/iccDEV.git
target=pip-install-iccdev
extra_commit=7fb0b2087e66946173cd49ad3289d435ba13a8e1
build_dir=/tmp/iccdev-linear-stack-build
```

### 1. Prepare a clean clone

```bash
mkdir -p "$(dirname "$repo")"
if [ -d "$repo/.git" ]; then
  cd "$repo"
  git remote set-url origin "$remote"
  git fetch --prune origin master "$target"
else
  git clone "$remote" "$repo"
  cd "$repo"
  git fetch --prune origin master "$target"
fi
git checkout -B "$target" "origin/$target"
git status --short --branch
```

If the target worktree is dirty, stop and use a fresh clone. Do not stash or
reset unknown local work.

### 2. Rebase the target onto master

```bash
git rebase origin/master
```

If conflicts appear, resolve them explicitly, then:

```bash
git add <resolved-files>
git -c core.editor=true rebase --continue
```

### 3. Stack the extra commit

Fetch the source branch if the commit is not local:

```bash
git fetch origin add-icc-connect
```

When the user asked to prefer the extra commit over target branch content:

```bash
git cherry-pick -X theirs "$extra_commit"
```

If conflicts remain:

```bash
git status --short --branch
git diff --cc
git add <resolved-files>
git -c core.editor=true cherry-pick --continue
```

### 4. Review the rewritten stack

```bash
git status --short --branch
git log --oneline --decorate --graph --boundary "origin/master..HEAD"
git range-diff origin/master "origin/$target" HEAD
git diff --check origin/master..HEAD
```

The range-diff should show the original target commits replayed, followed by
the extra stacked commit. Intentional conflict-resolution differences should be
small and explainable.

### 5. Build and test locally

```bash
rm -rf "$build_dir"
cmake -S Build/Cmake -B "$build_dir" -DCMAKE_BUILD_TYPE=Debug -DENABLE_TOOLS=ON
cmake --build "$build_dir" -j"$(nproc)"
cmake --build "$build_dir" --target build-test-binaries -j"$(nproc)"
ctest --test-dir "$build_dir" --output-on-failure
```

CTest may regenerate tracked profiles in the worktree. Restore only those
generated artifacts after confirming tests passed:

```bash
git status --short
git restore -- Testing/mcs/Flexo-CMYKOGP/*.icc
git status --short --branch
```

### 6. Push with an exact lease

Fetch immediately before pushing and record the remote SHA used as the lease:

```bash
git fetch --prune origin master "$target"
lease=$(git rev-parse "origin/$target")
git push --force-with-lease="refs/heads/$target:$lease" origin "$target"
git fetch origin "$target"
git log --oneline --decorate --graph --boundary "origin/master..origin/$target"
```

If the lease changes after fetch, stop and re-review. Another maintainer updated
the branch.

## Common Failure Modes

| Symptom | Cause | Fix |
|---------|-------|-----|
| HTTPS asks for username | Remote is not using SSH or gh git auth | Set `origin` to `git@github.com:InternationalColorConsortium/iccDEV.git` |
| Rebase conflict in a one-line guard | Both master and feature fixed the same bug differently | Prefer the clearer current master expression unless the stacked commit requires otherwise |
| CMake finds stale paths | Reused build directory | Delete the build dir and configure from scratch |
| CTest modifies tracked `.icc` files | Profile generation rewrote committed seeds | Restore generated artifacts after tests pass |
| Push rejected by lease | Remote branch moved | Fetch, range-diff again, and restack on the new remote tip |

## References

- `.github/prompts/iccdev-linear-stack-rebase.prompt.md` -- one-shot agent prompt
- `.github/skills/upstream-pr-readiness/SKILL.md` -- authorization and pre-PR gate
- `.github/skills/upstream-sync/SKILL.md` -- CFL patch reconciliation workflow
- `.github/skills/version-bump/SKILL.md` -- upstream version sync workflow
