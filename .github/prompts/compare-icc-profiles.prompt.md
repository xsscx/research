---
mode: agent
description: Compare two ICC profiles for structural and security differences
---

# Compare ICC Profiles

Compare two ICC color profiles side-by-side for structural and security divergences.

## Workflow

1. `compare_profiles` with both paths -- get structural diff
2. `analyze_security` on each profile individually
3. Highlight differences in: header fields, tag counts, tag types, colour spaces,
   security heuristic results, round-trip status
4. Flag any profile that triggers security findings the other does not

Present results as a side-by-side comparison table.

## Usage

```
Compare these two ICC profiles:
  Profile A: <path_a>
  Profile B: <path_b>
```
