---
mode: agent
description: Compare two ICC profiles for structural and security differences
---

# Compare ICC Profiles

Compare two ICC color profiles side-by-side for structural and security divergences.

## Workflow

1. Run `iccDumpProfile -v` on both paths and compare structural output
2. Run `iccPawgReport --json` on each profile
3. When an MCP runtime is requested, discover its tools and use the supported
   profile inspection and PAWG operations
4. Highlight differences in header fields, tag counts, tag types, colour
   spaces, PAWG states, and round-trip status
5. Flag findings present in only one profile

Present results as a side-by-side comparison table.

## Usage

```
Compare these two ICC profiles:
  Profile A: <path_a>
  Profile B: <path_b>
```
