## Hoyt's Research Repo

Last Updated: 2026-08-28

This Repo tracks ongoing Public Domain Research with emphasis on Color Profiles, Rendering Images & abusing User Agents.

## Recent Changes
### PAWG assessment and MCP tooling

The retired `iccAnalyzer-lite` and standalone server work is now represented
upstream in `InternationalColorConsortium/iccDEV` by:

- `iccPawgReport`, the PAWG security, conformance, and quality report CLI
- `iccdev-mcp`, the MCP and REST server that exposes the supported iccDEV tools
- `ghcr.io/internationalcolorconsortium/iccdev:latest`, the unified published
  image containing the CLI tools, MCP server, maintainer utilities, and test
  profiles

Use `docs/ICCDEV_UPSTREAM_INTEROP.md` for current source, container, MCP, and
maintainer validation. Dead analyzer commands and release gates have been
removed from active documentation.

### AFL & CFL
- Ongoing Campaigns
- Patches appear on research
  - Patches then Upstreamed

### LUT Dumper
- LUT Dumper code will be Upstreamed

### Color Bleed Tooling
- Available on Releases

### Test Profiles
Test Images & Profiles are made available in this Repo to aid Developers in identifying Bugs.

### Question, Comments or Concerns
- Open an Issue
