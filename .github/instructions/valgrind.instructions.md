---
applyTo: "valgrind/**"
---

# Valgrind Research Instructions

Keep Valgrind work focused on the registered production tools, target metadata,
build isolation, and evidence collection. Use `valgrind/targets.sh` as the
target registry and the existing `build.sh`, `run.sh`, and `validate.sh`
commands for verification.

Do not add regression source files, CTest targets, synthetic fixtures,
test-only binaries, or a new validation framework for Valgrind research
changes. Fix the actual tool invocation, registry, runner, output verification,
or non-sanitized build configuration and validate it with existing targets and
real inputs. Keep generated logs, profiles, and evidence below ignored output
directories.
