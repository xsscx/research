# iccDEV Bisect Reproduction -- Prompt

Verified workflow for reproducing iccDEV bugs across branches.
Derived from 9-turn failure analysis (April 2026) where unverified
reproduction commands wasted 4 hours.

## Mandatory Rules

1. VERIFY then CITE then CLAIM. Never reverse this order.
2. Fresh clone for every reproduction. Never reuse existing checkouts.
3. All commands must be 1-liner copy-paste ready. No backslash continuations.
4. Delete CMakeCache.txt and CMakeFiles/ before every branch switch.
5. Test profiles may be GENERATED (not in git). Check before assuming.
6. Run the EXACT command end-to-end before writing it in any document.

## Fresh Clone Recipe

    mkdir workdir && cd workdir && git clone https://github.com/InternationalColorConsortium/iccDEV.git

## Build (from Build/ directory)

    cd iccDEV/Build && git checkout BRANCH_NAME
    rm -rf CMakeCache.txt CMakeFiles
    CC=clang CXX=clang++ cmake Cmake -DCMAKE_BUILD_TYPE=Debug -DENABLE_SANITIZERS=ON -DENABLE_TOOLS=ON && make -j32

### Sanitizer Coverage Gap

`ENABLE_SANITIZERS=ON` gives `address,undefined,integer` but does NOT include
`float-divide-by-zero` (IEEE 754 defined behavior, not in the `undefined` group).
To catch float div-by-zero (e.g. issue #794), add explicit flags:

    CC=clang CXX=clang++ CXXFLAGS="-fsanitize=address,undefined,integer,float-divide-by-zero,float-cast-overflow -fno-omit-frame-pointer -g" LDFLAGS="-fsanitize=address,undefined,integer,float-divide-by-zero,float-cast-overflow" cmake Cmake -DCMAKE_BUILD_TYPE=Debug -DENABLE_TOOLS=ON && make -j32

## Generate Test Profiles (if needed)

Many .icc files in Testing/ are generated, not committed. Check:

    git ls-files Testing/Encoding/ISO22028-Encoded-bg-sRGB.icc

If empty, generate:

    cd ../Testing
    ASAN_OPTIONS=detect_leaks=0 LLVM_PROFILE_FILE=/dev/null ../Build/Tools/IccFromXml/iccFromXml Encoding/ISO22028-Encoded-bg-sRGB.xml Encoding/ISO22028-Encoded-bg-sRGB.icc

## A/B Comparison Pattern

1. Build and test on the BAD branch (e.g. master)
2. Capture BAD output to file
3. Switch branch: git checkout GOOD_BRANCH
4. Delete cmake cache: rm -rf CMakeCache.txt CMakeFiles
5. Rebuild: cmake Cmake ... && make -j32
6. Regenerate test profiles if needed
7. Capture GOOD output to file
8. diff the two outputs

## Common Failures and Root Causes

| Symptom | Root Cause | Fix |
|---------|-----------|-----|
| IccProfLibVer.h.in not found | Stale CMakeCache.txt | rm -rf CMakeCache.txt CMakeFiles |
| Profile not found | Generated file, not in git | Run iccFromXml first |
| Wrong output | Reusing old build artifacts | Clean rebuild from scratch |
| Command does not paste | Backslash line continuations | Use single-line && chains |
| Tool not found on PATH | PATH not set after build | Use full path: ../Build/Tools/ToolDir/tool |

## Anti-Patterns (from real failures)

- Substituting a different profile without verifying it triggers the same bug
- Reusing an existing checkout from a prior session
- Claiming the unix/ build convention works without testing on the target branch
- Writing reproduction docs before running the commands
- Multi-line commands that break when pasted

## PATH Setup (for Testing/ scripts)

    cd Testing && for d in ../Build/Tools/*; do [ -d "$d" ] && export PATH="$(realpath "$d"):$PATH"; done

## Issue Filing Format

Use the golfed format from `.github/prompts/upstream-issue-filing.prompt.md`.
Title: `Bisect: <sha> <type>`. Sections: Bisect, Build, Bad, Patch, Good, References.
Zero prose. Single code block for Build. Bad = sanitizer output only.

## PoC Requirements for iccRoundTrip

Minimal v2 RGB/XYZ-mntr profile needs 9 tags:
desc, cprt, rTRC, gTRC, bTRC, rXYZ, gXYZ, bXYZ, wtpt.
Without matrix tags (rXYZ/gXYZ/bXYZ), iccRoundTrip rejects with
"Unable to perform round trip". Use profile version 2.0.4. Min 576 bytes.

PoCs go in `xsscx/fuzz/graphics/icc/` with naming convention:
`{type}-{Class}-{Method}-{File}_cpp-Line{N}.icc`

## References

- ~/bisect-details-002.md -- Verified printf format bisect document
- .github/instructions/cfl.instructions.md -- CFL patch workflow
- .github/prompts/upstream-uio-hunting.prompt.md -- UIO bug hunting
- .github/prompts/upstream-issue-filing.prompt.md -- Golfed issue format
- .github/prompts/upstream-code-review-hunting.prompt.md -- Code review hunting
- docs/pocs/iccdev-upstream-bug-hunting.md -- Findings catalog
