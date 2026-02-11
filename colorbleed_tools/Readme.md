# Hoyt's ColorBleed Tooling

Last Updated: 2026-02-09 UTC by David Hoyt

ICC Color Profile research tools to load & store unsafe file representations.

## Tools

| Binary | Description |
|--------|-------------|
| `iccToXml_unsafe` | ICC Profile → XML (unsafe load) |
| `iccFromXml_unsafe` | XML → ICC Profile blob (unsafe store) |

## Use Cases
- Fuzzing
- [Latest Binary](https://github.com/xsscx/research/actions/workflows/colorbleed-tools-build.yml)

## Workflow

- Create Images with https://github.com/xsscx/xnuimagetools
- Fuzz Images with https://github.com/xsscx/xnuimagefuzzer
- Create ICC Profiles with these ColorBleed Tools
- Join the ICC Profile & Image
- Interact with:
   - iMessage
   - Outlook
   - Phone
   - Desktops
   - TVs

## Requirements

### Ubuntu/Debian
```
sudo apt install -y build-essential cmake clang clang-tools \
  libxml2-dev libtiff-dev zlib1g-dev liblzma-dev pkg-config git
```

## Build

### Quick Start
```
cd colorbleed_tools
make setup       # clone iccDEV, patch wxWidgets, build static libs
make test        # build tools and run tests
```

### Individual Targets
```
make setup       # clone iccDEV + build libraries (one-time)
make             # build both unsafe tools
make test        # build + run basic tests
make clean       # remove binaries and test files
make distclean   # remove everything including iccDEV clone
make help        # show all targets
```

### Build

```
git clone https://github.com/xsscx/research.git
cd research
cd colorbleed_tools
git clone https://github.com/InternationalColorConsortium/iccDEV.git
cd iccDEV && cd Build && cmake Cmake && make -j32
cd ../../ && make distclean && make setup &&  make -j32 all test
...
[OK] Basic tests complete
```

## CI Workflow

https://github.com/xsscx/research/blob/main/.github/workflows/colorbleed-tools-build.yml

## References
- https://srd.cx/cve-2022-26730/
- https://srd.cx/cve-2023-32443/
- https://srd.cx/cve-2024-38427/
