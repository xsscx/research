# Hoyt's ColorBleed Tooling

Last Updated: 2026-02-04 15:47:46 UTC by David Hoyt

ICC Color Profile research tools to load & store unsafe file represenations.

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

## Build
### Host
```
Linux repro 6.8.0-90-generic #91-Ubuntu SMP PREEMPT_DYNAMIC Tue Nov 18 14:14:30 UTC 2025 x86_64 x86_64 x86_64 GNU/Linux
```
### Instructions
```
export CXX=g++
git clone https://github.com/xsscx/research.git
cd research
cd colorbleed_tools
git clone https://github.com/InternationalColorConsortium/iccDEV.git
cd iccDEV && cd Build && cmake Cmake && make
cd ../../ && make clean all test
```

## Workflow

https://github.com/xsscx/research/blob/main/.github/workflows/colorbleed-tools-build.yml

## References 
- https://srd.cx/cve-2022-26730/
- https://srd.cx/cve-2023-32443/
- https://srd.cx/cve-2024-38427/
