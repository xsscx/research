## iccAnalyzer-lite

Last Updated: 2026-02-07 16:27:56 UTC

tl;dr ICC Profile Analysis Tool for Security Research
- Developed with AI
- [Latest Binary](https://github.com/xsscx/research/actions/workflows/iccanalyzer-lite-ab-test.yml)
  
## Use

`./bin/iccanalyzer-lite-run -nf examples/sample-display.icc`

## Target Audience
- Security Researcher
- NVD Analyst
- Developer

## Expected Output

Sat Feb  7 04:32:48 PM UTC 2026

```
=========================================================================
|                   *** REDUCED SECURITY MODE ***                       |
|                                                                       |
|             Copyright (c) 2021-2026 David H Hoyt LLC                 |
|                          hoyt.net                                     |
=========================================================================

WARNING: Analyzing malformed/corrupted ICC profile without validation.
         This mode bypasses all safety checks and may expose parser bugs.
         Use only for security research, fuzzing, or forensic analysis.

File: examples/sample-display.icc
Mode: FULL DUMP (entire file will be displayed)

Raw file size: 11236 bytes (0x2BE4)

=== RAW HEADER DUMP (0x0000-0x007F) ===
0x0000: 00 00 2B E4 00 00 00 00  05 00 00 00 73 70 61 63  |..+.........spac|
0x0010: 52 47 42 20 58 59 5A 20  07 EA 00 01 00 1F 00 02  |RGB XYZ ........|
0x0020: 00 0E 00 31 61 63 73 70  00 00 00 00 00 00 00 00  |...1acsp........|
0x0030: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x0040: 00 00 00 01 00 00 F6 D6  00 01 00 00 00 00 D3 2D  |...............-|
0x0050: 49 43 43 20 17 CE 2A 76  B4 B0 BF 15 94 54 F6 D9  |ICC ..*v.....T..|
0x0060: AA C9 FF BC 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x0070: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|

Header Fields (RAW - no validation):
  Profile Size:    0x00002BE4 (11236 bytes) OK
  CMM:             0x00000000  '....'
  Version:         0x05000000
  Device Class:    0x73706163  'spac'
  Color Space:     0x52474220  'RGB '
  PCS:             0x58595A20  'XYZ '
```

## Build

Repro: 2026-02-08 03:18:29 UTC by David Hoyt

### Dependencies

```bash
sudo apt-get install -y build-essential cmake g++ clang \
  libssl-dev libxml2-dev liblzma-dev zlib1g-dev \
  libtiff-dev libpng-dev libjpeg-dev \
  libwxgtk3.2-dev nlohmann-json3-dev
```

### Build

```bash
export CXX=g++
git clone https://github.com/xsscx/research.git
cd research
cd iccanalyzer-lite
git clone https://github.com/InternationalColorConsortium/iccDEV.git
cd iccDEV/Build
cmake Cmake -DENABLE_SANITIZERS=ON -DCMAKE_BUILD_TYPE=Debug
make -j32
cd ..
cd ..
./build.sh
```

## Latest Build
https://github.com/xsscx/research/actions/workflows/iccanalyzer-lite-ab-test.yml
