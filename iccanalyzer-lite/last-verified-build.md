# Last Build Test

Repro: 2026-02-08 03:06:59 UTC by David Hoyt

Built manually on hardware.

## Build

```
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
...
Using iccDEV at: iccDEV
Building iccAnalyzer-lite with ASAN+UBSAN+Coverage using 24 cores...
Linking...

[OK] Build complete
-rwxrwxr-x 1 xss xss 46M Feb  8 03:24 iccanalyzer-lite
iccanalyzer-lite: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=d6c0ca64b9fe9097b5bddc6a6b4c67c175aeb301, for GNU/Linux 3.2.0, with debug_info, not stripped
```
