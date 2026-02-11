###############################################################
#
# Copyright (c) 2026 David H Hoyt LLC
#
# Intent: Container image for ICC Profile MCP Server
#         Includes iccanalyzer-lite + colorbleed_tools binaries
#         and Python MCP server with Starlette web UI.
#
###############################################################

FROM ubuntu:24.04 AS builder
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
  build-essential cmake git ca-certificates pkg-config \
  clang llvm libclang-rt-18-dev file \
  libxml2-dev libtiff-dev libjpeg-dev libpng-dev \
  zlib1g-dev liblzma-dev nlohmann-json3-dev libssl-dev \
  python3 python3-venv \
  && rm -rf /var/lib/apt/lists/*

ENV CC=clang CXX=clang++

WORKDIR /build

# Copy source
COPY iccanalyzer-lite/ iccanalyzer-lite/
COPY colorbleed_tools/ colorbleed_tools/
COPY cfl/patches/ cfl/patches/
COPY mcp-server/ mcp-server/
COPY test-profiles/ test-profiles/

# Clone iccDEV for iccanalyzer-lite, apply patches, disable wxWidgets
RUN cd iccanalyzer-lite \
 && git clone --depth 1 https://github.com/InternationalColorConsortium/iccDEV.git \
 && for p in /build/cfl/patches/*.patch; do \
      patch -p1 -d iccDEV --forward -s < "$p" 2>/dev/null || true; \
    done \
 && sed -i '/find_package(wxWidgets/,/endif()/ s/^/# /' iccDEV/Build/Cmake/CMakeLists.txt

# Build iccDEV static libraries with sanitizers
RUN cd iccanalyzer-lite/iccDEV/Build \
 && cmake Cmake \
      -DCMAKE_BUILD_TYPE=Debug \
      -DCMAKE_C_COMPILER=clang \
      -DCMAKE_CXX_COMPILER=clang++ \
      -DCMAKE_CXX_FLAGS="-fsanitize=address,undefined -fno-sanitize-recover=undefined -fno-omit-frame-pointer -O0 -g3 -std=c++17" \
      -DCMAKE_C_FLAGS="-fsanitize=address,undefined -fno-sanitize-recover=undefined -fno-omit-frame-pointer -O0 -g3" \
      -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address,undefined" \
      -DENABLE_TOOLS=OFF \
      -DENABLE_STATIC_LIBS=ON \
      -Wno-dev \
 && make -j$(nproc)

# Build iccanalyzer-lite
RUN cd iccanalyzer-lite && bash build.sh

# Clone iccDEV for colorbleed_tools, apply CFL patches, then setup+build
RUN cd colorbleed_tools \
 && git clone --depth 1 https://github.com/InternationalColorConsortium/iccDEV.git \
 && for p in /build/cfl/patches/*.patch; do \
      patch -p1 -d iccDEV --forward -s < "$p" 2>/dev/null || true; \
    done \
 && make setup && make

# Python venv
RUN python3 -m venv mcp-server/.venv \
 && mcp-server/.venv/bin/pip install --no-cache-dir -r mcp-server/requirements.txt

# --- Runtime stage ---
FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
  libxml2 libtiff6 libjpeg8 libpng16-16t64 \
  zlib1g liblzma5 \
  python3 python3-venv \
  ca-certificates \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy built artifacts
COPY --from=builder /build/iccanalyzer-lite/iccanalyzer-lite iccanalyzer-lite/iccanalyzer-lite
COPY --from=builder /build/colorbleed_tools/iccToXml_unsafe colorbleed_tools/iccToXml_unsafe
COPY --from=builder /build/colorbleed_tools/iccFromXml_unsafe colorbleed_tools/iccFromXml_unsafe
COPY --from=builder /build/mcp-server/ mcp-server/
COPY --from=builder /build/test-profiles/ test-profiles/

EXPOSE 8000

ENTRYPOINT ["mcp-server/.venv/bin/python3", "mcp-server/web_ui.py"]
CMD ["--host", "0.0.0.0", "--port", "8000"]
