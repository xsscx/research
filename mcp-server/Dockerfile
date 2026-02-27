###############################################################
#
# Copyright (c) 2026 David H Hoyt LLC
#
# Intent: Container image for ICC Profile MCP Server
#         Includes iccanalyzer-lite + colorbleed_tools binaries
#         and Python MCP server with Starlette web UI.
#
#   MCP stdio:  docker run --rm -i ghcr.io/xsscx/icc-profile-mcp:latest
#   Web UI:     docker run --rm -p 8080:8080 ghcr.io/xsscx/icc-profile-mcp:latest web
#               Then open http://127.0.0.1:8080
#
###############################################################

FROM ubuntu:24.04 AS builder
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
  build-essential cmake git ca-certificates pkg-config patch \
  clang llvm libclang-rt-18-dev file \
  libxml2-dev libtiff-dev libjpeg-dev libpng-dev \
  zlib1g-dev liblzma-dev nlohmann-json3-dev libssl-dev \
  python3 python3-venv python3-pip \
  && rm -rf /var/lib/apt/lists/*

ENV CC=clang CXX=clang++

WORKDIR /build

# Copy source
COPY iccanalyzer-lite/ iccanalyzer-lite/
COPY colorbleed_tools/ colorbleed_tools/
COPY cfl/patches/ cfl-patches/
COPY docker/apply-patches.sh /usr/local/bin/apply-patches.sh
COPY mcp-server/ mcp-server/
COPY test-profiles/ test-profiles/
COPY extended-test-profiles/ extended-test-profiles/

# Single iccDEV clone + patch (shared by iccanalyzer-lite and colorbleed_tools)
RUN apply-patches.sh /build/iccdev /build/cfl-patches

# Build iccDEV static libraries (debug, no sanitizers for container)
RUN cd /build/iccdev/Build \
 && cmake Cmake \
      -DCMAKE_BUILD_TYPE=Debug \
      -DCMAKE_C_COMPILER=clang \
      -DCMAKE_CXX_COMPILER=clang++ \
      -DCMAKE_CXX_FLAGS="-fno-omit-frame-pointer -O1 -g -std=c++17" \
      -DCMAKE_C_FLAGS="-fno-omit-frame-pointer -O1 -g" \
      -DENABLE_TOOLS=OFF \
      -DENABLE_STATIC_LIBS=ON \
      -DICC_LOG_SAFE=ON \
      -DICC_TRACE_NAN_ENABLED=ON \
      -Wno-dev \
 && make -j$(nproc)

# Symlink shared iccDEV into iccanalyzer-lite so build.sh finds it
RUN ln -s /build/iccdev /build/iccanalyzer-lite/iccDEV

# Build iccanalyzer-lite (build.sh auto-detects libs)
RUN cd iccanalyzer-lite && bash build.sh

# Build colorbleed_tools against shared iccDEV (no second clone)
RUN cd colorbleed_tools \
 && ln -s /build/iccdev iccDEV \
 && make

# Python venv with MCP server
RUN python3 -m venv --clear /build/mcp-venv \
 && /build/mcp-venv/bin/python3 -m ensurepip --upgrade \
 && /build/mcp-venv/bin/pip install --no-cache-dir -e /build/mcp-server

# --- Runtime stage ---
FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
  libxml2 libtiff6 libjpeg8 libpng16-16t64 \
  zlib1g liblzma5 libssl3t64 \
  python3 python3-venv \
  ca-certificates \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Run as non-root user
RUN groupadd -r mcp && useradd -r -g mcp -d /app -s /sbin/nologin mcp

# Copy built artifacts
COPY --from=builder --chown=mcp:mcp /build/iccanalyzer-lite/iccanalyzer-lite iccanalyzer-lite/iccanalyzer-lite
COPY --from=builder --chown=mcp:mcp /build/colorbleed_tools/iccToXml_unsafe colorbleed_tools/iccToXml_unsafe
COPY --from=builder --chown=mcp:mcp /build/colorbleed_tools/iccFromXml_unsafe colorbleed_tools/iccFromXml_unsafe
COPY --from=builder --chown=mcp:mcp /build/mcp-venv/ mcp-venv/
COPY --from=builder --chown=mcp:mcp /build/mcp-server/ mcp-server/
COPY --from=builder --chown=mcp:mcp /build/test-profiles/ test-profiles/
COPY --from=builder --chown=mcp:mcp /build/extended-test-profiles/ extended-test-profiles/

ENV ASAN_OPTIONS=detect_leaks=0
ENV MallocNanoZone=0
ENV ICC_MCP_ROOT=/app

# Entrypoint script supports: mcp (default), web, or custom command
COPY <<'ENTRYPOINT' /app/entrypoint.sh
#!/bin/sh
set -e
case "${1:-mcp}" in
  mcp)   exec /app/mcp-venv/bin/python3 /app/mcp-server/icc_profile_mcp.py ;;
  web)   shift; exec /app/mcp-venv/bin/python3 /app/mcp-server/web_ui.py \
           --host "${HOST:-0.0.0.0}" --port "${PORT:-8080}" "$@" ;;
  *)     exec "$@" ;;
esac
ENTRYPOINT
RUN chmod +x /app/entrypoint.sh

EXPOSE 8080

USER mcp

ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["mcp"]
