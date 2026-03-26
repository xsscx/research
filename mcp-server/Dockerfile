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
COPY docs/iccDEV/specifications/ docs/iccDEV/specifications/
COPY mcp-server/ mcp-server/
COPY call-graph/knowledge-graph.json call-graph/knowledge-graph.json
COPY test-profiles/ test-profiles/
COPY extended-test-profiles/ extended-test-profiles/

# Clone fresh upstream iccDEV into the analyzer tree. The top-level repo does
# not track that nested checkout, and the MCP image must build against the
# unpatched upstream sources instead of any local working tree residue.
RUN rm -rf /build/iccanalyzer-lite/iccDEV \
 && git clone --depth 1 https://github.com/InternationalColorConsortium/iccDEV.git /build/iccanalyzer-lite/iccDEV \
 && SIGUTILS=/build/iccanalyzer-lite/iccDEV/IccProfLib/IccSignatureUtils.h \
 && if grep -qP '\xef\xb8\x8f' "$SIGUTILS" 2>/dev/null; then \
      sed -i 's/\xef\xb8\x8f//g' "$SIGUTILS"; \
    fi

# Build upstream iccDEV static libraries from a fresh unpatched checkout
RUN find /build/iccanalyzer-lite/iccDEV/Build -mindepth 1 -maxdepth 1 \
        ! -name Cmake ! -name XCode -exec rm -rf {} + \
 && cd /build/iccanalyzer-lite/iccDEV/Build \
 && cmake Cmake \
      -DCMAKE_BUILD_TYPE=Debug \
      -DCMAKE_C_COMPILER=clang \
      -DCMAKE_CXX_COMPILER=clang++ \
      -DCMAKE_CXX_FLAGS="-fno-omit-frame-pointer -O0 -g3 -std=c++17 -fsanitize=address,undefined -fprofile-instr-generate -fcoverage-mapping" \
      -DCMAKE_C_FLAGS="-fno-omit-frame-pointer -O0 -g3 -fsanitize=address,undefined -fprofile-instr-generate -fcoverage-mapping" \
      -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address,undefined -fprofile-instr-generate" \
      -DCMAKE_SHARED_LINKER_FLAGS="-fsanitize=address,undefined -fprofile-instr-generate" \
      -DENABLE_TOOLS=OFF \
      -DENABLE_STATIC_LIBS=ON \
      -DICC_LOG_SAFE=ON \
      -DICC_TRACE_NAN_ENABLED=ON \
      -Wno-dev \
 && make -j$(nproc)

# Build iccanalyzer-lite (ASAN+UBSAN+Coverage — unpatched upstream iccDEV)
RUN cd iccanalyzer-lite && bash build.sh

# Build icctest V2 CLI against the same unpatched iccDEV tree
RUN rm -rf /build/iccanalyzer-lite/icctest/build \
 && cd iccanalyzer-lite/icctest \
 && bash build.sh

# Build the safe non-GUI iccDEV CLI set used by the MCP maintainer endpoints
RUN cd /build/iccanalyzer-lite/iccDEV/Build \
 && cmake Cmake \
      -DCMAKE_BUILD_TYPE=Debug \
      -DCMAKE_C_COMPILER=clang \
      -DCMAKE_CXX_COMPILER=clang++ \
      -DCMAKE_CXX_FLAGS="-fno-omit-frame-pointer -O0 -g3 -std=c++17 -fsanitize=address,undefined -fprofile-instr-generate -fcoverage-mapping" \
      -DCMAKE_C_FLAGS="-fno-omit-frame-pointer -O0 -g3 -fsanitize=address,undefined -fprofile-instr-generate -fcoverage-mapping" \
      -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address,undefined -fprofile-instr-generate" \
      -DCMAKE_SHARED_LINKER_FLAGS="-fsanitize=address,undefined -fprofile-instr-generate" \
      -DENABLE_TOOLS=ON \
      -DENABLE_STATIC_LIBS=ON \
      -DICC_LOG_SAFE=ON \
      -DICC_TRACE_NAN_ENABLED=ON \
      -Wno-dev \
 && make -j$(nproc) \
      iccApplyNamedCmm \
      iccApplyProfiles \
      iccApplySearch \
      iccApplyToLink \
      iccDumpProfile \
      iccFromCube \
      iccFromXml \
      iccPngDump \
      iccRoundTrip \
      iccSpecSepToTiff \
      iccTiffDump \
      iccToXml \
      iccV5DspObsToV4Dsp

# Build colorbleed_tools against the same unpatched iccDEV tree using the
# sanitizer-instrumented configuration. The tools remain intentionally unsafe
# in behavior, but the binaries themselves stay on the Debug+ASAN+UBSAN path.
RUN cd colorbleed_tools \
 && rm -rf iccDEV \
 && ln -s /build/iccanalyzer-lite/iccDEV iccDEV \
 && make CONFIG=sanitizer setup

# Python venv with MCP server
RUN python3 -m venv --clear /build/mcp-venv \
 && /build/mcp-venv/bin/python3 -m ensurepip --upgrade \
 && /build/mcp-venv/bin/pip install --no-cache-dir -e /build/mcp-server

# --- Runtime stage ---
FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
  binutils build-essential cmake curl file git make ninja-build pkg-config \
  clang clang-tools llvm libclang-rt-18-dev \
  libxml2 libxml2-utils libxml2-dev \
  libtiff6 libtiff-dev libjpeg8 libjpeg-dev libpng16-16t64 libpng-dev \
  zlib1g zlib1g-dev liblzma5 liblzma-dev libssl3t64 libssl-dev \
  nlohmann-json3-dev \
  python3 python3-venv \
  ca-certificates \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Run as non-root user
RUN groupadd -r mcp && useradd -r -g mcp -d /app -s /sbin/nologin mcp

# Copy source trees needed by maintainer/operations tools
COPY --chown=mcp:mcp iccanalyzer-lite/ iccanalyzer-lite/
COPY --from=builder --chown=mcp:mcp /build/iccanalyzer-lite/iccDEV/ iccanalyzer-lite/iccDEV/
COPY --chown=mcp:mcp colorbleed_tools/ colorbleed_tools/

# Copy built artifacts used by analysis endpoints
COPY --from=builder --chown=mcp:mcp /build/iccanalyzer-lite/iccanalyzer-lite iccanalyzer-lite/iccanalyzer-lite
COPY --from=builder --chown=mcp:mcp /build/iccanalyzer-lite/icctest/build/cli/icctest iccanalyzer-lite/icctest/build/cli/icctest
COPY --from=builder --chown=mcp:mcp /build/colorbleed_tools/iccToXml_unsafe colorbleed_tools/iccToXml_unsafe
COPY --from=builder --chown=mcp:mcp /build/colorbleed_tools/iccFromXml_unsafe colorbleed_tools/iccFromXml_unsafe
COPY --from=builder --chown=mcp:mcp /build/mcp-venv/ mcp-venv/
COPY --from=builder --chown=mcp:mcp /build/mcp-server/ mcp-server/
COPY --from=builder --chown=mcp:mcp /build/call-graph/knowledge-graph.json call-graph/knowledge-graph.json
COPY --from=builder --chown=mcp:mcp /build/docs/iccDEV/specifications/ docs/iccDEV/specifications/
COPY --from=builder --chown=mcp:mcp /build/test-profiles/ test-profiles/
COPY --from=builder --chown=mcp:mcp /build/extended-test-profiles/ extended-test-profiles/

ENV ASAN_OPTIONS=detect_leaks=0,halt_on_error=0
ENV UBSAN_OPTIONS=halt_on_error=0,print_stacktrace=1
ENV LLVM_PROFILE_FILE=/dev/null
ENV MallocNanoZone=0
ENV ICC_MCP_ROOT=/app
ENV ICC_MCP_ANALYSIS_ENGINE=v2
ENV ICC_MCP_STRUCTURAL_ENGINE=v1
ENV LD_LIBRARY_PATH=/app/iccanalyzer-lite/iccDEV/Build/IccXML:/app/iccanalyzer-lite/iccDEV/Build/IccProfLib

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
