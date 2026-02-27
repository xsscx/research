###############################################################
# Dev Container — ICC Security Research (Dockerfile-based)
#
# Pre-builds iccDEV with ASAN+UBSAN instrumentation, fuzzers,
# MCP server venv, and all analysis tools so the container is
# ready to use immediately on launch.
###############################################################

FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

# System packages — compilers, cmake, libraries, Python, git, gh
RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential cmake pkg-config patch ca-certificates \
      clang-18 llvm-18 llvm-18-tools libclang-rt-18-dev \
      libxml2-dev libtiff-dev libjpeg-dev libpng-dev \
      zlib1g-dev liblzma-dev libssl-dev nlohmann-json3-dev \
      ccache git curl sudo \
      python3 python3-pip python3-venv \
    && rm -rf /var/lib/apt/lists/*

# Default compilers
ENV CC=clang-18 CXX=clang++-18

# Non-root user (matches Codespaces convention)
ARG USERNAME=vscode
ARG USER_UID=1000
ARG USER_GID=1000
RUN groupadd --force --gid ${USER_GID} ${USERNAME} \
    && useradd -o --uid ${USER_UID} --gid ${USER_GID} -m ${USERNAME} -s /bin/bash 2>/dev/null; \
    echo "${USERNAME} ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/${USERNAME} \
    && chmod 0440 /etc/sudoers.d/${USERNAME}

# Unified clone + patch via shared script
COPY cfl/patches/ /tmp/cfl-patches/
COPY docker/apply-patches.sh /usr/local/bin/apply-patches.sh
RUN apply-patches.sh /opt/iccdev /tmp/cfl-patches \
    && rm -rf /tmp/cfl-patches

# Build iccDEV — Debug + ASAN + UBSAN + Tools
RUN cd /opt/iccdev && mkdir -p Build/build && cd Build/build \
    && cmake ../Cmake \
       -DCMAKE_BUILD_TYPE=Debug \
       -DCMAKE_C_COMPILER=clang-18 \
       -DCMAKE_CXX_COMPILER=clang++-18 \
       -DENABLE_TOOLS=ON \
       -DENABLE_TESTS=OFF \
       -DENABLE_STATIC_LIBS=ON \
       -DENABLE_SHARED_LIBS=ON \
       -DENABLE_ASAN=ON \
       -DENABLE_UBSAN=ON \
       -Wno-dev \
    && cmake --build . --parallel "$(nproc)" \
    && echo "[OK] iccDEV build complete"

# Generate ICC test profiles
RUN cd /opt/iccdev/Testing \
    && export PATH="/opt/iccdev/Build/build/Tools/IccFromXml:$PATH" \
    && export PATH="/opt/iccdev/Build/build/Tools/IccToXml:$PATH" \
    && export PATH="/opt/iccdev/Build/build/Tools/IccApplyNamedCmm:$PATH" \
    && export PATH="/opt/iccdev/Build/build/Tools/IccApplyProfiles:$PATH" \
    && export PATH="/opt/iccdev/Build/build/Tools/IccRoundTrip:$PATH" \
    && export PATH="/opt/iccdev/Build/build/Tools/IccDumpProfile:$PATH" \
    && export PATH="/opt/iccdev/Build/build/Tools/IccSpecSepToTiff:$PATH" \
    && export PATH="/opt/iccdev/Build/build/Tools/IccTiffDump:$PATH" \
    && export PATH="/opt/iccdev/Build/build/Tools/IccV5DspObsToV4Dsp:$PATH" \
    && export LD_LIBRARY_PATH="/opt/iccdev/Build/build/IccProfLib:/opt/iccdev/Build/build/IccXML:${LD_LIBRARY_PATH:-}" \
    && export ASAN_OPTIONS=detect_leaks=0 \
    && timeout 120 bash CreateAllProfiles.sh || echo "[WARN] Some profiles may not have been created"

# Set ownership for workspace mount point
RUN mkdir -p /workspaces && chown ${USERNAME}:${USERNAME} /workspaces

USER ${USERNAME}
WORKDIR /workspaces
