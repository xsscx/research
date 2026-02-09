# ICC Profile MCP Server — Docker image
# Builds the C++ analysis tools and packages the Python MCP server.
#
# Build:  docker build -t icc-profile-mcp .
# Run:    docker run --rm -i icc-profile-mcp
# Web UI: docker run --rm -p 8080:8080 icc-profile-mcp icc-profile-web --host 0.0.0.0 --port 8080

FROM ubuntu:24.04 AS builder

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential cmake git clang-18 libclang-rt-18-dev file \
    libxml2-dev libtiff-dev libjpeg-dev libpng-dev \
    zlib1g-dev liblzma-dev nlohmann-json3-dev libssl-dev \
    python3 python3-pip python3-venv \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Build iccDEV libraries + tools
RUN git clone --depth 1 https://github.com/InternationalColorConsortium/DemoIccMAX.git iccDEV
# Patch out wxWidgets (not needed, avoids installing libwxgtk3.2-dev)
RUN sed -i 's/^  find_package(wxWidgets/#  find_package(wxWidgets/' iccDEV/Build/Cmake/CMakeLists.txt \
    && sed -i 's/^      ADD_SUBDIRECTORY(Tools\/wxProfileDump)/#      ADD_SUBDIRECTORY(Tools\/wxProfileDump)/' iccDEV/Build/Cmake/CMakeLists.txt \
    && sed -i 's/^    message(FATAL_ERROR "wxWidgets not found/#    message(FATAL_ERROR "wxWidgets not found/' iccDEV/Build/Cmake/CMakeLists.txt
RUN cd iccDEV/Build && cmake Cmake \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_C_COMPILER=clang-18 \
    -DCMAKE_CXX_COMPILER=clang++-18 \
    -DCMAKE_CXX_FLAGS="-std=c++17" \
    -DENABLE_TOOLS=ON \
    -DENABLE_STATIC_LIBS=ON \
    -DENABLE_SHARED_LIBS=ON \
    -Wno-dev \
    && make -j$(nproc)

# Copy safe iccToXml from iccDEV build
RUN cp iccDEV/Build/Tools/IccToXml/iccToXml /build/iccToXml_safe

# Symlink clang++-18 → clang++ so build scripts find it by default name
RUN ln -sf /usr/bin/clang++-18 /usr/local/bin/clang++ \
    && ln -sf /usr/bin/clang-18 /usr/local/bin/clang

# Build iccanalyzer-lite
COPY iccanalyzer-lite/ /build/iccanalyzer-lite/
RUN ln -sf /build/iccDEV /build/iccanalyzer-lite/iccDEV
RUN cd /build/iccanalyzer-lite && ./build.sh

# Build colorbleed_tools
COPY colorbleed_tools/ /build/colorbleed_tools/
RUN ln -sf /build/iccDEV /build/colorbleed_tools/iccDEV
RUN cd /build/colorbleed_tools && make

# ---- Runtime stage ----
FROM ubuntu:24.04

LABEL org.opencontainers.image.title="iccAnalyzer Web UI & MCP" \
      org.opencontainers.image.description="ICC Color Profile security analysis — MCP server and Web UI with ASAN/UBSAN instrumented tools" \
      org.opencontainers.image.source="https://github.com/xsscx/research" \
      org.opencontainers.image.url="https://github.com/xsscx/research/tree/mcp/mcp-server" \
      org.opencontainers.image.licenses="MIT"

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    libxml2 libtiff6 libssl3 liblzma5 libstdc++6 curl \
    python3 python3-pip python3-venv \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user for runtime
RUN groupadd -r mcp && useradd -r -g mcp -d /app -s /sbin/nologin mcp

WORKDIR /app

# Copy built binaries
COPY --from=builder /build/iccanalyzer-lite/iccanalyzer-lite /app/iccanalyzer-lite/iccanalyzer-lite
COPY --from=builder /build/iccToXml_safe /app/colorbleed_tools/iccToXml
COPY --from=builder /build/colorbleed_tools/iccToXml_unsafe /app/colorbleed_tools/iccToXml_unsafe
# Copy only shared library files from iccDEV build
COPY --from=builder /build/iccDEV/Build/IccProfLib/libIccProfLib2.so* /usr/local/lib/
COPY --from=builder /build/iccDEV/Build/IccXML/libIccXML2.so* /usr/local/lib/
RUN ldconfig

# Copy test profiles
COPY test-profiles/ /app/test-profiles/
COPY extended-test-profiles/ /app/extended-test-profiles/
COPY reference-profiles/ /app/reference-profiles/

# Install Python MCP server
COPY mcp-server/pyproject.toml mcp-server/README.md /app/mcp-server/
COPY mcp-server/icc_profile_mcp.py mcp-server/web_ui.py mcp-server/index.html /app/mcp-server/
RUN cd /app/mcp-server && python3 -m venv .venv \
    && .venv/bin/pip install --no-cache-dir . \
    && .venv/bin/pip install --no-cache-dir starlette uvicorn httpx

# Set ownership and drop privileges
RUN chown -R mcp:mcp /app
USER mcp

ENV PATH="/app/mcp-server/.venv/bin:$PATH"
ENV ASAN_OPTIONS="detect_leaks=0"
ENV ICC_MCP_ROOT="/app"

EXPOSE 8080

# Default: run MCP server over stdio
CMD ["icc-profile-mcp"]
