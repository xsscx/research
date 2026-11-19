#!/usr/bin/env bash
# Build the instrumented libxml2 required by the CFL MemorySanitizer XML lane.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SOURCE_DIR="$SCRIPT_DIR/sources"
BUILD_DIR="$SCRIPT_DIR/build-msan-libxml2"
PREFIX="$SCRIPT_DIR/install-msan-libxml2"
LIBXML2_VERSION="v2.15.4"
LIBXML2_COMMIT="96498992efa48d52b0e8b83058bd88dbdaf153c1"
CC_BIN="${CC:-clang-22}"
JOBS="${CFL_BUILD_JOBS:-$(nproc 2>/dev/null || echo 4)}"
SOURCE="$SOURCE_DIR/libxml2"
ARCHIVE="$PREFIX/lib/libxml2.a"
VERSION_STAMP="$PREFIX/.libxml2-commit"

for tool in "$CC_BIN" ar cmake git ninja; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "[FAIL] ERROR: $tool is required to build MSan libxml2" >&2
    exit 1
  fi
done

mkdir -p "$SOURCE_DIR"
if [[ ! -d "$SOURCE/.git" ]]; then
  echo "[*] Fetching libxml2 $LIBXML2_VERSION sources"
  git clone --depth 1 --filter=blob:none --branch "$LIBXML2_VERSION" \
    https://gitlab.gnome.org/GNOME/libxml2.git "$SOURCE"
fi

actual_commit="$(git -C "$SOURCE" rev-parse HEAD)"
if [[ "$actual_commit" != "$LIBXML2_COMMIT" ]]; then
  source_status="$(git -C "$SOURCE" status --porcelain)"
  if [[ -n "$source_status" ]]; then
    echo "[FAIL] ERROR: libxml2 source is $actual_commit with local changes; expected $LIBXML2_COMMIT ($LIBXML2_VERSION)" >&2
    echo "       Preserve or remove the local changes before updating the pinned source." >&2
    exit 1
  fi
  echo "[*] Updating libxml2 sources to $LIBXML2_VERSION"
  git -C "$SOURCE" fetch --depth 1 origin "refs/tags/$LIBXML2_VERSION"
  git -C "$SOURCE" checkout --detach "$LIBXML2_COMMIT"
  actual_commit="$(git -C "$SOURCE" rev-parse HEAD)"
  if [[ "$actual_commit" != "$LIBXML2_COMMIT" ]]; then
    echo "[FAIL] ERROR: libxml2 source is $actual_commit; expected $LIBXML2_COMMIT ($LIBXML2_VERSION)" >&2
    exit 1
  fi
fi

installed_commit=""
if [[ -f "$VERSION_STAMP" ]]; then
  IFS= read -r installed_commit < "$VERSION_STAMP" || true
fi
if [[ ! -f "$ARCHIVE" || ! -f "$PREFIX/include/libxml2/libxml/parser.h" ]] ||
   ! grep -a -q '__msan_' "$ARCHIVE" ||
   [[ "$installed_commit" != "$LIBXML2_COMMIT" ]]; then
  echo "[*] Configuring MemorySanitizer-instrumented libxml2"
  cmake -G Ninja -S "$SOURCE" -B "$BUILD_DIR" \
    -DBUILD_SHARED_LIBS=OFF \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX="$PREFIX" \
    -DCMAKE_C_COMPILER="$CC_BIN" \
    -DCMAKE_C_FLAGS="-g -O2 -fno-omit-frame-pointer -fsanitize=memory -fsanitize-memory-track-origins=2 -fPIC" \
    -DLIBXML2_WITH_DOCS=OFF \
    -DLIBXML2_WITH_ICONV=OFF \
    -DLIBXML2_WITH_MODULES=OFF \
    -DLIBXML2_WITH_PROGRAMS=OFF \
    -DLIBXML2_WITH_PYTHON=OFF \
    -DLIBXML2_WITH_TESTS=OFF \
    -DLIBXML2_WITH_ZLIB=OFF
  cmake --build "$BUILD_DIR" --parallel "$JOBS" --target LibXml2
  cmake --install "$BUILD_DIR" --component development
fi

if [[ ! -f "$ARCHIVE" || ! -f "$PREFIX/include/libxml2/libxml/parser.h" ]]; then
  echo "[FAIL] ERROR: instrumented libxml2 installation is incomplete: $PREFIX" >&2
  exit 1
fi
if ! grep -a -q '__msan_' "$ARCHIVE"; then
  echo "[FAIL] ERROR: MemorySanitizer instrumentation is missing from $ARCHIVE" >&2
  exit 1
fi
printf '%s\n' "$LIBXML2_COMMIT" > "$VERSION_STAMP"

echo "[OK] MemorySanitizer-instrumented libxml2: $ARCHIVE"
