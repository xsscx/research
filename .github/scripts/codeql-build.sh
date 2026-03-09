#!/bin/bash
# CodeQL build script for iccanalyzer-lite
# This script is used by `gh codeql database create` to compile the analyzer
# for static analysis. It performs per-file compilation with the correct flags.
#
# Usage (database creation):
#   gh codeql database create /tmp/codeql-db-analyzer \
#     --language=cpp --overwrite \
#     --command=".github/scripts/codeql-build.sh" \
#     --source-root="$(pwd)"
#
# Usage (analysis):
#   gh codeql database analyze /tmp/codeql-db-analyzer \
#     --format=sarif-latest --output=/tmp/codeql-results.sarif --threads=0 \
#     codeql/cpp-queries:codeql-suites/cpp-security-and-quality.qls \
#     iccanalyzer-lite/codeql-queries/
#
# Prerequisites (already installed, do NOT re-install):
#   - gh codeql extension (gh extensions install github/gh-codeql)
#   - Query packs (cd iccanalyzer-lite/codeql-queries && gh codeql pack install)
#   - clang++-18, libxml2-dev, libtiff-dev
set -e

cd "$(git rev-parse --show-toplevel)/iccanalyzer-lite"

FLAGS="-std=c++17 -g -O0 -DICCANALYZER_LITE"
INCLUDES="-I ../iccDEV/IccProfLib -I ../iccDEV/IccXML/IccLibXML -I/usr/include/libxml2"

mkdir -p /tmp/codeql-obj

for src in *.cpp; do
  clang++-18 $FLAGS $INCLUDES -c "$src" -o "/tmp/codeql-obj/$(basename "$src" .cpp).o"
done
