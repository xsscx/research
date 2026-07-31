###############################################################################
# Copyright (c) 2021-2026 David H Hoyt LLC
# ColorBleed Tooling: Unsafe Load & Store Makefile
#
# Last Updated: 28-FEB-2026 by David Hoyt | h02332@gmail.com
# URL https://hoyt.net
#
# Thin delegator to build.sh which handles all compilation.
# Three build configurations: release, debug, sanitizer.
#
# Usage:
#   make setup        # build via build.sh (auto-detects config)
#   make              # same as setup (ensures binaries exist)
#   make test         # run roundtrip tests
#   make clean        # remove test artifacts (keeps binaries)
#   make distclean    # remove everything including iccDEV clone
#
# Config selection (auto-detected from CXX, or override):
#   make CONFIG=sanitizer setup    # ASan+UBSan+coverage (clang only)
#   make CONFIG=release setup      # optimized, no sanitizers
#   make CONFIG=debug setup        # debug symbols, no sanitizers
#
# Requirements (Ubuntu/Debian):
#   sudo apt install -y build-essential cmake clang clang-tools \
#     libxml2-dev libtiff-dev zlib1g-dev liblzma-dev pkg-config git
#
# ColorBleed Warning:
# These Tools will attempt to Load & Store ICC Blobs & XML Representations
# Use with care
#
###############################################################################

REPO_ROOT ?= iccDEV

# Default to clang/clang++ to match build.sh (override via environment: CXX=g++ CC=gcc make setup)
ifeq ($(origin CXX),default)
CXX := clang++
endif
ifeq ($(origin CC),default)
CC := clang
endif

# Auto-detect config: sanitizer for clang (needs llvm runtime), release for gcc
CONFIG ?= $(shell $(CXX) --version 2>&1 | grep -qi clang && echo sanitizer || echo release)

TARGETS = iccToXml_unsafe iccFromXml_unsafe iccToJson_unsafe iccFromJson_unsafe iccDumpAll iccDiagnosticLoad
UBSAN_SUPP = $(CURDIR)/silence.txt
SAN_RUN_ENV = LSAN_OPTIONS=verbosity=0:log_threads=0 ASAN_OPTIONS=detect_leaks=0 UBSAN_OPTIONS=print_stacktrace=1:suppressions=$(UBSAN_SUPP)

.PHONY: all clean distclean test qa setup help

# Default target: ensure binaries exist
all: setup

setup:
	@CXX=$(CXX) CC=$(CC) ./build.sh $(CONFIG)

clean:
	@echo "Cleaning test artifacts..."
	rm -f test.xml test.json roundtrip.icc roundtrip-json.icc SHA256SUMS *.o *.profraw *.profdata
	@echo "  [OK] Clean complete (binaries preserved in bin/)"

distclean: clean
	@CXX=$(CXX) CC=$(CC) ./build.sh clean

test: all colorbleed-test
	@echo ""
	@echo "=== Testing Unsafe Tools ==="
	@echo ""
	@echo "Test 1: iccToXml_unsafe (no args)"
	@$(SAN_RUN_ENV) ./iccToXml_unsafe 2>&1 | head -10 || true
	@echo ""
	@echo "Test 2: iccFromXml_unsafe (no args)"
	@$(SAN_RUN_ENV) ./iccFromXml_unsafe 2>&1 | head -10 || true
	@echo ""
	@echo "Test 3: iccToJson_unsafe (no args)"
	@$(SAN_RUN_ENV) ./iccToJson_unsafe 2>&1 | head -10 || true
	@echo ""
	@echo "Test 4: iccFromJson_unsafe (no args)"
	@$(SAN_RUN_ENV) ./iccFromJson_unsafe 2>&1 | head -10 || true
	@echo ""
	@if [ -f "$(REPO_ROOT)/Testing/sRGB_v4_ICC_preference.icc" ]; then \
		echo "Test 5: XML roundtrip conversion"; \
		$(SAN_RUN_ENV) ./iccToXml_unsafe $(REPO_ROOT)/Testing/sRGB_v4_ICC_preference.icc test.xml; \
		$(SAN_RUN_ENV) ./iccFromXml_unsafe test.xml roundtrip.icc; \
		ls -lh test.xml roundtrip.icc; \
	fi
	@echo ""
	@if [ -f "$(REPO_ROOT)/Testing/sRGB_v4_ICC_preference.icc" ]; then \
		echo "Test 6: JSON roundtrip conversion"; \
		$(SAN_RUN_ENV) ./iccToJson_unsafe $(REPO_ROOT)/Testing/sRGB_v4_ICC_preference.icc test.json; \
		$(SAN_RUN_ENV) ./iccFromJson_unsafe test.json roundtrip-json.icc; \
		ls -lh test.json roundtrip-json.icc; \
	fi
	@echo ""
	@sha256sum $(TARGETS) 2>/dev/null || shasum -a 256 $(TARGETS) 2>/dev/null
	@echo ""
	@echo "[OK] Basic tests complete"

qa: all
	@COLORBLEED_TOOLS_DIR="$(CURDIR)" ./qa-roundtrip-colorbleed.sh

help:
	@echo "ColorBleed Unsafe ICC XML/JSON Tools Makefile"
	@echo ""
	@echo "Targets:"
	@echo "  setup     - Build via build.sh (default config: $(CONFIG))"
	@echo "  all       - Same as setup"
	@echo "  clean     - Remove test artifacts (keeps binaries)"
	@echo "  distclean - Remove everything including iccDEV clone"
	@echo "  test      - Build and run basic tests"
	@echo "  qa        - Build and run XML/JSON/blob converter QA"
	@echo "  help      - Show this help message"
	@echo ""
	@echo "Config override:"
	@echo "  make CONFIG=sanitizer setup   # ASan+UBSan+coverage (clang only)"
	@echo "  make CONFIG=release setup     # optimized, no sanitizers"
	@echo "  make CONFIG=debug setup       # debug symbols, no sanitizers"
	@echo ""
	@echo "Quick start:"
	@echo "  make setup && make test"
	@echo ""
	@echo "Requirements (Ubuntu/Debian):"
	@echo "  sudo apt install -y build-essential cmake clang clang-tools \\"
	@echo "    libxml2-dev libtiff-dev zlib1g-dev liblzma-dev pkg-config git"
	@echo ""
	@echo "ColorBleed Warning:"
	@echo "These tools Load & Store unsafe code for Icc Profiles"

# Extra smoke coverage for iccDumpAll and iccDiagnosticLoad.
include Makefile.colorbleed-extra
