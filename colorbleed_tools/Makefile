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

TARGETS = iccToXml_unsafe iccFromXml_unsafe

.PHONY: all clean distclean test setup help

# Default target: ensure binaries exist
all: setup

setup:
	@CXX=$(CXX) CC=$(CC) ./build.sh $(CONFIG)

clean:
	@echo "Cleaning test artifacts..."
	rm -f test.xml roundtrip.icc SHA256SUMS *.o *.profraw *.profdata
	@echo "  [OK] Clean complete (binaries preserved in bin/)"

distclean: clean
	@CXX=$(CXX) CC=$(CC) ./build.sh clean

test: all
	@echo ""
	@echo "=== Testing Unsafe Tools ==="
	@echo ""
	@echo "Test 1: iccToXml_unsafe (no args)"
	@./iccToXml_unsafe 2>&1 | head -10 || true
	@echo ""
	@echo "Test 2: iccFromXml_unsafe (no args)"
	@./iccFromXml_unsafe 2>&1 | head -10 || true
	@echo ""
	@if [ -f "$(REPO_ROOT)/Testing/sRGB_v4_ICC_preference.icc" ]; then \
		echo "Test 3: Roundtrip conversion"; \
		./iccToXml_unsafe $(REPO_ROOT)/Testing/sRGB_v4_ICC_preference.icc test.xml; \
		./iccFromXml_unsafe test.xml roundtrip.icc; \
		ls -lh test.xml roundtrip.icc; \
	fi
	@echo ""
	@sha256sum $(TARGETS) 2>/dev/null || shasum -a 256 $(TARGETS) 2>/dev/null
	@echo ""
	@echo "[OK] Basic tests complete"

help:
	@echo "ColorBleed Unsafe XML Tools Makefile"
	@echo ""
	@echo "Targets:"
	@echo "  setup     - Build via build.sh (default config: $(CONFIG))"
	@echo "  all       - Same as setup"
	@echo "  clean     - Remove test artifacts (keeps binaries)"
	@echo "  distclean - Remove everything including iccDEV clone"
	@echo "  test      - Build and run basic tests"
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
