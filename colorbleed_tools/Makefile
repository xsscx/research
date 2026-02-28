###############################################################################
# Copyright (c) 2021-2026 David H Hoyt LLC
# ColorBleed Tooling: Unsafe Load & Store Makefile
#
# Last Updated: 09-FEB-2026 by David Hoyt | h02332@gmail.com
# URL https://hoyt.net
#
# Makefile for ColorBleed XML Tools
# Research Tooling for Load & Store of ICC Profiles
#
# Usage:
#   make setup        # clone iccDEV, patch wxWidgets, build static libs
#   make              # build both unsafe tools
#   make test         # build and run basic tests
#   make clean        # remove built binaries and test files
#   make distclean    # remove everything including iccDEV clone
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

# Detect build directory
REPO_ROOT ?= iccDEV
BUILD_DIR ?= $(REPO_ROOT)/Build
NPROC := $(shell nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)

# Compiler settings — full instrumentation: ASan + UBSan + coverage
COMMON_CFLAGS = -g -O1 -fno-omit-frame-pointer
SANITIZER_FLAGS = -fsanitize=address,undefined -fsanitize-recover=undefined
COVERAGE_FLAGS = -fprofile-instr-generate -fcoverage-mapping
CXXFLAGS = $(COMMON_CFLAGS) $(SANITIZER_FLAGS) $(COVERAGE_FLAGS) -std=gnu++17 -Wall -frtti
INCLUDES = -I$(REPO_ROOT)/IccProfLib \
           -I$(REPO_ROOT)/IccXML/IccLibXML \
           $(shell pkg-config --cflags libxml-2.0 2>/dev/null || echo '-I/usr/include/libxml2')

# Static libraries
LIB_PROF = $(BUILD_DIR)/IccProfLib/libIccProfLib2-static.a
LIB_XML  = $(BUILD_DIR)/IccXML/libIccXML2-static.a

# Linker flags — static iccDEV + compression libs, dynamic libxml2/libc
LDFLAGS = $(SANITIZER_FLAGS) $(COVERAGE_FLAGS)
LINK_LIBS = -lxml2 -lz -llzma -lm -lpthread

# Targets
TARGETS = iccToXml_unsafe iccFromXml_unsafe

.PHONY: all clean distclean test setup preflight help

all: preflight $(TARGETS)
	@echo ""
	@echo "=== Unsafe XML Tools Built ==="
	@ls -lh $(TARGETS)
	@echo ""
	@echo "ColorBleed Tooling: Unsafe Load & Store for ICC Profiles"
	@echo "Copyright (c) 2021-2026 David H Hoyt LLC"
	@echo ""

preflight:
	@command -v $(CXX) >/dev/null 2>&1 || { echo "[FAIL] ERROR: $(CXX) not found"; exit 1; }
	@command -v cmake >/dev/null 2>&1 || { echo "[FAIL] ERROR: cmake not found"; exit 1; }
	@test -f "$(LIB_PROF)" || { echo "[FAIL] ERROR: $(LIB_PROF) not found. Run 'make setup' first."; exit 1; }
	@test -f "$(LIB_XML)" || { echo "[FAIL] ERROR: $(LIB_XML) not found. Run 'make setup' first."; exit 1; }

setup:
	@echo "Delegating to build.sh (clones iccDEV, applies CFL patches, builds libs + tools)..."
	@./build.sh

iccToXml_unsafe: IccToXml_unsafe.cpp $(LIB_PROF) $(LIB_XML)
	@echo "Building iccToXml_unsafe..."
	$(CXX) $(CXXFLAGS) $(LDFLAGS) $(INCLUDES) $< \
		$(LIB_PROF) $(LIB_XML) \
		$(LINK_LIBS) \
		-o $@
	@chmod +x $@
	@echo "  [OK] iccToXml_unsafe built"

iccFromXml_unsafe: IccFromXml_unsafe.cpp $(LIB_PROF) $(LIB_XML)
	@echo "Building iccFromXml_unsafe..."
	$(CXX) $(CXXFLAGS) $(LDFLAGS) $(INCLUDES) $< \
		$(LIB_PROF) $(LIB_XML) \
		$(LINK_LIBS) \
		-o $@
	@chmod +x $@
	@echo "  [OK] iccFromXml_unsafe built"

clean:
	@echo "Cleaning unsafe tools..."
	rm -f $(TARGETS)
	rm -f *.o
	rm -f test.xml roundtrip.icc SHA256SUMS
	@echo "  [OK] Clean complete"

distclean: clean
	@echo "Removing iccDEV clone..."
	rm -rf $(REPO_ROOT)
	@echo "  [OK] Distclean complete"

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
	@echo "  setup     - Clone iccDEV, patch wxWidgets, build static libraries"
	@echo "  all       - Build both unsafe tools (default)"
	@echo "  clean     - Remove built binaries and test files"
	@echo "  distclean - Remove everything including iccDEV clone"
	@echo "  test      - Build and run basic tests"
	@echo "  help      - Show this help message"
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
