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

# Compiler settings
# On CI, CXX=g++ is set by the workflow; locally, Make defaults to g++
# Both work: g++ can link clang-compiled ELF objects (make setup patches out LTO)
CXXFLAGS = -O2 -DNDEBUG -std=gnu++17 -Wall
INCLUDES = -I$(REPO_ROOT)/IccProfLib \
           -I$(REPO_ROOT)/IccXML/IccLibXML \
           $(shell pkg-config --cflags libxml-2.0 2>/dev/null || echo '-I/usr/include/libxml2')

# Static libraries
LIB_PROF = $(BUILD_DIR)/IccProfLib/libIccProfLib2-static.a
LIB_XML  = $(BUILD_DIR)/IccXML/libIccXML2-static.a

# Linker flags — static iccDEV + compression libs, dynamic libxml2/libc
LDFLAGS =
LINK_LIBS = -Wl,-Bstatic -lz -llzma -Wl,-Bdynamic -lxml2 -lm -lpthread

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
	@command -v $(CXX) >/dev/null 2>&1 || { echo "❌ ERROR: $(CXX) not found"; exit 1; }
	@command -v cmake >/dev/null 2>&1 || { echo "❌ ERROR: cmake not found"; exit 1; }
	@test -f "$(LIB_PROF)" || { echo "❌ ERROR: $(LIB_PROF) not found. Run 'make setup' first."; exit 1; }
	@test -f "$(LIB_XML)" || { echo "❌ ERROR: $(LIB_XML) not found. Run 'make setup' first."; exit 1; }

setup:
	@echo ""
	@echo "════════════════════════════════════════"
	@echo "  ColorBleed Setup: iccDEV Libraries"
	@echo "════════════════════════════════════════"
	@command -v $(CXX) >/dev/null 2>&1 || { echo "❌ ERROR: $(CXX) not found"; exit 1; }
	@command -v cmake >/dev/null 2>&1 || { echo "❌ ERROR: cmake not found"; exit 1; }
	@if [ ! -d "$(REPO_ROOT)/.git" ]; then \
		echo "Cloning iccDEV..."; \
		git clone --depth 1 https://github.com/InternationalColorConsortium/iccDEV.git $(REPO_ROOT); \
	else \
		echo "Using existing checkout: $$(cd $(REPO_ROOT) && git rev-parse --short HEAD)"; \
	fi
	@echo "Patching wxWidgets and LTO out..."
	@CMAKELISTS="$(REPO_ROOT)/Build/Cmake/CMakeLists.txt"; \
	if grep -q 'find_package(wxWidgets' "$$CMAKELISTS" 2>/dev/null; then \
		sed -i 's/find_package(wxWidgets/#find_package(wxWidgets/' "$$CMAKELISTS"; \
		sed -i 's/if(wxWidgets_FOUND)/if(FALSE AND wxWidgets_FOUND)/' "$$CMAKELISTS"; \
		sed -i '/wx_/ s/^/#/' "$$CMAKELISTS" 2>/dev/null || true; \
		echo "  Patched wxWidgets"; \
	else \
		echo "  wxWidgets already patched"; \
	fi; \
	if grep -q 'set(CMAKE_INTERPROCEDURAL_OPTIMIZATION ON)' "$$CMAKELISTS" 2>/dev/null; then \
		sed -i 's/set(CMAKE_INTERPROCEDURAL_OPTIMIZATION ON)/#set(CMAKE_INTERPROCEDURAL_OPTIMIZATION ON)/' "$$CMAKELISTS"; \
		echo "  Patched LTO (disabled)"; \
	else \
		echo "  LTO already patched"; \
	fi
	@echo "Building static libraries..."
	@mkdir -p $(BUILD_DIR)
	@echo "  Clearing cmake cache (prevent stale configs)..."
	@rm -rf $(BUILD_DIR)/CMakeCache.txt $(BUILD_DIR)/CMakeFiles
	@cd $(BUILD_DIR) && cmake Cmake/ \
		-DCMAKE_CXX_COMPILER=clang++ \
		-DCMAKE_BUILD_TYPE=Release \
		-DCMAKE_CXX_FLAGS="-O2 -DNDEBUG" \
		-DCMAKE_INTERPROCEDURAL_OPTIMIZATION=OFF \
		-DENABLE_STATIC_LIBS=ON \
		-DENABLE_SHARED_LIBS=ON \
		-DENABLE_TOOLS=OFF \
		-Wno-dev 2>&1 | tail -5
	@cd $(BUILD_DIR) && $(MAKE) -j$(NPROC) IccProfLib2-static IccXML2-static 2>&1 | tail -3
	@echo ""
	@echo "Libraries:"
	@ls -lh $(LIB_PROF) $(LIB_XML)
	@ASAN_COUNT=$$(nm $(LIB_PROF) 2>/dev/null | grep -c '__asan_\|__ubsan_'); \
	if [ "$$ASAN_COUNT" -gt 0 ]; then \
		echo ""; \
		echo "⚠️  WARNING: Libraries contain $$ASAN_COUNT sanitizer symbols."; \
		echo "  This will cause linker errors with g++. Run 'make distclean && make setup' to rebuild clean."; \
	fi
	@echo ""
	@echo "✅ Setup complete — run 'make' to build tools"

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
